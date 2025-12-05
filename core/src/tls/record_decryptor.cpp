#include "tls/record_decryptor.h"

#include <algorithm>

namespace tls {
    namespace {
        constexpr uint16_t kTls13 = 0x0304;
        constexpr uint8_t kApplicationData = 23;
        constexpr uint8_t kHandshake = 22;
        constexpr uint8_t kHandshakeFinished = 20;
        constexpr uint8_t kHandshakeKeyUpdate = 24;
        constexpr size_t kMaxTls13Fragment = 16384 + 256;   // RFC 8446 section 5.2: TLSCiphertext.length

        constexpr uint16_t kTls12 = 0x0303;
        constexpr size_t kGcmExplicitNonce = 8;   // RFC 5288 section 3: the nonce_explicit that starts each GCM record
        constexpr size_t kGcmSalt = 4;            // fixed_iv_length of the GCM suites
        constexpr size_t kMaxTls12Fragment = 16384 + 2048;   // RFC 5246 section 6.2.3

        constexpr CipherSuite kSuites[] = {
            // TLS 1.2: AEAD suites of RFC 5288 (GCM) and RFC 7905 (ChaCha20-Poly1305); the hash is the PRF hash
            {0x009C, false, crypto::Aead::Aes128Gcm, crypto::Hash::Sha256, "TLS_RSA_WITH_AES_128_GCM_SHA256"},
            {0x009D, false, crypto::Aead::Aes256Gcm, crypto::Hash::Sha384, "TLS_RSA_WITH_AES_256_GCM_SHA384"},
            {0x009E, false, crypto::Aead::Aes128Gcm, crypto::Hash::Sha256, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256"},
            {0x009F, false, crypto::Aead::Aes256Gcm, crypto::Hash::Sha384, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384"},
            {0xC02B, false, crypto::Aead::Aes128Gcm, crypto::Hash::Sha256, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"},
            {0xC02C, false, crypto::Aead::Aes256Gcm, crypto::Hash::Sha384, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"},
            {0xC02F, false, crypto::Aead::Aes128Gcm, crypto::Hash::Sha256, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"},
            {0xC030, false, crypto::Aead::Aes256Gcm, crypto::Hash::Sha384, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384"},
            {0xCCA8, false, crypto::Aead::ChaCha20Poly1305, crypto::Hash::Sha256, "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
            {0xCCA9, false, crypto::Aead::ChaCha20Poly1305, crypto::Hash::Sha256, "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256"},
            {0xCCAA, false, crypto::Aead::ChaCha20Poly1305, crypto::Hash::Sha256, "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"},
            // TLS 1.3 suites (RFC 8446 appendix B.4)
            {0x1301, true, crypto::Aead::Aes128Gcm, crypto::Hash::Sha256, "TLS_AES_128_GCM_SHA256"},
            {0x1302, true, crypto::Aead::Aes256Gcm, crypto::Hash::Sha384, "TLS_AES_256_GCM_SHA384"},
            {0x1303, true, crypto::Aead::ChaCha20Poly1305, crypto::Hash::Sha256, "TLS_CHACHA20_POLY1305_SHA256"},
        };

        // per-record nonce: the 64-bit sequence number, big endian, left padded to 12 bytes and XORed into the IV
        // (RFC 8446 section 5.3; RFC 7905 uses the same rule for the TLS 1.2 ChaCha suites)
        std::array<uint8_t, 12> xorNonce(const std::array<uint8_t, 12> &iv, uint64_t sequence) {
            std::array<uint8_t, 12> nonce = iv;
            for (size_t i = 0; i < 8; ++i) nonce[4 + i] ^= static_cast<uint8_t>(sequence >> (56 - 8 * i));
            return nonce;
        }
    } // namespace

    const char *decryptStatusText(DecryptStatus status) {
        switch (status) {
            case DecryptStatus::Decrypted: return "decrypted";
            case DecryptStatus::TagFailure: return "tag failure (wrong key?)";
            case DecryptStatus::NoKey: return "no key";
            case DecryptStatus::UnsupportedSuite: return "unsupported cipher suite";
            case DecryptStatus::Malformed: return "malformed record";
            case DecryptStatus::NoBackend: return "decryption not available in this build";
        }
        return "";
    }

    const CipherSuite *findCipherSuite(uint16_t version, uint16_t id) {
        if (version != kTls13 && version != kTls12) return nullptr;
        for (const CipherSuite &s: kSuites) {
            if (s.id == id && s.tls13 == (version == kTls13)) return &s;
        }
        return nullptr;
    }

    // ---- handshake message walker -----------------------------------------------------------------------------

    void RecordDecryptor::HandshakeScanner::feed(std::span<const uint8_t> data) {
        size_t pos = 0;
        while (pos < data.size()) {
            if (remaining > 0) {                                   // inside a message body (possibly begun in an earlier record)
                const size_t skip = std::min<size_t>(remaining, data.size() - pos);
                pos += skip;
                remaining -= static_cast<uint32_t>(skip);
                continue;
            }
            header[have++] = data[pos++];
            if (have < header.size()) continue;
            have = 0;
            remaining = (static_cast<uint32_t>(header[1]) << 16) | (static_cast<uint32_t>(header[2]) << 8) | header[3];
            if (header[0] == kHandshakeFinished) finishedSeen = true;
            if (header[0] == kHandshakeKeyUpdate) keyUpdateSeen = true;
        }
    }

    // ---- setup ------------------------------------------------------------------------------------------------

    RecordDecryptor::RecordDecryptor(uint16_t version, uint16_t cipherSuite, const ClientRandom &clientRandom,
                                     const ClientRandom &serverRandom, const KeyEntry *keys) {
        suite_ = findCipherSuite(version, cipherSuite);
        if (!suite_) {
            availability_ = DecryptStatus::UnsupportedSuite;
            return;
        }
        if (!crypto::available()) {
            availability_ = DecryptStatus::NoBackend;
            return;
        }
        availability_ = DecryptStatus::NoKey;
        tls13_ = suite_->tls13;
        if (!keys) return;
        if (!tls13_) {
            deriveTls12Keys(keys->get(SecretKind::MasterSecret), clientRandom, serverRandom);
            return;
        }

        const size_t hashLen = crypto::hashLength(suite_->hash);
        auto usable = [&](SecretKind kind) {
            const Secret &s = keys->get(kind);
            return s.length == hashLen ? crypto::Bytes(s.bytes.begin(), s.bytes.begin() + s.length) : crypto::Bytes();
        };
        const SecretKind handshake[2] = {SecretKind::ClientHandshakeTraffic, SecretKind::ServerHandshakeTraffic};
        const SecretKind application[2] = {SecretKind::ClientTraffic0, SecretKind::ServerTraffic0};
        for (size_t i = 0; i < 2; ++i) {
            DirectionState &d = dir_[i];
            d.applicationSecret = usable(application[i]);
            const crypto::Bytes hs = usable(handshake[i]);
            d.handshakeSecret = hs;
            if (!hs.empty()) installKeys(d, hs);
            if (d.keys.valid || !d.applicationSecret.empty()) availability_ = DecryptStatus::Decrypted;
        }
    }

    void RecordDecryptor::deriveTls12Keys(const Secret &master, const ClientRandom &clientRandom, const ClientRandom &serverRandom) {
        if (master.length != 48) return;
        const size_t keyLen = crypto::aeadKeyLength(suite_->aead);
        const size_t ivLen = suite_->aead == crypto::Aead::ChaCha20Poly1305 ? crypto::kAeadNonceLength : kGcmSalt;
        // seed = server_random + client_random (the order differs from the master secret derivation)
        crypto::Bytes seed(serverRandom.begin(), serverRandom.end());
        seed.insert(seed.end(), clientRandom.begin(), clientRandom.end());
        const auto block = crypto::prf(suite_->hash, std::span<const uint8_t>(master.bytes.data(), master.length), "key expansion", seed,
                                       2 * keyLen + 2 * ivLen);
        if (!block) return;
        for (size_t i = 0; i < 2; ++i) {   // client_write_key, server_write_key, client_write_IV, server_write_IV
            Keys &k = dir_[i].keys;
            k.key.assign(block->begin() + i * keyLen, block->begin() + (i + 1) * keyLen);
            std::copy_n(block->begin() + 2 * keyLen + i * ivLen, ivLen, k.iv.begin());
            k.valid = true;
            dir_[i].epoch = KeyEpoch::Application;
        }
        availability_ = DecryptStatus::Decrypted;
    }

    bool RecordDecryptor::deriveKeys(const crypto::Bytes &secret, Keys &out) const {
        out = Keys{};
        const auto key = crypto::hkdfExpandLabel(suite_->hash, secret, "key", {}, crypto::aeadKeyLength(suite_->aead));
        const auto iv = crypto::hkdfExpandLabel(suite_->hash, secret, "iv", {}, crypto::kAeadNonceLength);
        if (!key || !iv || iv->size() != out.iv.size()) return false;
        out.key = *key;
        std::copy(iv->begin(), iv->end(), out.iv.begin());
        out.valid = true;
        return true;
    }

    bool RecordDecryptor::installKeys(DirectionState &d, const crypto::Bytes &secret) {
        d.secret = secret;
        d.sequence = 0;
        return deriveKeys(secret, d.keys);
    }

    // ---- decryption -------------------------------------------------------------------------------------------

    DecryptedRecord RecordDecryptor::decrypt(Direction direction, uint8_t type, uint16_t recordVersion, std::span<const uint8_t> fragment) {
        DecryptedRecord r;
        if (availability_ == DecryptStatus::UnsupportedSuite || availability_ == DecryptStatus::NoBackend) {
            r.status = availability_;
            return r;
        }
        DirectionState &d = dir_[static_cast<size_t>(direction)];
        return tls13_ ? decrypt13(d, type, recordVersion, fragment) : decrypt12(d, type, recordVersion, fragment);
    }

    DecryptedRecord RecordDecryptor::open12(const Keys &keys, uint64_t sequence, uint8_t type, uint16_t recordVersion,
                                            std::span<const uint8_t> fragment, bool &sequenceUsed) const {
        DecryptedRecord r;
        r.sequence = sequence;
        r.epoch = KeyEpoch::Application;
        sequenceUsed = false;
        const bool gcm = suite_->aead != crypto::Aead::ChaCha20Poly1305;
        const size_t overhead = (gcm ? kGcmExplicitNonce : 0) + crypto::kAeadTagLength;
        if (fragment.size() < overhead || fragment.size() > kMaxTls12Fragment) {
            r.status = DecryptStatus::Malformed;
            return r;
        }
        if (!keys.valid) {
            r.status = DecryptStatus::NoKey;
            return r;
        }

        std::array<uint8_t, 12> nonce;
        std::span<const uint8_t> sealed = fragment;
        if (gcm) {   // nonce = fixed IV (salt) + the explicit nonce carried in the record
            std::copy_n(keys.iv.begin(), kGcmSalt, nonce.begin());
            std::copy_n(fragment.begin(), kGcmExplicitNonce, nonce.begin() + kGcmSalt);
            sealed = fragment.subspan(kGcmExplicitNonce);
        } else {
            nonce = xorNonce(keys.iv, sequence);
        }
        // additional data = seq_num + type + version + length of the plaintext (RFC 5246 section 6.2.3.3)
        const size_t plainLength = fragment.size() - overhead;
        uint8_t aad[13];
        for (size_t i = 0; i < 8; ++i) aad[i] = static_cast<uint8_t>(sequence >> (56 - 8 * i));
        aad[8] = type;
        aad[9] = static_cast<uint8_t>(recordVersion >> 8);
        aad[10] = static_cast<uint8_t>(recordVersion);
        aad[11] = static_cast<uint8_t>(plainLength >> 8);
        aad[12] = static_cast<uint8_t>(plainLength);

        const crypto::AeadStatus status = crypto::aeadOpen(suite_->aead, keys.key, nonce, aad, sealed, r.plaintext);
        if (status == crypto::AeadStatus::Unavailable) {
            r.status = DecryptStatus::NoBackend;
            return r;
        }
        sequenceUsed = true;
        r.status = status == crypto::AeadStatus::Ok ? DecryptStatus::Decrypted
                   : status == crypto::AeadStatus::TagFailure ? DecryptStatus::TagFailure : DecryptStatus::Malformed;
        if (r.status == DecryptStatus::Decrypted) r.contentType = type;
        return r;
    }

    DecryptedRecord RecordDecryptor::decrypt12(DirectionState &d, uint8_t type, uint16_t recordVersion, std::span<const uint8_t> fragment) {
        bool used = false;
        DecryptedRecord r = open12(d.keys, d.sequence, type, recordVersion, fragment, used);
        if (used) ++d.sequence;
        return r;
    }

    DecryptedRecord RecordDecryptor::decryptAt(Direction direction, KeyEpoch epoch, uint32_t keyUpdates, uint64_t sequence, uint8_t type,
                                               uint16_t recordVersion, std::span<const uint8_t> fragment) const {
        DecryptedRecord r;
        r.sequence = sequence;
        r.epoch = epoch;
        r.keyUpdates = keyUpdates;
        if (availability_ == DecryptStatus::UnsupportedSuite || availability_ == DecryptStatus::NoBackend) {
            r.status = availability_;
            return r;
        }
        const DirectionState &d = dir_[static_cast<size_t>(direction)];
        if (!tls13_) {
            bool used = false;
            return open12(d.keys, sequence, type, recordVersion, fragment, used);
        }
        if (type != kApplicationData || fragment.size() < crypto::kAeadTagLength + 1 || fragment.size() > kMaxTls13Fragment) {
            r.status = DecryptStatus::Malformed;
            return r;
        }
        crypto::Bytes secret = epoch == KeyEpoch::Handshake ? d.handshakeSecret : d.applicationSecret;
        if (secret.empty()) {
            r.status = DecryptStatus::NoKey;
            return r;
        }
        for (uint32_t i = 0; i < keyUpdates; ++i) {   // traffic_secret_N+1 = HKDF-Expand-Label(traffic_secret_N, "traffic upd", "", Hash.length)
            const auto next = crypto::hkdfExpandLabel(suite_->hash, secret, "traffic upd", {}, crypto::hashLength(suite_->hash));
            if (!next) {
                r.status = DecryptStatus::NoKey;
                return r;
            }
            secret = *next;
        }
        Keys keys;
        if (!deriveKeys(secret, keys)) {
            r.status = DecryptStatus::NoKey;
            return r;
        }
        crypto::Bytes inner;
        const crypto::AeadStatus status = open13(keys, sequence, recordVersion, fragment, inner);
        if (status == crypto::AeadStatus::Unavailable) r.status = DecryptStatus::NoBackend;
        else if (status == crypto::AeadStatus::TagFailure) r.status = DecryptStatus::TagFailure;
        else if (status != crypto::AeadStatus::Ok) r.status = DecryptStatus::Malformed;
        else finishInner13(inner, r);
        return r;
    }

    crypto::AeadStatus RecordDecryptor::open13(const Keys &keys, uint64_t sequence, uint16_t recordVersion, std::span<const uint8_t> fragment,
                                               crypto::Bytes &inner) const {
        // additional data = the record header: opaque_type (23), legacy_record_version, length (RFC 8446 section 5.2)
        const uint8_t aad[5] = {kApplicationData, static_cast<uint8_t>(recordVersion >> 8), static_cast<uint8_t>(recordVersion),
                                static_cast<uint8_t>(fragment.size() >> 8), static_cast<uint8_t>(fragment.size())};
        const auto nonce = xorNonce(keys.iv, sequence);
        return crypto::aeadOpen(suite_->aead, keys.key, nonce, aad, fragment, inner);
    }

    void RecordDecryptor::finishInner13(crypto::Bytes &inner, DecryptedRecord &r) {
        // TLSInnerPlaintext = content || content type || zero padding: the type is the last non-zero byte
        size_t end = inner.size();
        while (end > 0 && inner[end - 1] == 0) --end;
        if (end == 0) {
            r.status = DecryptStatus::Malformed;
            return;
        }
        r.contentType = inner[end - 1];
        inner.resize(end - 1);
        r.plaintext = std::move(inner);
        r.status = DecryptStatus::Decrypted;
    }

    DecryptedRecord RecordDecryptor::decrypt13(DirectionState &d, uint8_t type, uint16_t recordVersion, std::span<const uint8_t> fragment) {
        DecryptedRecord r;
        r.sequence = d.sequence;
        r.epoch = d.epoch;
        r.keyUpdates = d.keyUpdates;
        if (type != kApplicationData || fragment.size() < crypto::kAeadTagLength + 1 || fragment.size() > kMaxTls13Fragment) {
            r.status = DecryptStatus::Malformed;
            return r;
        }
        if (!d.keys.valid && (d.epoch != KeyEpoch::Handshake || d.applicationSecret.empty())) {
            r.status = DecryptStatus::NoKey;
            return r;
        }

        crypto::Bytes inner;
        crypto::AeadStatus status = d.keys.valid ? open13(d.keys, d.sequence, recordVersion, fragment, inner) : crypto::AeadStatus::TagFailure;
        if (status != crypto::AeadStatus::Ok && d.epoch == KeyEpoch::Handshake && !d.applicationSecret.empty()) {
            // no handshake secret, or the record of the Finished message was missed: try the first application key once
            DirectionState probe;
            probe.sequence = 0;
            if (installKeys(probe, d.applicationSecret)) {
                crypto::Bytes opened;
                if (open13(probe.keys, 0, recordVersion, fragment, opened) == crypto::AeadStatus::Ok) {
                    d.keys = probe.keys;
                    d.secret = d.applicationSecret;
                    d.sequence = 0;
                    d.epoch = KeyEpoch::Application;
                    d.keyUpdates = 0;
                    d.scanner = HandshakeScanner{};
                    inner = std::move(opened);
                    status = crypto::AeadStatus::Ok;
                    r.sequence = 0;
                    r.epoch = KeyEpoch::Application;
                    r.keyUpdates = 0;
                }
            }
        }
        if (status == crypto::AeadStatus::Unavailable) {
            r.status = DecryptStatus::NoBackend;
            return r;
        }
        if (!d.keys.valid && status != crypto::AeadStatus::Ok) {
            r.status = DecryptStatus::NoKey;
            return r;
        }
        ++d.sequence;
        if (status == crypto::AeadStatus::TagFailure) {
            r.status = DecryptStatus::TagFailure;
            return r;
        }
        if (status != crypto::AeadStatus::Ok) {
            r.status = DecryptStatus::Malformed;
            return r;
        }

        finishInner13(inner, r);
        if (r.status != DecryptStatus::Decrypted) return r;

        if (r.contentType == kHandshake) {
            d.scanner.feed(r.plaintext);
            if (d.epoch == KeyEpoch::Handshake && d.scanner.finishedComplete()) {
                // this direction's Finished is complete: from the next record on the application traffic keys protect it
                d.epoch = KeyEpoch::Application;
                d.keyUpdates = 0;
                d.scanner = HandshakeScanner{};
                if (d.applicationSecret.empty() || !installKeys(d, d.applicationSecret)) d.keys = Keys{};
            } else if (d.epoch == KeyEpoch::Application && d.scanner.keyUpdateComplete()) {
                // traffic_secret_N+1 = HKDF-Expand-Label(traffic_secret_N, "traffic upd", "", Hash.length)
                const auto next = crypto::hkdfExpandLabel(suite_->hash, d.secret, "traffic upd", {}, crypto::hashLength(suite_->hash));
                ++d.keyUpdates;
                d.scanner.keyUpdateSeen = false;
                if (!next || !installKeys(d, *next)) d.keys = Keys{};
            }
        }
        return r;
    }
} // namespace tls
