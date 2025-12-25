#include "dtls_decrypt.h"

#include <array>

#include <tls/crypto.h>

namespace dissect {
    namespace {
        constexpr uint16_t kDtls12 = 0xfefd;
        constexpr size_t kExplicitNonce = 8;
        constexpr size_t kSalt = 4;
        constexpr size_t kMaxFragment = 16384 + 2048;   // RFC 6347 section 4.1.2.1 / RFC 5246 section 6.2.3
    } // namespace

    std::optional<TlsRecordState> prepareDtlsKeys(DtlsSession &session, const tls::KeyEntry *keys) {
        if (session.keysReady) return std::nullopt;
        if (!keys || !session.hasClientRandom || keys->get(tls::SecretKind::MasterSecret).length != 48) return TlsRecordState::NoKey;
        if (!session.hasServerRandom || session.version == 0 || session.cipherSuite == 0) return TlsRecordState::NoHandshake;
        if (session.version != kDtls12) return TlsRecordState::UnsupportedSuite;
        // DTLS 1.2 uses the TLS 1.2 suites; only the GCM ones are opened here
        const tls::CipherSuite *suite = tls::findCipherSuite(0x0303, session.cipherSuite);
        if (!suite || suite->aead == tls::crypto::Aead::ChaCha20Poly1305) return TlsRecordState::UnsupportedSuite;
        if (!tls::crypto::available()) return TlsRecordState::NoBackend;
        const auto block = tls::deriveTls12KeyBlock(*suite, keys->get(tls::SecretKind::MasterSecret), session.clientRandom, session.serverRandom);
        if (!block) return TlsRecordState::NoKey;
        session.keys = *block;
        session.keysReady = true;
        return std::nullopt;
    }

    TlsRecordState openDtlsRecord(const DtlsSession &session, bool fromClient, const DtlsRecordInput &in, std::vector<uint8_t> &plaintext) {
        plaintext.clear();
        if (!session.keysReady) return TlsRecordState::NoKey;
        const tls::CipherSuite *suite = tls::findCipherSuite(0x0303, session.cipherSuite);
        if (!suite) return TlsRecordState::UnsupportedSuite;
        const size_t overhead = kExplicitNonce + tls::crypto::kAeadTagLength;
        if (in.fragment.size() < overhead || in.fragment.size() > kMaxFragment) return TlsRecordState::Malformed;

        const tls::Tls12WriteKeys &keys = session.keys[fromClient ? 0 : 1];
        std::array<uint8_t, tls::crypto::kAeadNonceLength> nonce{};
        std::copy_n(keys.iv.begin(), kSalt, nonce.begin());
        std::copy_n(in.fragment.begin(), kExplicitNonce, nonce.begin() + kSalt);
        const size_t plainLength = in.fragment.size() - overhead;
        uint8_t aad[13];
        aad[0] = static_cast<uint8_t>(in.epoch >> 8);
        aad[1] = static_cast<uint8_t>(in.epoch);
        for (size_t i = 0; i < 6; ++i) aad[2 + i] = static_cast<uint8_t>(in.sequence >> (40 - 8 * i));
        aad[8] = in.type;
        aad[9] = static_cast<uint8_t>(in.version >> 8);
        aad[10] = static_cast<uint8_t>(in.version);
        aad[11] = static_cast<uint8_t>(plainLength >> 8);
        aad[12] = static_cast<uint8_t>(plainLength);

        switch (tls::crypto::aeadOpen(suite->aead, keys.key, nonce, aad, in.fragment.subspan(kExplicitNonce), plaintext)) {
            case tls::crypto::AeadStatus::Ok: return TlsRecordState::Decrypted;
            case tls::crypto::AeadStatus::TagFailure: return TlsRecordState::TagFailure;
            case tls::crypto::AeadStatus::Unavailable: return TlsRecordState::NoBackend;
            default: return TlsRecordState::Malformed;
        }
    }
} // namespace dissect
