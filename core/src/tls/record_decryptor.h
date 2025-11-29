#pragma once

// TLS record decryption: given what a connection negotiated (version, cipher suite, the hello randoms) and the secrets
// the key store holds for it, decrypt the records of the two directions one after the other. No dissector, capture or UI
// knowledge: inputs are bytes and numbers, outputs are plaintext or a status that says why there is none.
//
// Typical use (what the load pass does per TLS connection):
//     tls::RecordDecryptor dec(version, cipherSuite, clientRandom, serverRandom, keyStore.find(clientRandom));
//     for each record of a direction, in stream order, that is protected:
//         auto r = dec.decrypt(direction, record.type, record.version, record.fragment);
//         if (r.status == tls::DecryptStatus::Decrypted) use(r.plaintext, r.contentType);
//
// Results (DecryptStatus):
//   Decrypted         plaintext and contentType are valid, the AEAD tag matched
//   TagFailure        keys exist but the tag does not verify: wrong key (a secret of another connection, a stale key log),
//                     a record that is not part of this key epoch, or damaged data. No plaintext is ever returned.
//   NoKey             the key store has no (usable) secret for this direction and epoch
//   UnsupportedSuite  version or cipher suite is outside the supported table (findCipherSuite)
//   Malformed         the record cannot be a protected record (too short, too long, TLS 1.3 record that is not
//                     application_data, no content type in the padding)
//   NoBackend         the build has no OpenSSL (tls::crypto::available() is false)
//
// Supported cipher suites (everything else is UnsupportedSuite: CBC and CCM suites, TLS 1.1 and older, DTLS, QUIC):
//   TLS 1.3 (RFC 8446)  TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256
//   TLS 1.2 (RFC 5246)  AES-128-GCM-SHA256, AES-256-GCM-SHA384 (RFC 5288) and CHACHA20-POLY1305-SHA256 (RFC 7905) with
//                       RSA, DHE_RSA, ECDHE_RSA and ECDHE_ECDSA key exchange: 0x009C 0x009D 0x009E 0x009F 0xC02B 0xC02C
//                       0xC02F 0xC030 0xCCA8 0xCCA9 0xCCAA
//
// TLS 1.2 keys: the CLIENT_RANDOM master secret (48 bytes) is expanded with the PRF of the suite (SHA-256, or SHA-384 for
// the AES-256 suite): key_block = PRF(master_secret, "key expansion", server_random + client_random) split into
// client_write_key, server_write_key, client_write_IV, server_write_IV (AEAD suites have no MAC keys; the GCM IV is the
// 4 byte implicit salt, the ChaCha IV 12 bytes). Per record:
//   GCM       nonce = salt + the 8 byte explicit nonce at the start of the record; record = explicit nonce, ciphertext, tag
//   ChaCha    nonce = IV xor sequence number (as in TLS 1.3); record = ciphertext, tag
//   AAD       sequence number (8) + content type + record version + plaintext length (2)
// Feed the records that follow that direction's ChangeCipherSpec (the encrypted Finished first, sequence number 0); the
// content type of the result is the record's own type. Renegotiation (a second key block) is not followed.
//
// Sequence numbers: every direction has a 64-bit record sequence number that starts at 0 when keys are installed and
// advances with each record that was tried with a key (Decrypted, TagFailure, or Malformed because of the padding;
// NoKey, UnsupportedSuite and Malformed by the size / type checks do not advance it). Feed the records of a direction in the order they were sent and
// without gaps; setSequence() repositions a direction when records are known to be missing.
//
// TLS 1.3 key epochs (RFC 8446 section 7.2 / 4.6.3), tracked per direction from the decrypted plaintext:
//   handshake epoch     keys from CLIENT_/SERVER_HANDSHAKE_TRAFFIC_SECRET
//   application epoch   keys from CLIENT_/SERVER_TRAFFIC_SECRET_0, entered after the record that completes that direction's
//                       Finished message; sequence number restarts at 0
//   KeyUpdate           after the record that completes a KeyUpdate message, that direction's secret becomes
//                       HKDF-Expand-Label(secret, "traffic upd", "", Hash.length) (traffic_secret_N+1), sequence restarts
// A message may span records under the same keys (the switch waits for its last byte); it cannot span a key change.
// The key log carries only the *_0 secrets, later generations are derived here. When a record of the handshake epoch
// cannot be opened (no handshake secret in the log, or the Finished record was missed) but a CLIENT_/SERVER_TRAFFIC_SECRET_0
// exists, the decryptor tries the first application key once; if that opens the record the direction moves to the
// application epoch. 0-RTT (CLIENT_EARLY_TRAFFIC_SECRET) is not decrypted.

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "tls/crypto.h"
#include "tls/keylog.h"

namespace tls {
    enum class Direction : uint8_t { ClientToServer = 0, ServerToClient = 1 };

    enum class DecryptStatus : uint8_t { Decrypted, TagFailure, NoKey, UnsupportedSuite, Malformed, NoBackend };
    /// "decrypted" / "tag failure (wrong key?)" / "no key" / "unsupported cipher suite" / "malformed record" / "decryption not available in this build"
    const char *decryptStatusText(DecryptStatus status);

    /// One supported cipher suite: how its records are protected.
    struct CipherSuite {
        uint16_t id;           // IANA value as sent in the hello
        bool tls13;
        crypto::Aead aead;
        crypto::Hash hash;     // HKDF hash (TLS 1.3); length of the traffic secrets
        const char *name;
    };
    /// The suite `id` as negotiated under `version` (0x0304 = TLS 1.3); nullptr when it is not supported.
    const CipherSuite *findCipherSuite(uint16_t version, uint16_t id);

    enum class KeyEpoch : uint8_t { Handshake, Application };

    struct DecryptedRecord {
        DecryptStatus status = DecryptStatus::NoKey;
        std::vector<uint8_t> plaintext;   // the content without padding / inner content type (empty unless Decrypted)
        uint8_t contentType = 0;          // TLS 1.3: the inner content type (22 handshake, 23 application_data, 21 alert)
        uint64_t sequence = 0;            // the sequence number the record was opened with
        KeyEpoch epoch = KeyEpoch::Handshake;
        uint32_t keyUpdates = 0;          // TLS 1.3: how many KeyUpdates of this direction came before the record
    };

    class RecordDecryptor {
    public:
        /// `keys` may be null (nothing known about the connection); it is copied. The randoms are the 32 bytes of the
        /// ClientHello / ServerHello random.
        RecordDecryptor(uint16_t version, uint16_t cipherSuite, const ClientRandom &clientRandom, const ClientRandom &serverRandom,
                        const KeyEntry *keys);

        /// Decrypted when the suite is supported and the build can decrypt, otherwise UnsupportedSuite / NoBackend; NoKey when
        /// the key store had nothing for either direction. A Decrypted here does not promise that a record opens.
        DecryptStatus availability() const { return availability_; }

        /// Opens one protected record: `type` and `recordVersion` are the record header fields, `fragment` the bytes after
        /// the 5 byte header. TLS 1.3 records must have type 23 (application_data); the real type is returned in
        /// contentType.
        DecryptedRecord decrypt(Direction direction, uint8_t type, uint16_t recordVersion, std::span<const uint8_t> fragment);

        uint64_t sequence(Direction direction) const { return dir_[static_cast<size_t>(direction)].sequence; }
        void setSequence(Direction direction, uint64_t sequence) { dir_[static_cast<size_t>(direction)].sequence = sequence; }
        KeyEpoch epoch(Direction direction) const { return dir_[static_cast<size_t>(direction)].epoch; }

    private:
        // Walks the handshake messages inside the plaintext of handshake records (one message can span records).
        struct HandshakeScanner {
            std::array<uint8_t, 4> header{};
            size_t have = 0;
            uint32_t remaining = 0;
            bool finishedSeen = false;     // the header of a Finished / KeyUpdate message has been read ...
            bool keyUpdateSeen = false;
            void feed(std::span<const uint8_t> data);
            // ... and the message is complete once its body has been read too (it may continue in the next record)
            bool finishedComplete() const { return finishedSeen && remaining == 0; }
            bool keyUpdateComplete() const { return keyUpdateSeen && remaining == 0; }
        };

        struct Keys {
            crypto::Bytes key;
            std::array<uint8_t, 12> iv{};
            bool valid = false;
        };

        struct DirectionState {
            Keys keys;
            crypto::Bytes secret;              // TLS 1.3: the secret the keys came from
            crypto::Bytes applicationSecret;   // TLS 1.3: *_TRAFFIC_SECRET_0 (empty = not known)
            uint64_t sequence = 0;
            KeyEpoch epoch = KeyEpoch::Handshake;
            uint32_t keyUpdates = 0;
            HandshakeScanner scanner;
        };

        bool installKeys(DirectionState &d, const crypto::Bytes &secret);   // TLS 1.3: key / iv from a traffic secret
        DecryptedRecord decrypt13(DirectionState &d, uint8_t type, uint16_t recordVersion, std::span<const uint8_t> fragment);
        crypto::AeadStatus open13(const Keys &keys, uint64_t sequence, uint16_t recordVersion, std::span<const uint8_t> fragment,
                                  crypto::Bytes &inner) const;
        DecryptedRecord decrypt12(DirectionState &d, uint8_t type, uint16_t recordVersion, std::span<const uint8_t> fragment);
        void deriveTls12Keys(const Secret &master, const ClientRandom &clientRandom, const ClientRandom &serverRandom);

        const CipherSuite *suite_ = nullptr;
        bool tls13_ = false;
        DecryptStatus availability_ = DecryptStatus::UnsupportedSuite;
        std::array<DirectionState, 2> dir_;
    };
} // namespace tls
