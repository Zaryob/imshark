#pragma once

// DTLS 1.2 record decryption (RFC 6347 + RFC 5288): AES-128-GCM and AES-256-GCM with the key block derived from the
// CLIENT_RANDOM master secret of the key log. TLS 1.2 and DTLS 1.2 expand the master secret the same way, so the keys come from
// tls::deriveTls12KeyBlock(); what differs is the record: DTLS has no implicit sequence number, the epoch and the 48 bit
// sequence number are in the record header, so every record opens on its own:
//
//     nonce = client/server_write_IV (4 byte salt) || the 8 byte explicit nonce at the start of the record fragment
//     AAD   = epoch (2) || sequence number (6) || content type || version (2) || length of the plaintext (2)
//     fragment = explicit nonce (8) || ciphertext || tag (16)
//
// Not supported (UnsupportedSuite): ChaCha20-Poly1305, CBC and CCM suites, DTLS 1.0, DTLS 1.3. Renegotiation is not followed
// (the key block of the first handshake is used for every record of epoch >= 1).

#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include <tls/keylog.h>

#include "dtls_session.h"

namespace dissect {
    /// One record as it sits in the datagram: header fields and the bytes after the 13 byte header.
    struct DtlsRecordInput {
        uint8_t type = 0;
        uint16_t version = 0;
        uint16_t epoch = 0;
        uint64_t sequence = 0;                  // the 48 bit sequence number
        std::span<const uint8_t> fragment;
    };

    /// Makes `session` ready to open records: derives the write keys from `keys` (the key log entry of its client random;
    /// null: none known). Returns std::nullopt when the keys are ready, otherwise the reason (NoKey, NoHandshake,
    /// UnsupportedSuite or NoBackend). Does nothing when the keys are ready already.
    std::optional<TlsRecordState> prepareDtlsKeys(DtlsSession &session, const tls::KeyEntry *keys);

    /// Opens `in` with the keys of a session whose keys are ready. `fromClient` selects client_write or server_write.
    /// Decrypted (plaintext filled), TagFailure or Malformed; the plaintext is only filled when the tag matched.
    TlsRecordState openDtlsRecord(const DtlsSession &session, bool fromClient, const DtlsRecordInput &in, std::vector<uint8_t> &plaintext);
} // namespace dissect
