#pragma once

// Decryption of the TLS records of a loaded capture: the glue between the TLS session mapping (tls_session.h), the key
// material (tls/keylog.h) and the record decryptor (tls/record_decryptor.h).
//
// Load pass (rule 4: decisions are made here, detail building only reads): the TLS dissector registers every complete TCP
// message of a connection in the session tables and then hands its records to TlsDecryptTable::process(). The records of a
// direction are opened strictly in stream order with one tls::RecordDecryptor per connection, so the sequence numbers, the
// TLS 1.3 key epochs and the KeyUpdate generations follow from the records themselves. What is kept per record is small:
//
//     TlsRecordOutcome   state (TlsRecordState), the (sequence number, epoch, KeyUpdate generation) the record was opened
//                        with, the inner content type, the plaintext length and the protocol the application data was
//                        dissected as. 24 bytes; no plaintext is kept.
//
// Detail building (Replay) re-opens only the records of the packet it is asked about: tls::RecordDecryptor::decryptAt()
// takes the stored (epoch, generation, sequence), so nothing depends on any other record and the plaintext equals what the
// load pass dissected. The bytes of a record that is not Decrypted never leave the decryptor.
//
// Records that are not decrypted get the state that says why (TlsRecordState): wrong key, no key, unsupported suite, data
// missing from the capture before the record (TLS record numbers are the nonce, so everything after a TCP gap in that
// direction is CaptureGap rather than "wrong key"), ServerHello not captured. A connection without any key material keeps
// no outcomes at all: the same states are derived from the session tables when they are read (readMessage()).
//
// Limits (documented in docs/KNOWN_ISSUES.md): TLS 1.2 renegotiation is not followed (the key block of the first
// handshake is used for the whole connection); TLS 1.3 early data is not decrypted; a TLS 1.3 record that fails its tag
// in the handshake epoch does not advance the direction's sequence number (so one undecryptable record, e.g. 0-RTT data,
// does not spoil the Finished that follows it).

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include <tls/keylog.h>
#include <tls/record_decryptor.h>

#include "tls_session.h"
#include "tls_summary.h"

namespace dissect {
    /// One record as it was cut out of the TCP stream: header fields and the bytes after the 5 byte header.
    struct TlsRecordInput {
        uint8_t type = 0;
        uint16_t version = 0;
        std::span<const uint8_t> fragment;
    };

    struct TlsRecordOutcome {
        uint64_t sequence = 0;       // the sequence number the record was opened with
        uint32_t keyUpdates = 0;     // TLS 1.3: how many KeyUpdates of the direction came before it
        uint32_t plainLength = 0;    // length of the decrypted content
        uint8_t state = 0;           // TlsRecordState
        uint8_t contentType = 0;     // inner content type (TLS 1.3) or the record type (TLS 1.2 and clear records)
        uint8_t epoch = 0;           // tls::KeyEpoch
        uint8_t inner = 0;           // TlsInner the application data was dissected as
        TlsRecordState recordState() const { return static_cast<TlsRecordState>(state); }
        TlsInner innerProtocol() const { return static_cast<TlsInner>(inner); }
    };

    /// The outcomes of the records of one message (and the plaintext of the Decrypted ones, same index).
    struct TlsMessageDecryption {
        std::vector<TlsRecordOutcome> outcomes;
        std::vector<std::vector<uint8_t>> plaintext;
    };

    class TlsDecryptTable {
    public:
        /// Load pass: opens the `records` of one registered message (direction `direction` of `session`, records
        /// firstRecord ...). `keys` is the key entry of the connection (null: none). `maxMemory` is what the table may use
        /// in total; on false nothing was recorded and the table stays exhausted (everything later is "state lost").
        /// `firstOutcome` receives where the outcomes start in the table.
        bool process(TlsSession &session, uint32_t sessionId, unsigned direction, uint32_t firstRecord, bool gapBefore,
                     std::span<const TlsRecordInput> records, const tls::KeyEntry *keys, size_t maxMemory, uint32_t &firstOutcome,
                     TlsMessageDecryption &out);

        /// What the session tables alone say about records that were not recorded (no key material): Clear, NoKey or
        /// NoHandshake. Also the rule process() uses to tell protected records from clear ones.
        static TlsRecordState unkeyedState(const TlsSession &session, unsigned direction, uint32_t index, uint8_t type);

        /// Detail building: the outcomes of the `records` of message `ref` (recorded ones, or derived), and the
        /// plaintext of the Decrypted ones, re-opened with `keys`.
        void read(const TlsSession &session, const TlsMessageRef &ref, std::span<const TlsRecordInput> records, const tls::KeyEntry *keys,
                  TlsMessageDecryption &out) const;

        const TlsRecordOutcome *outcomes(uint32_t first) const { return first < outcomes_.size() ? &outcomes_[first] : nullptr; }
        size_t outcomeCount() const { return outcomes_.size(); }
        size_t memory() const { return memory_; }
        bool exhausted() const { return exhausted_; }
        void clear();

    private:
        struct Runtime {
            std::optional<tls::RecordDecryptor> decryptor;
            std::optional<tls::KeyEntry> keys;   // the key entry the load pass used: detail building opens records with it, so
                                                 // keys that change afterwards (live capture) cannot make Replay differ
            bool built = false;
            bool desync[2] = {false, false};     // per direction: records are missing, later ones cannot be numbered
        };
        static constexpr size_t kRuntimeCost = 1152;   // a map node and a decryptor with two directions of keys and secrets

        static tls::Direction directionOf(const TlsSession &session, unsigned direction);

        std::vector<TlsRecordOutcome> outcomes_;
        std::unordered_map<uint32_t, Runtime> runtimes_;   // by session id: only connections that have key material
        size_t memory_ = 0;
        bool exhausted_ = false;
    };

    /// TLS 1.3: the protocol the server selected in EncryptedExtensions, from the decrypted plaintext of its handshake
    /// record(s). Empty if there is none (or the message is cut across records).
    std::string alpnFromEncryptedExtensions(std::span<const uint8_t> handshakePlaintext);

    /// What the application data starting at `data` is, judged by its first bytes (HTTP/2 client preface, HTTP/1.x
    /// request or status line); Unknown for anything else.
    TlsInner sniffTlsInner(std::span<const uint8_t> data);

    /// ALPN "h2" -> Http2, "http/1.1" / "http/1.0" -> Http1, anything else Unknown.
    TlsInner tlsInnerFromAlpn(const std::string &alpn);
} // namespace dissect
