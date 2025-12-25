#pragma once

// DTLS as the load pass sees it (rule 4: decisions are made while the capture loads, detail building only reads).
// Three things are kept, all per DTLS connection (the two UDP endpoints):
//
//   - sessions   the randoms of the hellos, the negotiated version and cipher suite and, once the first protected record
//                needed them, the write keys derived from the key log (CLIENT_RANDOM). DTLS records carry their own epoch and
//                48 bit sequence number, so no per-direction counter is needed: every record can be opened on its own.
//   - handshake  fragments. Every handshake fragment of a packet gets a DtlsFragmentRef; fragments of one message
//                (key = endpoints + direction + epoch + message_seq) go through network::DatagramReassembler. The fragment
//                that completes a message knows where it came from, the earlier ones know where it was completed, and a
//                completed message that equals an earlier one (same bytes) is flagged as a retransmission.
//   - outcomes   what became of each protected record (epoch >= 1): a TlsRecordState (tls_summary.h) and the plaintext length.
//                No plaintext is kept; detail building opens the record again with the session's keys.
//
// Everything counts against one memory budget (the "dtls" table of SessionTables); when it runs out the table is state lost
// and the packets say so instead of showing nothing.
//
// Limits: a retransmitted lone fragment of a message that already completed starts a pending message that never completes
// (it is forgotten by the reassembler's timeout); renegotiation is not followed (every record of epoch >= 1 is opened with
// the key block of the first handshake); a pending message whose reassembler entry timed out keeps its fragment refs until
// the same key comes again.

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include <network/datagram_reassembly.h>
#include <tls/record_decryptor.h>

#include "tls_session.h"
#include "tls_summary.h"

namespace dissect {
    constexpr uint32_t kDtlsNone = 0xFFFFFFFFu;

    struct DtlsSession {
        bool hasClientRandom = false, hasServerRandom = false;
        TlsRandom clientRandom{}, serverRandom{};
        uint16_t version = 0;                    // ServerHello's server_version (0xfefd = DTLS 1.2; 0 = no ServerHello seen)
        uint16_t cipherSuite = 0;                // ServerHello's choice (0 = none seen)
        int8_t clientDirection = -1;             // 0 when the client is the endpoint that sorts first ("address/port" text order)
        bool keysReady = false;                  // `keys` hold the key block derived from the key log
        std::array<tls::Tls12WriteKeys, 2> keys; // client_write, server_write
    };

    struct DtlsHelloFacts {
        bool client = false;                     // ClientHello (else ServerHello)
        TlsRandom random{};
        uint16_t version = 0;                    // ServerHello: server_version
        uint16_t cipherSuite = 0;                // ServerHello: chosen suite
    };

    /// What the load pass found out about one handshake fragment of a packet (key: packet number and the offset of the
    /// fragment's handshake header inside the UDP payload).
    struct DtlsFragmentRef {
        enum : uint8_t {
            kCompletesHere = 1,        // this fragment completed its message
            kWhole = 2,                // ... and the message is this fragment alone (nothing was reassembled)
            kConflict = 4,             // an overlapping fragment disagreed with bytes the message already had
            kTotalConflict = 8,        // announced another message length than the first fragment: the message was dropped
            kRejected = 16,            // unusable fragment (beyond the message, or a message that is too large)
            kRetransmission = 32,      // the completed message equals one completed before (`retransmissionOf`)
        };
        uint32_t completedIn = 0;      // number of the packet that completed the message (0 = it never did)
        uint32_t message = kDtlsNone;  // kCompletesHere without kWhole: index into DtlsTable::message()
        uint32_t retransmissionOf = 0; // kRetransmission: packet that completed the message first
        uint8_t flags = 0;
    };

    /// A message put together from several fragments.
    struct DtlsMessage {
        std::string body;                        // the handshake message body (without the 12 byte header)
        std::vector<uint32_t> packets;           // packets whose fragments made it, arrival order
    };

    struct DtlsFragment {
        uint32_t packet = 0;
        uint16_t position = 0;                   // offset of the handshake header in the UDP payload
        uint16_t epoch = 0;
        uint16_t messageSeq = 0;
        uint8_t type = 0;
        uint32_t length = 0;                     // the whole message's length
        uint32_t offset = 0;                     // fragment_offset
        const char *data = nullptr;
        size_t size = 0;
        double time = 0;
    };

    struct DtlsRecordOutcome {
        uint32_t session = kDtlsNone;
        uint32_t plainLength = 0;
        uint8_t state = 0;                       // TlsRecordState
        bool fromClient = false;                 // the record travelled from the client (selects the write key)
        TlsRecordState recordState() const { return static_cast<TlsRecordState>(state); }
    };

    class DtlsTable {
    public:
        /// Registers a hello (a complete message). A hello whose random differs from the one the latest session of these
        /// endpoints already has starts a new session. Returns false when the budget did not allow it.
        bool addHello(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, const DtlsHelloFacts &facts,
                      size_t maxMemory);

        /// The latest session between the endpoints (kDtlsNone: none); `direction` is the index of the traffic from the
        /// first endpoint to the second, to compare with DtlsSession::clientDirection.
        uint32_t find(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, unsigned *direction = nullptr) const;
        const DtlsSession *session(uint32_t id) const { return id < sessions_.size() ? &sessions_[id] : nullptr; }
        DtlsSession *mutableSession(uint32_t id) { return id < sessions_.size() ? &sessions_[id] : nullptr; }

        /// Takes one handshake fragment. Returns false when the budget did not allow keeping it (nothing is recorded then);
        /// a fragment of a packet and position seen before is ignored. On completion `earlierPackets` receives the other
        /// packets whose fragments made the message (the earlier fragments now know where it was completed).
        bool addFragment(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, const DtlsFragment &fragment,
                         size_t maxMemory, std::vector<uint32_t> &earlierPackets);

        const DtlsFragmentRef *fragment(uint32_t packet, uint16_t position) const;
        const DtlsMessage *message(uint32_t index) const { return index < messages_.size() ? &messages_[index] : nullptr; }

        bool addOutcome(uint32_t packet, uint16_t position, const DtlsRecordOutcome &outcome, size_t maxMemory);
        const DtlsRecordOutcome *outcome(uint32_t packet, uint16_t position) const;

        size_t sessionCount() const { return sessions_.size(); }
        size_t fragmentCount() const { return fragments_.size(); }
        size_t messageCount() const { return messages_.size(); }
        size_t outcomeCount() const { return outcomes_.size(); }
        size_t pendingMessages() const { return reassembler_.pendingMessages(); }
        size_t memory() const { return memory_ + reassembler_.pendingBytes(); }
        void clear();

    private:
        struct Done { uint64_t hash = 0; uint32_t length = 0; uint8_t type = 0; uint32_t packet = 0; };

        static uint64_t positionKey(uint32_t packet, uint16_t position) { return (static_cast<uint64_t>(packet) << 16) | position; }
        // both endpoints in a fixed order, so both directions share one key; `direction` is 0 when the source sorts first
        static std::string connectionKey(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, unsigned &direction);
        void complete(const std::string &key, const DtlsFragment &f, const char *body, size_t size, DtlsFragmentRef &ref);

        std::vector<DtlsSession> sessions_;
        std::unordered_map<std::string, uint32_t> latest_;                 // connection key -> its newest session
        std::unordered_map<uint64_t, DtlsFragmentRef> fragments_;      // (packet, position) -> what became of the fragment
        std::unordered_map<std::string, std::vector<uint64_t>> pending_;   // message key -> the fragment refs waiting for completion
        std::unordered_map<std::string, Done> done_;                   // message key -> the message completed last (retransmissions)
        std::vector<DtlsMessage> messages_;
        std::unordered_map<uint64_t, DtlsRecordOutcome> outcomes_;
        network::DatagramReassembler reassembler_;
        size_t memory_ = 0;
    };
} // namespace dissect
