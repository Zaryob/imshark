#pragma once

// SCTP as the load pass sees it (rule 4: decisions are made while the capture loads, detail building only reads).
//
//   fragments   The DATA / I-DATA chunks that carry only part of a user message (not both the B and the E bit). The fragments of
//               one message are told apart by (association, direction, stream, SSN for ordered DATA / MID for I-DATA, ordered or
//               not) and follow each other by TSN (DATA) or FSN (I-DATA): the message is complete when the fragments from the one
//               with the B bit to the one with the E bit are all there. They can arrive in any order and repeat. A fragment
//               only carries a position inside the message through its neighbours, so the bytes are kept until the message is
//               complete and are then handed to network::DatagramReassembler (B2, with the offsets now known) which puts the
//               message together. The chunk that completed the message knows the message, the earlier chunks know where it
//               was completed, a chunk that repeats a fragment (or a fragment of a message completed before) is flagged as a
//               retransmission. The "association" is the pair of IP addresses and ports (the verification tag changes during an
//               association's life and multi-homed paths are not joined).
//   streams     Per direction and stream: DATA chunks, user bytes and finished messages seen in the capture (shown on the DATA
//               chunks; the total, so it does not depend on the packet looked at).
//
// Everything counts against one memory budget (the "sctp" table of SessionTables). When it runs out, or an incomplete message had
// to be dropped to make room, the table is state lost and the chunks say so instead of showing nothing.
//
// Limits: incomplete messages stay until the budget evicts them (no timeout); the verification tag is not part of the key, so
// two associations between the same address/port pairs share their state (a port reuse after an ABORT may mix fragments); a
// fragment of an already completed message is a retransmission only while it is the latest message of its key.

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <network/datagram_reassembly.h>

namespace dissect {
    constexpr uint32_t kSctpNone = 0xFFFFFFFFu;

    struct SctpFragmentRef {
        enum : uint8_t {
            kCompletesHere = 1,        // this fragment completed its message (`message`)
            kConflict = 2,             // a repeated fragment carried other bytes than the first copy
            kRetransmission = 4,       // the fragment (or its whole message) was seen before: `original`
            kRejected = 8,             // unusable (the message would be larger than the reassembler accepts)
        };
        uint32_t completedIn = 0;      // number of the packet that completed the message (0 = it never did)
        uint32_t message = kSctpNone;  // kCompletesHere: index into SctpTable::message()
        uint32_t original = 0;         // kRetransmission: packet of the first copy (or that completed the message)
        uint8_t flags = 0;
    };

    struct SctpMessage {
        std::string data;
        std::vector<uint32_t> packets;     // packets whose fragments made it, in fragment order, without repeats
        uint16_t stream = 0;
        uint32_t ssn = 0;                  // SSN (DATA) or MID (I-DATA)
        bool idata = false, unordered = false;
        uint32_t ppid = 0;                 // from the first fragment
    };

    struct SctpFragment {
        uint32_t packet = 0;
        uint16_t position = 0;             // offset of the chunk inside the SCTP packet
        bool idata = false, begin = false, end = false, unordered = false;
        uint16_t stream = 0;
        uint32_t ssn = 0;                  // SSN (DATA) or MID (I-DATA)
        uint32_t sequence = 0;             // TSN (DATA) or FSN (I-DATA)
        uint32_t ppid = 0;                 // meaningful in the fragment with the B bit
        const char *data = nullptr;
        size_t size = 0;
        double time = 0;
    };

    struct SctpStreamStats {
        uint32_t chunks = 0;
        uint64_t bytes = 0;
        uint32_t messages = 0;             // chunks that ended a message (E bit)
    };

    class SctpTable {
    public:
        struct AddResult {
            bool kept = true;              // the fragment got its reference (false: no room, nothing was recorded)
            bool evicted = false;          // incomplete messages were dropped to make room
        };

        /// Takes one fragment. A fragment of a packet and position seen before is ignored. On completion `earlierPackets`
        /// receives the other packets whose fragments made the message.
        AddResult addFragment(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, const SctpFragment &fragment,
                              size_t maxMemory, std::vector<uint32_t> &earlierPackets);
        const SctpFragmentRef *fragment(uint32_t packet, uint16_t position) const;
        const SctpMessage *message(uint32_t index) const { return index < messages_.size() ? &messages_[index] : nullptr; }

        /// Counts one DATA / I-DATA chunk of a stream (every chunk, fragmented or not; a chunk of a packet and position already
        /// counted is ignored). Returns false when the budget did not allow it.
        bool noteData(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, uint16_t stream, size_t bytes, bool endsMessage,
                      uint32_t packet, uint16_t position, size_t maxMemory);
        const SctpStreamStats *stream(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, uint16_t stream) const;
        /// Number of different streams that carried DATA in this direction.
        size_t streamCount(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort) const;

        size_t fragmentCount() const { return refs_.size(); }
        size_t messageCount() const { return messages_.size(); }
        size_t pendingMessages() const { return pending_.size(); }
        size_t evictedMessages() const { return evicted_; }
        size_t memory() const { return memory_ + reassembler_.pendingBytes(); }
        void clear();

    private:
        struct Held {
            uint32_t packet = 0;
            uint16_t position = 0;
            bool begin = false, end = false;
            uint32_t ppid = 0;
            std::string bytes;
        };
        struct Pending {
            std::unordered_map<uint32_t, Held> fragments;     // by TSN / FSN
            uint64_t bytes = 0;
            uint64_t age = 0;                                 // creation order, for evicting the oldest
            uint16_t stream = 0;
            uint32_t ssn = 0;
            bool idata = false, unordered = false;
        };
        struct Done { uint32_t first = 0, last = 0, packet = 0; };
        struct Direction { size_t streams = 0; uint64_t lastNoted = 0; bool any = false; };

        static uint64_t refKey(uint32_t packet, uint16_t position) { return (static_cast<uint64_t>(packet) << 16) | position; }
        static std::string directionKey(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort);
        static std::string messageKey(const std::string &direction, const SctpFragment &f);
        bool storeRef(uint64_t key, const SctpFragmentRef &ref, size_t maxMemory);
        void dropPending(std::unordered_map<std::string, Pending>::iterator it);
        bool makeRoom(size_t need, size_t maxMemory, const std::string &keep, bool &evicted);

        std::unordered_map<uint64_t, SctpFragmentRef> refs_;
        std::unordered_map<std::string, Pending> pending_;
        std::map<uint64_t, std::string> byAge_;               // Pending::age -> key
        std::unordered_map<std::string, Done> done_;
        std::vector<SctpMessage> messages_;
        std::unordered_map<std::string, SctpStreamStats> streams_;     // direction key + stream
        std::unordered_map<std::string, Direction> directions_;
        network::DatagramReassembler reassembler_;
        size_t memory_ = 0;
        uint64_t counter_ = 0;
        size_t evicted_ = 0;
    };
} // namespace dissect
