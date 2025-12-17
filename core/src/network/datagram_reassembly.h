#pragma once

// Reassembly of messages that are split into fragments carried by separate datagrams
// (DTLS handshake messages, SCTP user messages). Nothing here knows the protocol: the caller
// builds the key and the fragment, the reassembler only puts bytes together.

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace network {
    struct DatagramFragment {
        uint32_t offset = 0;          // byte offset of `data` inside the whole message
        uint32_t totalLength = 0;     // length of the whole message (the first fragment of a key fixes it)
        std::vector<char> data;
        uint32_t packetNumber = 0;
        double time = 0;              // capture time in seconds (for the reassembly timeout)
    };

    /// Collects the fragments of messages while a capture is read, in capture order. Same shape as `IpReassembler`.
    class DatagramReassembler {
    public:
        struct Result {
            bool complete = false;
            std::vector<char> message;                  // the whole message when complete
            std::vector<uint32_t> packetNumbers;        // packets whose fragments were accepted for the message, in arrival
                                                        // order without repeats (including this one); filled when complete
            bool conflictingOverlap = false;            // an overlapping fragment carried different bytes than the first copy
                                                        // (the first copy still wins; reported on the fragment that disagreed
                                                        // and, sticky, on the completion result)
            bool totalConflict = false;                 // the fragment announced another total length than the first fragment:
                                                        // the pending message and this fragment were both discarded
            bool rejected = false;                      // the fragment itself is unusable (empty with a non-empty message, runs
                                                        // past the total, or the total is larger than kMaxMessageBytes); the
                                                        // pending message, if any, is untouched
        };

        /// A message whose first fragment is older than `timeoutSeconds` (capture time) is forgotten.
        explicit DatagramReassembler(double timeoutSeconds = 60.0) : timeout_(timeoutSeconds) {}

        /// `key` is opaque and built by the caller: for DTLS conversation + epoch + message_seq, for SCTP
        /// association + stream + TSN range. A message of total length 0 (DTLS HelloRequest) completes at once.
        /// A fragment of a message that already completed starts a new pending message under the same key.
        Result add(const std::string &key, const DatagramFragment &fragment);

        size_t pendingMessages() const { return sets_.size(); }
        size_t pendingBytes() const { return static_cast<size_t>(totalBytes_); }
        /// Messages dropped because their timeout ran out.
        size_t timedOutMessages() const { return timedOut_; }
        /// Messages dropped to stay inside kMaxPending / kMaxPendingBytes.
        size_t evictedMessages() const { return evicted_; }

        static constexpr size_t kMaxPending = 1024;                    // incomplete messages kept
        static constexpr uint64_t kMaxPendingBytes = 64ull << 20;      // total bytes held
        static constexpr uint32_t kMaxMessageBytes = 16u << 20;        // largest total length accepted (DTLS: 2^24 - 1)

    private:
        struct Set {
            uint32_t total = 0;
            std::map<uint32_t, std::vector<char>> segments;   // disjoint pieces by offset, first copy of each byte
            std::vector<uint32_t> packets;                    // arrival order, no repeats
            uint64_t bytes = 0;                               // sum of the segment sizes
            uint64_t order = 0;                               // insertion order, for evicting the oldest
            double firstTime = 0;                             // capture time of the first fragment
            bool conflict = false;
        };

        void evictOldest(const std::string *keep);

        std::map<std::string, Set> sets_;
        uint64_t totalBytes_ = 0;
        uint64_t counter_ = 0;
        double timeout_;
        size_t timedOut_ = 0;
        size_t evicted_ = 0;
    };
} // namespace network
