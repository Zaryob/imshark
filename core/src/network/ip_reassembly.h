#pragma once

// IP fragment reassembly (IPv4 and IPv6).

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace network {
    struct IpFragment {
        uint32_t offset = 0;          // byte offset of the data inside the original payload
        bool moreFragments = false;   // the MF flag
        std::vector<char> data;
        uint32_t packetNumber = 0;
        uint8_t protocol = 0;         // upper layer protocol the fragment announces (meaningful in the offset 0 fragment)
        double time = 0;              // capture time in seconds (for the reassembly timeout)
    };

    /// Puts fragments (any order, duplicates allowed) together. Returns true and fills `payload` only if
    /// the datagram is complete: the last fragment (MF = 0) is present and there are no holes.
    bool assembleIpv4Payload(const std::vector<IpFragment> &fragments, std::vector<char> &payload);

    /// Collects the fragments of datagrams while a capture is read, in capture order.
    class IpReassembler {
    public:
        struct Result {
            bool complete = false;
            std::vector<char> payload;                  // the whole payload when complete
            std::vector<uint32_t> fragmentNumbers;      // packets that made up the datagram (including this one)
            uint8_t protocol = 0;                       // protocol announced by the offset 0 fragment (when complete)
            bool overlapDiscarded = false;              // strict mode: conflicting overlap, the datagram was dropped
        };

        /// A datagram whose first fragment is older than `timeoutSeconds` (capture time) is forgotten.
        explicit IpReassembler(double timeoutSeconds = 60.0) : timeout_(timeoutSeconds) {}

        /// `key` identifies the datagram (source, destination, identification, protocol).
        /// `strictOverlap` (IPv6, RFC 5722): a fragment that overlaps another one with different data makes the
        /// whole datagram invalid. Otherwise the first copy of an overlapping byte wins (IPv4 behaviour).
        Result add(const std::string &key, const IpFragment &fragment, bool strictOverlap = false);

        size_t pendingDatagrams() const { return sets_.size(); }
        /// Datagrams dropped because their timeout ran out.
        size_t expiredDatagrams() const { return expired_; }

    private:
        struct Set {
            std::vector<IpFragment> fragments;
            uint64_t bytes = 0;
            uint64_t order = 0;     // insertion order, for evicting the oldest
            double firstTime = 0;   // capture time of the first fragment
        };
        static constexpr size_t kMaxPending = 1024;                    // incomplete datagrams kept
        static constexpr uint64_t kMaxPendingBytes = 64ull << 20;      // total bytes held

        std::map<std::string, Set> sets_;
        uint64_t totalBytes_ = 0;
        uint64_t counter_ = 0;
        double timeout_;
        size_t expired_ = 0;
    };
} // namespace network
