#pragma once

// IPv4 fragment reassembly.

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
        };

        /// `key` identifies the datagram (source, destination, identification, protocol).
        Result add(const std::string &key, const IpFragment &fragment);

        size_t pendingDatagrams() const { return sets_.size(); }

    private:
        struct Set {
            std::vector<IpFragment> fragments;
            uint64_t bytes = 0;
            uint64_t order = 0;     // insertion order, for evicting the oldest
        };
        static constexpr size_t kMaxPending = 1024;                    // incomplete datagrams kept
        static constexpr uint64_t kMaxPendingBytes = 64ull << 20;      // total bytes held

        std::map<std::string, Set> sets_;
        uint64_t totalBytes_ = 0;
        uint64_t counter_ = 0;
    };
} // namespace network
