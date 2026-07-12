#pragma once

// The MAC addresses of every Ethernet frame of a capture (ROADMAP B8). The packet summary holds one address pair that the
// IP dissector replaces by the IP addresses and PacketInfo cannot grow, so the load pass records the pair of each frame here
// (6 + 6 bytes + the packet number) and the statistics and the eth.* filter fields read it back by packet number.

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace packet {
    class EthernetAddressTable {
    public:
        struct Entry {
            uint32_t number = 0;             // packet number (1-based, as in PacketInfo::number)
            std::array<uint8_t, 6> source{};
            std::array<uint8_t, 6> destination{};
        };

        /// Appends the addresses of packet `number`. Numbers must increase: a number that is not greater than the last one is
        /// refused (a packet is recorded once), and so is any entry beyond `maxEntries`.
        bool add(uint32_t number, const uint8_t *source, const uint8_t *destination, size_t maxEntries) {
            if (!entries_.empty() && number <= entries_.back().number) return false;
            if (entries_.size() >= maxEntries) return false;
            Entry e;
            e.number = number;
            for (size_t i = 0; i < 6; ++i) { e.source[i] = source[i]; e.destination[i] = destination[i]; }
            entries_.push_back(e);
            return true;
        }

        /// The addresses of packet `number`, or nullptr if none were recorded for it.
        const Entry *find(uint32_t number) const {
            size_t lo = 0, hi = entries_.size();
            while (lo < hi) {
                const size_t mid = lo + (hi - lo) / 2;
                if (entries_[mid].number < number) lo = mid + 1; else hi = mid;
            }
            return lo < entries_.size() && entries_[lo].number == number ? &entries_[lo] : nullptr;
        }

        size_t size() const { return entries_.size(); }
        bool empty() const { return entries_.empty(); }
        void clear() { entries_.clear(); entries_.shrink_to_fit(); }
        size_t memory() const { return entries_.capacity() * sizeof(Entry); }

        /// "aa:bb:cc:dd:ee:ff" (lower case), the form the Ethernet dissector puts into PacketInfo::source.
        static std::string format(const std::array<uint8_t, 6> &mac) {
            static const char digits[] = "0123456789abcdef";
            std::string out(17, ':');
            for (size_t i = 0; i < 6; ++i) {
                out[i * 3] = digits[mac[i] >> 4];
                out[i * 3 + 1] = digits[mac[i] & 0xF];
            }
            return out;
        }

    private:
        std::vector<Entry> entries_;
    };
} // namespace packet
