#pragma once

// The IPsec headers of a capture. AH and ESP are layers that usually carry another protocol (AH always, ESP when its payload
// is not encrypted), and PacketInfo cannot grow: the summary fields an inner protocol such as TCP fills would overwrite the SPI
// and the sequence number. The load pass therefore records them here (one entry per packet that has an AH or ESP header, keyed
// by packet number, like the Ethernet addresses in ethernet_table.h) and the ah.* / esp.* filter fields read them back.

#include <cstddef>
#include <cstdint>
#include <vector>

namespace packet {
    class IpsecTable {
    public:
        struct Entry {
            uint32_t number = 0;     // packet number (1-based, as in PacketInfo::number)
            uint32_t ahSpi = 0, ahSequence = 0;
            uint32_t espSpi = 0, espSequence = 0;
            uint8_t flags = 0;       // kAh / kEsp: which of the two headers were seen (the outermost of each kind is recorded)
        };
        static constexpr uint8_t kAh = 1, kEsp = 2;

        /// Records an AH (or ESP) header of packet `number`. Numbers never decrease: the same packet may add its second header
        /// (AH + ESP), an older number is refused, and so is a new entry beyond `maxEntries`. A second header of the same
        /// kind in the packet (a tunnel inside a tunnel) keeps the first one.
        bool add(uint32_t number, uint8_t kind, uint32_t spi, uint32_t sequence, size_t maxEntries) {
            if (!entries_.empty() && number < entries_.back().number) return false;
            if (entries_.empty() || entries_.back().number != number) {
                if (entries_.size() >= maxEntries) return false;
                Entry e;
                e.number = number;
                entries_.push_back(e);
            }
            Entry &e = entries_.back();
            if (e.flags & kind) return true;
            e.flags = static_cast<uint8_t>(e.flags | kind);
            if (kind == kAh) { e.ahSpi = spi; e.ahSequence = sequence; }
            else { e.espSpi = spi; e.espSequence = sequence; }
            return true;
        }

        /// The headers of packet `number`, or nullptr if none were recorded for it.
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

    private:
        std::vector<Entry> entries_;
    };
} // namespace packet
