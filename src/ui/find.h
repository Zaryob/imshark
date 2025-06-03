#pragma once

#include <string>
#include <vector>

#include <packet/packet_info.h>

namespace ui {
    enum class FindMode : int { Text = 0, Filter = 1 };

    /// Result of a search over the displayed rows.
    struct FindResult {
        int position = -1;   // index into the displayed order, -1 = no match
        std::string error;   // set when the query itself is invalid (bad display filter)
    };

    /// Finds the next (or previous) row after/before `fromPosition` (-1 = start from the first/last row),
    /// wrapping around. `order` is the displayed order (indices into `packets`).
    ///  - Text:   case-insensitive substring in the source, destination, protocol or info column
    ///  - Filter: a display filter expression
    FindResult findPacket(const std::vector<packet::PacketInfo> &packets, const std::vector<uint32_t> &order,
                          double captureStartEpoch, FindMode mode, const std::string &query, int fromPosition, bool forward);
} // namespace ui
