#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include <packet/packet_info.h>

namespace ui {
    /// The value part of a tree label: "Source Port: 443" -> "443" (the whole text if there is no ": ").
    std::string fieldValue(const packet::Field &field);

    /// "de ad be ef" for `length` bytes starting at `offset` (clamped to the data).
    std::string bytesToHex(const std::vector<char> &data, size_t offset, size_t length);

    /// Printable ASCII for the bytes, '.' for everything else.
    std::string bytesToAscii(const std::vector<char> &data, size_t offset, size_t length);

    /// Classic 16-bytes-per-line dump: offset, hex bytes and the ASCII column.
    std::string hexDump(const std::vector<char> &data);

    /// Tab separated columns of the packet list row (No, Time, Source, Destination, Protocol, Length, Info).
    std::string summaryRow(const packet::PacketInfo &packet);
} // namespace ui
