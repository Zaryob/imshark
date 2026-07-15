#pragma once

#include <optional>
#include <string>
#include <vector>

#include <capture_reader.h>

#include <packet/ethernet_table.h>
#include <packet/packet_info.h>

namespace ui {
    enum class FindMode : int {
        Text = 0,        // text in the summary columns
        Filter = 1,      // display filter
        Hex = 2,         // byte sequence in the frame data, e.g. "de ad be ef"
        BytesText = 3,   // ASCII text in the frame data
    };

    /// Result of a search over the displayed rows.
    struct FindResult {
        int position = -1;   // index into the displayed order, -1 = no match
        std::string error;   // set when the query itself is invalid (bad display filter)
    };

    /// Finds the next (or previous) row after/before `fromPosition` (-1 = start from the first/last row),
    /// wrapping around. `order` is the displayed order (indices into `packets`).
    ///  - Text:   case-insensitive substring in the source, destination, protocol or info column
    ///  - Filter: a display filter expression (`ethernet`, the capture's address table, lets eth.* match IP frames too)
    FindResult findPacket(const std::vector<packet::PacketInfo> &packets, const std::vector<uint32_t> &order,
                          double captureStartEpoch, FindMode mode, const std::string &query, int fromPosition, bool forward,
                          const packet::EthernetAddressTable *ethernet = nullptr);

    /// What to look for inside the frame bytes.
    struct ByteNeedle {
        std::vector<uint8_t> bytes;
        bool ignoreCase = false;   // ASCII letters only
    };

    /// "de ad be ef", "DEADBEEF", "0xde 0xad", "de:ad:be:ef" -> bytes. On error returns nullopt and sets `error`.
    std::optional<ByteNeedle> parseHexNeedle(const std::string &text, std::string &error);
    /// The UTF-8 bytes of `text`, compared case-insensitively.
    ByteNeedle textNeedle(const std::string &text);
    bool frameContains(const std::vector<char> &frame, const ByteNeedle &needle);

    /// Like findPacket, but looks inside the frame bytes (read from `capturePath`). Returns position -1 and
    /// an empty error when nothing matches; an error text if the file could not be read; `cancelled` is set
    /// if `control` asked to stop.
    FindResult findBytes(const std::string &capturePath, const std::vector<packet::PacketInfo> &packets,
                         const std::vector<uint32_t> &order, const ByteNeedle &needle, int fromPosition, bool forward,
                         core::ScanControl *control, bool *cancelled = nullptr);
} // namespace ui
