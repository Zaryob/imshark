#pragma once

// Small helpers shared by the capture file readers and the format registry.

#include <cstdint>
#include <cstring>
#include <istream>
#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <capture_info.h>

namespace core::io {
    // Upper bound for a single record/block; anything larger is treated as corruption instead of being allocated.
    constexpr uint64_t kMaxRecordSize = 256ull * 1024 * 1024;

    constexpr uint32_t kPcapMagicMicro = 0xa1b2c3d4;
    constexpr uint32_t kPcapMagicNano = 0xa1b23c4d;
    constexpr uint32_t kBlockSHB = 0x0A0D0D0A; // pcapng Section Header Block (also the pcapng magic number)

    inline uint16_t swap16(uint16_t v) { return static_cast<uint16_t>((v << 8) | (v >> 8)); }

    inline uint32_t swap32(uint32_t v) {
        return (v << 24) | ((v & 0xff00u) << 8) | ((v >> 8) & 0xff00u) | (v >> 24);
    }

    /// Reads fixed-size integers from a buffer in the byte order of the capture file.
    struct Endian {
        bool swap = false;

        uint16_t u16(const uint8_t *p) const {
            uint16_t v;
            std::memcpy(&v, p, sizeof(v));
            return swap ? swap16(v) : v;
        }

        uint32_t u32(const uint8_t *p) const {
            uint32_t v;
            std::memcpy(&v, p, sizeof(v));
            return swap ? swap32(v) : v;
        }
    };

    // Byte order independent field access for the formats that fix their byte order (snoop, iptrace and the ERF
    // header are big endian, Network Monitor and the ERF timestamp little endian).
    inline uint16_t be16(const uint8_t *p) { return static_cast<uint16_t>(p[0] << 8 | p[1]); }
    inline uint32_t be32(const uint8_t *p) { return uint32_t(p[0]) << 24 | uint32_t(p[1]) << 16 | uint32_t(p[2]) << 8 | p[3]; }
    inline uint16_t le16(const uint8_t *p) { return static_cast<uint16_t>(p[1] << 8 | p[0]); }
    inline uint32_t le32(const uint8_t *p) { return uint32_t(p[3]) << 24 | uint32_t(p[2]) << 16 | uint32_t(p[1]) << 8 | p[0]; }
    inline uint64_t le64(const uint8_t *p) { return uint64_t(le32(p + 4)) << 32 | le32(p); }

    /// Link type given to frames whose medium ImShark has no mapping for (LINKTYPE_USER0): the dissector table has no
    /// entry for it, so the packet list says "Unsupported link type 147" and the details show the bytes as data.
    constexpr uint32_t kUnmappedLinkType = 147;

    /// Counts the frames of media a reader cannot map and says so once at the end of the load.
    struct UnmappedMedia {
        uint64_t frames = 0;
        std::string first;                   // description of the first unmapped medium seen

        void note(const std::string &medium) {
            if (frames++ == 0) first = medium;
        }

        /// Appends "<n> frame(s) of <medium> cannot be decoded ..." to a load message.
        void report(std::string &message) const {
            if (frames == 0) return;
            if (!message.empty()) message += "; ";
            message += std::to_string(frames) + " frame(s) of unsupported medium (first: " + first + ") are shown as raw data";
        }
    };

    /// Finds or appends the capture interface for a (link type, key) pair as a reader meets them.
    struct InterfaceTable {
        std::vector<std::pair<uint64_t, int>> index;

        int find(core::CaptureInfo &info, uint64_t key, uint32_t linkType, uint64_t ticksPerSecond, const std::string &name) {
            for (const auto &[k, i]: index) if (k == key) return i;
            core::InterfaceInfo itf;
            itf.linkType = linkType;
            itf.ticksPerSecond = ticksPerSecond;
            itf.name = name;
            info.interfaces.push_back(itf);
            index.push_back({key, static_cast<int>(info.interfaces.size() - 1)});
            return index.back().second;
        }
    };

    /// Bytes between the current read position and the end of a file of `fileSize` bytes.
    inline uint64_t remainingBytes(std::istream &file, uint64_t fileSize) {
        const auto pos = file.tellg();
        if (pos < 0) return 0;
        return fileSize - std::min<uint64_t>(fileSize, static_cast<uint64_t>(pos));
    }
} // namespace core::io
