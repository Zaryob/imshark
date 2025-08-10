#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace core {
    /// One capture interface (pcapng IDB, or the single interface of a classic pcap file).
    struct InterfaceInfo {
        uint32_t linkType = 1;
        uint32_t snapLen = 0;
        uint64_t ticksPerSecond = 1000000;  // timestamp resolution (ticks per second)
        std::string name, description;
        uint64_t packets = 0;               // packets of this interface in the file
        bool hasStats = false;              // an Interface Statistics Block was present
        uint64_t received = 0, dropped = 0; // from the statistics block (if given)
        uint8_t fcsLength = 0;              // FCS bytes appended to each frame (0 = unknown/none)
    };

    struct NameRecord {
        std::string address;
        std::string name;
    };

    /// Metadata of a capture file that is not part of any packet.
    struct CaptureInfo {
        std::string format;                  // "pcap" / "pcapng" with byte order and precision
        uint64_t fileSize = 0;               // size of the file the packets are read from (decompressed size for .gz)
        std::string container;               // "gzip" if the file was opened from a compressed copy
        uint64_t compressedSize = 0;         // size of the compressed file (0 if not compressed)
        uint32_t sections = 0;               // pcapng section header blocks
        std::string comment, hardware, os, application; // first section header
        std::vector<InterfaceInfo> interfaces;
        std::vector<NameRecord> names;       // name resolution blocks (capped)
        std::unordered_map<uint32_t, std::string> packetComments; // by packet number
    };
} // namespace core
