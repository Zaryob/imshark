#pragma once

#include <cstdint>
#include <string>
#include <filesystem>
#include <vector>

#include <packet/packet_info.h>
#include <packet/packet_parser.h>

namespace core {
    /// Reads capture files (classic pcap and pcapng) into a list of parsed packets.
    ///
    /// Both entry points return true if the file could be read. On failure `message` describes the
    /// problem; on partial success (e.g. a truncated last packet) they return true, keep the packets
    /// that were read and describe the problem in `message`. `message` is empty when everything is fine.
    /// Malformed input never terminates the process.
    /// Interprets a std::string as UTF-8 (what the file dialog returns) when building a path. Needed on
    /// Windows, where a plain std::string path would go through the ANSI code page.
    inline std::filesystem::path pathFromUtf8(const std::string &utf8) {
        return std::filesystem::path(std::u8string(reinterpret_cast<const char8_t *>(utf8.data()), utf8.size()));
    }

    class FileProcessor {
        packet::PacketParser parser;
    public:
        bool processPcapFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                             std::string &message);

        bool processPcapngFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                               std::string &message);
    };
} // namespace core
