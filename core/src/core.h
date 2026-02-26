#pragma once

#include <cstdint>
#include <string>
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
    class FileProcessor {
        packet::PacketParser parser;
    public:
        bool processPcapFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                             std::string &message);

        bool processPcapngFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets,
                               std::string &message);
    };
} // namespace core
