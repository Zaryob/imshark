#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <packet/packet_parser.h>

namespace support {
    /// "00 11 22" / "001122" -> bytes (whitespace ignored)
    inline std::vector<char> hex(const std::string &text) {
        std::vector<char> out;
        std::string digits;
        for (char c: text) {
            if (c != ' ' && c != '\n') digits += c;
        }
        for (size_t i = 0; i + 1 < digits.size(); i += 2) {
            out.push_back(static_cast<char>(std::stoi(digits.substr(i, 2), nullptr, 16)));
        }
        return out;
    }

    inline packet::PacketInfo parse(const std::vector<char> &frame, uint32_t linkType = 1) {
        packet::PacketParser parser;
        packet::PacketInfo info(1);
        info.link_type = linkType;
        std::vector<char> data = frame;
        parser.parsePacket(info, data);
        info.captured_length = info.frame_length = static_cast<uint32_t>(frame.size());
        return info;
    }

    template<typename T>
    void put(std::vector<char> &out, T value, bool bigEndian = false) {
        char bytes[sizeof(T)];
        std::memcpy(bytes, &value, sizeof(T));
        if (bigEndian) std::reverse(bytes, bytes + sizeof(T));
        out.insert(out.end(), bytes, bytes + sizeof(T));
    }

    inline std::string writeTemp(const std::string &name, const std::vector<char> &bytes) {
        const auto path = (std::filesystem::temp_directory_path() / ("imshark_test_" + name)).string();
        std::ofstream f(path, std::ios::binary);
        f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        return path;
    }

    // ---- sample frames -----------------------------------------------------------------------
    // Ethernet + IPv4 + UDP (10.0.0.1:4660 -> 10.0.0.2:53, empty payload)
    inline const char *kEthIpUdp =
        "001122334455 aabbccddeeff 0800 4500001c000000004011 0000 0a000001 0a000002 1234 0035 0008 0000";
    // ARP request: who has 10.0.0.2? tell 10.0.0.1
    inline const char *kArpRequest =
        "ffffffffffff 001122334455 0806 0001 0800 06 04 0001 001122334455 0a000001 000000000000 0a000002";
} // namespace support
