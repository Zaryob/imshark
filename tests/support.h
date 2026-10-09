#pragma once

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <string>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>
#include <atomic>
#if defined(_WIN32)
#include <process.h>
#else
#include <unistd.h>
#endif

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

    inline std::string tempPath(const std::string &name) {
        static std::atomic<uint64_t> seq{0};
#if defined(_WIN32)
        const auto pid = static_cast<unsigned long>(_getpid());
#else
        const auto pid = static_cast<unsigned long>(getpid());
#endif
        return (std::filesystem::temp_directory_path() /
                ("imshark_test_" + std::to_string(pid) + "_" + std::to_string(seq.fetch_add(1)) + "_" + name)).string();
    }

    /// A path in the platform's own spelling: the UI stores native paths, so on Windows a "C:/x/y" literal reads back with backslashes.
    inline std::string nativePath(const std::string &path) { return std::filesystem::path(path).make_preferred().string(); }

    inline std::string writeTemp(const std::string &name, const std::vector<char> &bytes) {
        const auto path = tempPath(name);
        std::ofstream f(path, std::ios::binary);
        f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        return path;
    }

    // ---- synthetic traffic -----------------------------------------------------------------------------
    inline std::string hexOf(const std::string &bytes) {
        static const char *d = "0123456789abcdef";
        std::string out;
        for (unsigned char c: bytes) { out += d[c >> 4]; out += d[c & 15]; }
        return out;
    }

    /// Ethernet + IPv4 + TCP (20-byte header) frame carrying `payload`. Addresses are 8 hex digits, ports 4,
    /// seq/ack 8, flags 2 (e.g. "18" = PSH+ACK).
    inline std::vector<char> tcpPacket(const std::string &src, const std::string &dst, const std::string &sport,
                                       const std::string &dport, const std::string &seq, const std::string &ack,
                                       const std::string &flags, const std::string &payload = "") {
        char total[8];
        std::snprintf(total, sizeof total, "%04zx", 40 + payload.size());
        return hex("001122334455 aabbccddeeff 0800 4500" + std::string(total) + "0000 0000 4006 0000 " + src + " " + dst + " " + sport +
                   " " + dport + " " + seq + " " + ack + " 50" + flags + " 2000 0000 0000 " + hexOf(payload));
    }

    inline std::vector<char> udpPacket(const std::string &src, const std::string &dst, const std::string &sport,
                                       const std::string &dport, const std::string &payload) {
        char total[8], len[8];
        std::snprintf(total, sizeof total, "%04zx", 28 + payload.size());
        std::snprintf(len, sizeof len, "%04zx", 8 + payload.size());
        return hex("001122334455 aabbccddeeff 0800 4500" + std::string(total) + "0000 0000 4011 0000 " + src + " " + dst + " " + sport +
                   " " + dport + " " + len + " 0000 " + hexOf(payload));
    }

    /// A classic little-endian pcap file (Ethernet) with one frame per entry, 1 ms apart.
    inline std::vector<char> pcapBytes(const std::vector<std::vector<char>> &frames) {
        std::vector<char> f;
        put<uint32_t>(f, 0xa1b2c3d4);
        put<uint16_t>(f, 2);
        put<uint16_t>(f, 4);
        put<int32_t>(f, 0);
        put<uint32_t>(f, 0);
        put<uint32_t>(f, 65535);
        put<uint32_t>(f, 1);
        uint32_t t = 0;
        for (const auto &fr: frames) {
            put<uint32_t>(f, 1700000000 + t / 1000);
            put<uint32_t>(f, (t % 1000) * 1000);
            put<uint32_t>(f, static_cast<uint32_t>(fr.size()));
            put<uint32_t>(f, static_cast<uint32_t>(fr.size()));
            f.insert(f.end(), fr.begin(), fr.end());
            ++t;
        }
        return f;
    }

    // ---- sample frames -----------------------------------------------------------------------
    // Ethernet + IPv4 + UDP (10.0.0.1:4660 -> 10.0.0.2:53, empty payload)
    inline const char *kEthIpUdp =
        "001122334455 aabbccddeeff 0800 4500001c000000004011 0000 0a000001 0a000002 1234 0035 0008 0000";
    // ARP request: who has 10.0.0.2? tell 10.0.0.1
    inline const char *kArpRequest =
        "ffffffffffff 001122334455 0806 0001 0800 06 04 0001 001122334455 0a000001 000000000000 0a000002";
} // namespace support
