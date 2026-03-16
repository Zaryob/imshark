#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <string>

#include <network/byteorder.h>

namespace dissect {
    /// Copies a T out of [base, base + avail) at `off`. Returns false if it does not fit.
    /// memcpy (instead of reinterpret_cast) also avoids unaligned-access UB.
    template<typename T>
    bool readStruct(const char *base, size_t avail, size_t off, T &out) {
        if (off > avail || avail - off < sizeof(T)) return false;
        std::memcpy(&out, base + off, sizeof(T));
        return true;
    }

    inline uint16_t be16(const char *p) {
        uint16_t v;
        std::memcpy(&v, p, sizeof(v));
        return network::ntoh16(v);
    }

    inline uint32_t be32(const char *p) {
        uint32_t v;
        std::memcpy(&v, p, sizeof(v));
        return network::ntoh32(v);
    }

    inline uint16_t le16(const char *p) {
        uint16_t v;
        std::memcpy(&v, p, sizeof(v));
        return std::endian::native == std::endian::big ? network::bswap16(v) : v;
    }

    inline uint32_t le32(const char *p) {
        uint32_t v;
        std::memcpy(&v, p, sizeof(v));
        return std::endian::native == std::endian::big ? network::bswap32(v) : v;
    }

    inline std::string etherTypeName(uint16_t type) {
        switch (type) {
            case 0x0800: return "IPv4";
            case 0x86DD: return "IPv6";
            case 0x0806: return "ARP";
            case 0x8035: return "RARP";
            case 0x8100: return "802.1Q VLAN";
            case 0x8808: return "Ethernet flow control";
            case 0x8809: return "Slow Protocols";
            case 0x8847: return "MPLS unicast";
            case 0x8848: return "MPLS multicast";
            case 0x8863: return "PPPoE Discovery";
            case 0x8864: return "PPPoE Session";
            case 0x888E: return "802.1X Authentication";
            case 0x88A8: return "802.1ad VLAN";
            case 0x88CC: return "LLDP";
            default: return "unknown";
        }
    }

    /// `addr` points to 4 bytes in network byte order.
    inline std::string ip4(const void *addr) {
        return network::formatIPv4(addr);
    }

    inline std::string ip4(uint32_t addr) { return ip4(&addr); }

    inline std::string hexString(uint32_t value, int width) {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::setw(width) << std::setfill('0') << value;
        return ss.str();
    }

    /// Printable preview of a payload for the details tree
    inline std::string asciiPreview(const char *data, size_t length, size_t max = 40) {
        std::string out;
        for (size_t i = 0; i < std::min(length, max); ++i) {
            const auto c = static_cast<unsigned char>(data[i]);
            out += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
        }
        if (length > max) out += "...";
        return out;
    }

    /// Attacker-controlled text for Info and the field tree: printable ASCII only (anything else becomes '?'), at most `max`
    /// characters (then "..."). Use it for every string taken from a packet.
    inline std::string printableText(const void *data, size_t length, size_t max = 200) {
        std::string out;
        const auto *p = static_cast<const unsigned char *>(data);
        for (size_t i = 0; p && i < length && i < max; ++i) out += (p[i] >= 32 && p[i] < 127) ? static_cast<char>(p[i]) : '?';
        if (length > max) out += "...";
        return out;
    }
} // namespace dissect
