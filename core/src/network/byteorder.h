#pragma once

// Portable replacements for the POSIX/Winsock byte-order and address formatting functions
// (ntohs, htonl, inet_ntop, ...), so the core builds without <arpa/inet.h> or Winsock.
// Network byte order is big endian. Named ntoh16/hton32/... because ntohs & co. are macros on some platforms.

#include <bit>
#include <cstdint>
#include <string>

namespace network {
    constexpr uint16_t bswap16(uint16_t v) { return static_cast<uint16_t>((v << 8) | (v >> 8)); }

    constexpr uint32_t bswap32(uint32_t v) {
        return (v << 24) | ((v & 0xff00u) << 8) | ((v >> 8) & 0xff00u) | (v >> 24);
    }

    constexpr uint16_t ntoh16(uint16_t v) { return std::endian::native == std::endian::little ? bswap16(v) : v; }
    constexpr uint32_t ntoh32(uint32_t v) { return std::endian::native == std::endian::little ? bswap32(v) : v; }
    constexpr uint16_t hton16(uint16_t v) { return ntoh16(v); }
    constexpr uint32_t hton32(uint32_t v) { return ntoh32(v); }

    /// Dotted-decimal form of 4 bytes in network order.
    inline std::string formatIPv4(const void *addr) {
        const auto *b = static_cast<const uint8_t *>(addr);
        return std::to_string(b[0]) + "." + std::to_string(b[1]) + "." + std::to_string(b[2]) + "." + std::to_string(b[3]);
    }

    /// Text form of 16 address bytes (RFC 5952 style, same output as inet_ntop: the longest run of zero
    /// groups becomes "::", IPv4-mapped addresses end in dotted decimal).
    inline std::string formatIPv6(const void *addr) {
        const auto *b = static_cast<const uint8_t *>(addr);
        uint16_t w[8];
        for (int i = 0; i < 8; ++i) w[i] = static_cast<uint16_t>((b[2 * i] << 8) | b[2 * i + 1]);

        // find the longest run of zero groups (the first one wins a tie)
        int bestBase = -1, bestLen = 0, curBase = -1, curLen = 0;
        for (int i = 0; i < 8; ++i) {
            if (w[i] == 0) {
                if (curBase == -1) { curBase = i; curLen = 1; } else { ++curLen; }
            } else if (curBase != -1) {
                if (bestBase == -1 || curLen > bestLen) { bestBase = curBase; bestLen = curLen; }
                curBase = -1;
            }
        }
        if (curBase != -1 && (bestBase == -1 || curLen > bestLen)) { bestBase = curBase; bestLen = curLen; }
        if (bestBase != -1 && bestLen < 2) bestBase = -1;

        static const char digits[] = "0123456789abcdef";
        std::string out;
        for (int i = 0; i < 8; ++i) {
            if (bestBase != -1 && i >= bestBase && i < bestBase + bestLen) {
                if (i == bestBase) out += ':';
                continue;
            }
            if (i != 0) out += ':';
            if (i == 6 && bestBase == 0 &&
                (bestLen == 6 || (bestLen == 7 && w[7] != 1) || (bestLen == 5 && w[5] == 0xffff))) {
                out += formatIPv4(b + 12); // encapsulated IPv4 address
                return out;
            }
            bool started = false;
            for (int shift = 12; shift >= 0; shift -= 4) {
                const int nibble = (w[i] >> shift) & 0xf;
                if (nibble != 0 || started || shift == 0) { out += digits[nibble]; started = true; }
            }
        }
        if (bestBase != -1 && bestBase + bestLen == 8) out += ':';
        return out;
    }
} // namespace network
