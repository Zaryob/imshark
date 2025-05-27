#pragma once

// IP address parsing and CIDR matching, independent of any platform socket API.

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>

namespace network {
    /// An IPv4 or IPv6 address. IPv4 uses the first 4 bytes of `bytes` (network order).
    struct IpAddress {
        bool v6 = false;
        std::array<uint8_t, 16> bytes{};

        bool operator==(const IpAddress &o) const { return v6 == o.v6 && bytes == o.bytes; }
        bool operator<(const IpAddress &o) const { return v6 != o.v6 ? v6 < o.v6 : bytes < o.bytes; }
    };

    namespace detail {
        inline int hexValue(char c) {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        }
    } // namespace detail

    /// "10.0.0.1" -> 4 bytes. Strict dotted decimal: four parts, 0-255, no leading zeros, no extra characters.
    inline std::optional<std::array<uint8_t, 4>> parseIPv4(std::string_view text) {
        std::array<uint8_t, 4> out{};
        size_t pos = 0;
        for (int part = 0; part < 4; ++part) {
            if (part > 0) {
                if (pos >= text.size() || text[pos] != '.') return std::nullopt;
                ++pos;
            }
            const size_t start = pos;
            unsigned value = 0;
            while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9') {
                value = value * 10 + static_cast<unsigned>(text[pos] - '0');
                if (value > 255) return std::nullopt;
                ++pos;
            }
            const size_t digits = pos - start;
            if (digits == 0 || digits > 3) return std::nullopt;
            if (digits > 1 && text[start] == '0') return std::nullopt; // leading zero (ambiguous octal)
            out[part] = static_cast<uint8_t>(value);
        }
        if (pos != text.size()) return std::nullopt;
        return out;
    }

    /// "2001:db8::1", "::ffff:1.2.3.4" -> 16 bytes (RFC 4291 text forms; no zone ids).
    inline std::optional<std::array<uint8_t, 16>> parseIPv6(std::string_view text) {
        std::array<uint8_t, 16> out{};
        uint16_t head[8], tail[8];
        int headCount = 0, tailCount = 0;
        bool compressed = false;
        size_t pos = 0;

        if (text.size() >= 2 && text[0] == ':' && text[1] == ':') {
            compressed = true;
            pos = 2;
        } else if (!text.empty() && text[0] == ':') {
            return std::nullopt;
        }

        bool first = true;
        while (pos < text.size()) {
            if (!first) {
                if (text[pos] != ':') return std::nullopt;
                ++pos;
                if (pos < text.size() && text[pos] == ':') { // "::"
                    if (compressed) return std::nullopt;
                    compressed = true;
                    ++pos;
                    if (pos >= text.size()) break;
                }
            }
            first = false;

            // trailing embedded IPv4
            const size_t dot = text.find('.', pos);
            const size_t colon = text.find(':', pos);
            if (dot != std::string_view::npos && (colon == std::string_view::npos || dot < colon)) {
                const auto v4 = parseIPv4(text.substr(pos));
                if (!v4) return std::nullopt;
                uint16_t hi = static_cast<uint16_t>(((*v4)[0] << 8) | (*v4)[1]);
                uint16_t lo = static_cast<uint16_t>(((*v4)[2] << 8) | (*v4)[3]);
                uint16_t *dst = compressed ? tail : head;
                int &n = compressed ? tailCount : headCount;
                if (headCount + tailCount + 2 > 8) return std::nullopt;
                dst[n++] = hi;
                dst[n++] = lo;
                pos = text.size();
                break;
            }

            unsigned value = 0;
            int digits = 0;
            while (pos < text.size() && detail::hexValue(text[pos]) >= 0) {
                value = value * 16 + static_cast<unsigned>(detail::hexValue(text[pos]));
                ++pos;
                if (++digits > 4) return std::nullopt;
            }
            if (digits == 0) return std::nullopt;
            if (headCount + tailCount + 1 > 8) return std::nullopt;
            (compressed ? tail[tailCount++] : head[headCount++]) = static_cast<uint16_t>(value);
        }

        const int total = headCount + tailCount;
        if (compressed ? total > 7 : total != 8) return std::nullopt; // "::" must stand for at least one group
        uint16_t groups[8] = {0};
        for (int i = 0; i < headCount; ++i) groups[i] = head[i];
        for (int i = 0; i < tailCount; ++i) groups[8 - tailCount + i] = tail[i];
        for (int i = 0; i < 8; ++i) {
            out[2 * i] = static_cast<uint8_t>(groups[i] >> 8);
            out[2 * i + 1] = static_cast<uint8_t>(groups[i] & 0xff);
        }
        return out;
    }

    /// Either family.
    inline std::optional<IpAddress> parseIpAddress(std::string_view text) {
        IpAddress a;
        if (text.find(':') != std::string_view::npos) {
            const auto b = parseIPv6(text);
            if (!b) return std::nullopt;
            a.v6 = true;
            a.bytes = *b;
        } else {
            const auto b = parseIPv4(text);
            if (!b) return std::nullopt;
            for (size_t i = 0; i < 4; ++i) a.bytes[i] = (*b)[i];
        }
        return a;
    }

    /// An address with a prefix length ("10.0.0.0/8"); a plain address is a /32 or /128.
    struct IpNetwork {
        IpAddress address;
        int prefix = 0;

        bool contains(const IpAddress &other) const {
            if (other.v6 != address.v6) return false;
            int bits = prefix;
            for (size_t i = 0; i < 16 && bits > 0; ++i, bits -= 8) {
                const uint8_t mask = bits >= 8 ? 0xff : static_cast<uint8_t>(0xff << (8 - bits));
                if ((other.bytes[i] & mask) != (address.bytes[i] & mask)) return false;
            }
            return true;
        }
    };

    inline std::optional<IpNetwork> parseIpNetwork(std::string_view text) {
        IpNetwork net;
        const auto slash = text.find('/');
        const auto addr = parseIpAddress(text.substr(0, slash));
        if (!addr) return std::nullopt;
        net.address = *addr;
        const int maxPrefix = addr->v6 ? 128 : 32;
        net.prefix = maxPrefix;
        if (slash != std::string_view::npos) {
            const auto digits = text.substr(slash + 1);
            if (digits.empty() || digits.size() > 3) return std::nullopt;
            int value = 0;
            for (char c: digits) {
                if (c < '0' || c > '9') return std::nullopt;
                value = value * 10 + (c - '0');
            }
            if (value > maxPrefix) return std::nullopt;
            net.prefix = value;
        }
        return net;
    }
} // namespace network
