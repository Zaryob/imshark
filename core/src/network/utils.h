//
// Created by Süleyman Poyraz on 12.10.2024.
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <string>

#include <network/byteorder.h>

#include <network/l3_network/ip6_header.h>

namespace network {
    inline std::string getMACAddressString(const uint8_t sender_hw_addr[6]) {
        std::ostringstream ss;
        for (int i = 0; i < 6; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sender_hw_addr[i]);
            if (i < 5) // Don't add a colon after the last byte
                ss << ":";
        }
        return ss.str();
    }

    // Reads a (possibly compressed) DNS name starting at `offset`.
    // `data`/`length` describe the whole DNS message; `offset` is advanced past the name
    // as it appears at the original position (a compression pointer consumes 2 bytes).
    // Never reads outside [data, data + length); returns what was decoded so far on malformed input.
    inline std::string getDomainName(const char *data, size_t &offset, size_t length) {
        std::string domain;
        size_t pos = offset;
        size_t resume = 0;          // where to continue after the first compression pointer
        bool jumped = false;
        int hops = 0;

        while (pos < length) {
            const uint8_t labelLength = static_cast<uint8_t>(data[pos]);
            if (labelLength == 0) { // End of domain name
                ++pos;
                break;
            }
            if ((labelLength & 0xC0) == 0xC0) { // Compression pointer
                if (pos + 1 >= length || ++hops > 16) { pos = length; break; }
                const size_t target = ((labelLength & 0x3F) << 8) | static_cast<uint8_t>(data[pos + 1]);
                if (!jumped) resume = pos + 2;
                jumped = true;
                pos = target;
                continue;
            }
            if ((labelLength & 0xC0) != 0 || pos + 1 + labelLength > length) { pos = length; break; }
            if (!domain.empty()) domain += ".";
            domain.append(data + pos + 1, labelLength);
            pos += 1 + labelLength;
        }

        offset = jumped ? resume : pos;
        return domain;
    }

    inline std::string getIPv6AddressString(const ipv6_addr &addr) {
        return formatIPv6(&addr);
    }
} // namespace network
