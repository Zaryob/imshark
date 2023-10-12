//
// Created by Süleyman Poyraz on 12.10.2024.
//

#pragma once

#include <cstdint>

namespace network {
    std::string getMACAddressString(const uint8_t sender_hw_addr[6]) {
        std::ostringstream ss;
        for (int i = 0; i < 6; ++i) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sender_hw_addr[i]);
            if (i < 5) // Don't add a colon after the last byte
                ss << ":";
        }
        return ss.str();

    }

    std::string getDomainName(const char* data, size_t& offset, size_t length) {
        std::string domain;
        while (offset < length) {
            uint8_t labelLength = data[offset++];
            if (labelLength == 0) break; // End of domain name
            if (!domain.empty()) domain += ".";
            domain += std::string(data + offset, labelLength);
            offset += labelLength;
        }
        return domain;
    }
} // namespace network