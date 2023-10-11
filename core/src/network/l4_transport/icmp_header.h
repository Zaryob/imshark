//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

namespace network {
    struct ICMPHeader {
        uint8_t type;        // ICMP message type
        uint8_t code;        // ICMP message code
        uint16_t checksum;   // ICMP checksum
        uint16_t identifier; // Identifier (for Echo Request/Reply)
        uint16_t sequence;   // Sequence number (for Echo Request/Reply)
    };
} // namespace network

