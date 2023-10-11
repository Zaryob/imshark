//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

namespace network {
    struct ARPHeader {
        uint16_t hw_type;                   // Hardware type
        uint16_t protocol_type;             // Protocol type
        uint8_t hw_addr_len;                // Hardware address length
        uint8_t protocol_addr_len;          // Protocol address length
        uint16_t opcode;                    // Operation code
        uint8_t sender_hw_addr[6];          // Sender hardware address
        uint8_t sender_protocol_addr[4];    // Sender protocol address
        uint8_t target_hw_addr[6];          // Target hardware address
        uint8_t target_protocol_addr[4];    // Target protocol address
    };
} // namespace network
