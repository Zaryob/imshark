//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

namespace network {
    struct IPHeader {
        uint8_t ihl:4, version:4;  // IP version and header length
        uint8_t tos;                // Type of service
        uint16_t tot_length;        // Total length
        uint16_t id;                // Identification
        uint16_t frag_off;          // Fragment offset field
        uint8_t ttl;                // Time to live
        uint8_t protocol;           // Protocol
        uint16_t check;             // Header checksum
        uint32_t src_addr;          // Source IP addresses
        uint32_t dst_addr;          // Destination IP addresses
    };
} // namespace network
