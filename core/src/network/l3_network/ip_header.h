//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

#include <network/byteorder.h>

namespace network {
    struct IPHeader {
        uint8_t ihl:4, version:4;   // IP version and header length
        uint8_t tos;                // Type of service
        uint16_t tot_length;        // Total length
        uint16_t id;                // Identification
        uint16_t flags_frag_off;    // 3 flag bits + 13-bit fragment offset (network byte order)
        uint8_t ttl;                // Time to live
        uint8_t protocol;           // Protocol
        uint16_t check;             // Header checksum
        uint32_t src_addr;          // Source IP addresses
        uint32_t dst_addr;          // Destination IP addresses

        // The top 3 bits: 0x4 = reserved, 0x2 = Don't Fragment, 0x1 = More Fragments
        uint8_t flags() const { return static_cast<uint8_t>(network::ntoh16(flags_frag_off) >> 13); }
        // Fragment offset in 8-byte units
        uint16_t fragmentOffset() const { return network::ntoh16(flags_frag_off) & 0x1FFF; }
    };
} // namespace network
