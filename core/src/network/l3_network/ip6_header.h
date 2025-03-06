//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

#include <arpa/inet.h>

namespace network {
    struct ipv6_addr {
        unsigned char bytes[16]; // 128-bit IPv6 address (16 bytes; not named s6_addr, which is a macro on some platforms)
    };

#pragma pack(push, 1)
    struct IPv6Header {
        uint32_t ver_tc_flow;       // version (4 bits) | traffic class (8) | flow label (20), network byte order
        uint16_t payload_len;       // 16-bit payload length
        uint8_t next_header;        // 8-bit next header (protocol)
        uint8_t hop_limit;          // 8-bit hop limit
        struct ipv6_addr src_addr;   // Source IPv6 address (16 bytes)
        struct ipv6_addr dst_addr;   // Destination IPv6 address (16 bytes)

        uint8_t version() const { return static_cast<uint8_t>(ntohl(ver_tc_flow) >> 28); }
        uint8_t trafficClass() const { return static_cast<uint8_t>((ntohl(ver_tc_flow) >> 20) & 0xFF); }
        uint32_t flowLabel() const { return ntohl(ver_tc_flow) & 0xFFFFF; }
    };
#pragma pack(pop)

} // namespace network
