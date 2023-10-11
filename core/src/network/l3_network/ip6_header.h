//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

namespace network {
    struct ipv6_addr {
        unsigned char s6_addr[16]; // 128-bit IPv6 address (16 bytes)
    };

#pragma pack(push, 1)
    struct IPv6Header {
        uint32_t version: 4;        //  4-bit version
        uint32_t traffic_class: 8;  //  8-bit traffic class
        uint32_t flow_label: 20;    //  20-bit flow label
        uint16_t payload_len;       // 16-bit payload length
        uint8_t next_header;        // 8-bit next header (protocol)
        uint8_t hop_limit;          // 8-bit hop limit
        struct ipv6_addr src_addr;   // Source IPv6 address (16 bytes)
        struct ipv6_addr dst_addr;   // Destination IPv6 address (16 bytes)
    };
#pragma pack(pop)

} // namespace network
