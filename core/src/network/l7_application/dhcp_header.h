//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

namespace network {
    struct DHCPHeader {
        uint8_t op;               // Message op code / message type
        uint8_t hw_type;            // Hardware address type
        uint8_t hw_len;             // Hardware address length
        uint8_t hops;             // Hops
        uint32_t xid;             // Transaction ID
        uint16_t secs;            // Seconds elapsed since client started
        uint16_t flags;           // Flags
        uint32_t cip_addr;          // Client IP address
        uint32_t yip_addr;          // 'Your' (client) IP address
        uint32_t sip_addr;          // Next server IP address
        uint32_t gip_addr;          // Relay agent IP address
        uint8_t ch_addr[16];       // Client hardware address
        uint8_t srv_hname[64];        // Server host name
        uint8_t file[128];        // Boot file name
    };
} // namespace network