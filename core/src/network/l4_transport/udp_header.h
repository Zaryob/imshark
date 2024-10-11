//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

namespace network {
    struct UDPHeader {
        uint16_t src_port;  // Source port
        uint16_t dest_port; // Destination port
        uint16_t len;       // Length
        uint16_t check;     // Checksum
    };
} // namespace network