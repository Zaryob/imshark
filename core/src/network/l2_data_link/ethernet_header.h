#pragma once

#include <cstdint>

namespace network {
    struct EthernetHeader {
        uint8_t dest_mac[6];    // Destination MAC address
        uint8_t src_mac[6];     // Source MAC address
        uint16_t type;          // Type
    };
}  // namespace network