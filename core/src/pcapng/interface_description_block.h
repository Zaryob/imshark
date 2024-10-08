#pragma once

#include <cstdint>

struct InterfaceDescriptionBlock {
    uint32_t blockType;          // Block Type, should be 0x00000001 for IDB
    uint32_t blockTotalLength;   // Total block length (including the header and trailer)
    uint16_t linkType;           // Data link type (Ethernet, etc.)
    uint16_t reserved;           // Reserved, must be zero
    uint32_t snaplen;            // Maximum length of captured packets, in octets
    // Optional fields (omitted for simplicity)
    // You could add options like timestamp resolution, etc.
};
