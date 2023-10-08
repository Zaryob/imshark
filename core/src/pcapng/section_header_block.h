#pragma once

#include <cstdint>

struct SectionHeaderBlock {
    uint32_t blockType;          // Should be 0x0A0D0D0A for SHB
    uint32_t blockTotalLength;   // Total length of the block
    uint32_t magicNumber;        // Magic number (0x1A2B3C4D)
    uint16_t versionMajor;       // Major version number
    uint16_t versionMinor;       // Minor version number
    int64_t sectionLength;       // Length of the section (can be -1 for unknown)
};

