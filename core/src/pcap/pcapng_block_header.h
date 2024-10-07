#pragma once
#include <cstdint>

struct PcapNGBlockHeader {
    uint32_t blockType;
    uint32_t blockTotalLength;
};

