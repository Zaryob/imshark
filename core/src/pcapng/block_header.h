#pragma once

#include <cstdint>

#define BT_SHB 0x0A0D0D0A  // Section Header Block
#define BT_IDB 0x00000001  // Interface Description Block
#define BT_PB  0x00000002  // Packet Block
#define BT_SPB 0x00000003  // Simple Packet Block
#define BT_NRB 0x00000004  // Name Resolution Block
#define BT_ISB 0x00000005  // Interface Statistics Block
#define BT_EPB 0x00000006  // Enhanced Packet Block
#define BT_DSB 0x0000000A  // Decryption Secrets Block
#define BT_CB1 0x00000BAD  // Custom Block
#define BT_CB2 0x40000BAD  // Custom Block

struct BlockHeader {
    uint32_t blockType;
    uint32_t blockTotalLength;

    // Function to deserialize BlockHeader
    void deserialize(std::ifstream& stream) {
        stream.read(reinterpret_cast<char*>(&blockType), sizeof(blockType));
        stream.read(reinterpret_cast<char*>(&blockTotalLength), sizeof(blockTotalLength));
    }
};

