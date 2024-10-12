#pragma once

#include <cstdint>
#include <fstream>

namespace pcapng {

    enum class BlockType : uint32_t {
        SHB = 0x0A0D0D0A,  // Section Header Block
        IDB = 0x00000001,  // Interface Description Block
        PB  = 0x00000002,  // Packet Block
        SPB = 0x00000003,  // Simple Packet Block
        NRB = 0x00000004,  // Name Resolution Block
        ISB = 0x00000005,  // Interface Statistics Block
        EPB = 0x00000006,  // Enhanced Packet Block
        DSB = 0x0000000A,  // Decryption Secrets Block
        CB1 = 0x00000BAD,  // Custom Block
        CB2 = 0x40000BAD   // Custom Block
    };

    struct BlockHeader {
        uint32_t block_type;
        uint32_t block_total_length;

        // Function to deserialize BlockHeader
        void deserialize(std::ifstream& stream) {
            stream.read(reinterpret_cast<char*>(&block_type), sizeof(block_type));
            stream.read(reinterpret_cast<char*>(&block_total_length), sizeof(block_total_length));
        }
    };
} // namespace pcapng