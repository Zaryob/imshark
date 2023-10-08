#pragma once

#include <cstdint>
#include <pcapng/block_header.h>

struct EnhancedPacketBlock : public BlockHeader {
    uint32_t interfaceID;        // Interface ID of the packet
    uint32_t timestampUpper;     // High 32 bits of the timestamp
    uint32_t timestampLower;     // Low 32 bits of the timestamp
    uint32_t capturedLength;     // Length of the captured portion of the packet
    uint32_t originalLength;     // Length of the original packet
    std::vector<char> packetData; // Packet data
    uint32_t blockTotalLengthRedundant;

    EnhancedPacketBlock() = default;
    // Constructor that initializes EnhancedPacketBlock with BlockHeader fields
    EnhancedPacketBlock(const BlockHeader& header)
    {
        blockType = header.blockType;
        blockTotalLength = header.blockTotalLength;
    }

    // Function to deserialize EnhancedPacketBlock specific fields
    void deserializeEnhancedFields(std::ifstream& stream) {
        stream.read(reinterpret_cast<char*>(&interfaceID), sizeof(interfaceID));
        stream.read(reinterpret_cast<char*>(&timestampUpper), sizeof(timestampUpper));
        stream.read(reinterpret_cast<char*>(&timestampLower), sizeof(timestampLower));
        stream.read(reinterpret_cast<char*>(&capturedLength), sizeof(capturedLength));
        stream.read(reinterpret_cast<char*>(&originalLength), sizeof(originalLength));

        // Calculate the remaining bytes for packetData
        size_t dataLength = blockTotalLength - (sizeof(uint32_t) * 7 + sizeof(uint32_t)); // 7 uint32_t fields
        packetData.resize(dataLength);
        stream.read(packetData.data(), dataLength);

        // Read redundant block total length
        stream.read(reinterpret_cast<char*>(&blockTotalLengthRedundant), sizeof(blockTotalLengthRedundant));

    }
};
