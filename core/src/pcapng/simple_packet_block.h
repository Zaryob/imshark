#pragma once

#include <pcapng/block_header.h>

#include <cstdint>

struct SimplePacketBlock : public BlockHeader {
    uint32_t originalPacketLength;  // The length of the packet before any truncation
    std::vector<char> packetData;   // The actual packet data
    uint32_t blockTotalLengthRedundant;  // The redundant block total length field

    // Constructor that initializes SimplePacketBlock with BlockHeader fields
    SimplePacketBlock(const BlockHeader& header)
    {
        blockType = header.blockType;
        blockTotalLength = header.blockTotalLength;
    }

    // Function to deserialize Simple Packet Block specific fields
    void deserializePacketFields(std::ifstream& stream) {
        // Read original packet length
        stream.read(reinterpret_cast<char*>(&originalPacketLength), sizeof(originalPacketLength));

        // Calculate the remaining packet data length
        size_t packetDataLength = blockTotalLength - (sizeof(uint32_t) * 3 + sizeof(uint32_t)); // Exclude block header and originalPacketLength
        packetData.resize(packetDataLength);
        stream.read(packetData.data(), packetDataLength);

        // Read redundant block total length
        stream.read(reinterpret_cast<char*>(&blockTotalLengthRedundant), sizeof(blockTotalLengthRedundant));
    }
};
