#pragma once

#include <cstdint>
#include <pcapng/block_header.h>
#include <vector>

struct InterfaceStatisticsBlock : public BlockHeader {
    uint32_t interfaceID;        // Interface ID
    uint32_t timestampHigh;      // High 32 bits of the timestamp
    uint32_t timestampLow;       // Low 32 bits of the timestamp
    std::vector<char> options;   // Optional fields (like captured packet count, dropped packet count)
    uint32_t blockTotalLengthRedundant;   // Total length of the block (again)

    // Constructor that initializes InterfaceStatisticsBlock with BlockHeader fields
    InterfaceStatisticsBlock(const BlockHeader& header) {
        blockType = header.blockType;
        blockTotalLength = header.blockTotalLength;
    }

    // Function to deserialize Interface Statistics Block specific fields
    void deserializeStatisticsFields(std::ifstream& stream) {
        stream.read(reinterpret_cast<char*>(&interfaceID), sizeof(interfaceID));
        stream.read(reinterpret_cast<char*>(&timestampHigh), sizeof(timestampHigh));
        stream.read(reinterpret_cast<char*>(&timestampLow), sizeof(timestampLow));

        // Calculate the remaining bytes for options
        size_t optionsLength = blockTotalLength - (sizeof(uint32_t) * 3 + sizeof(uint32_t) * 2 + sizeof(uint32_t)); // Exclude block header
        options.resize(optionsLength);
        stream.read(options.data(), optionsLength);

        // Read redundant block total length
        stream.read(reinterpret_cast<char*>(&blockTotalLengthRedundant), sizeof(blockTotalLengthRedundant));

    }


};
