#pragma once

#include <cstdint>
#include <pcapng/block_header.h>

struct InterfaceDescriptionBlock : public BlockHeader {
    uint32_t linkType;            // The link type (e.g., Ethernet)
    uint16_t reserved;            // Reserved field, typically set to 0
    uint16_t snapLen;             // Maximum length of captured packets
    std::vector<char> options;    // Options field for extended info
    uint32_t blockTotalLengthRedundant;   // Total length of the block (again)

    InterfaceDescriptionBlock() = default;

    // Constructor that initializes InterfaceDescriptionBlock with BlockHeader fields
    InterfaceDescriptionBlock(const BlockHeader& header)
    {
        blockType = header.blockType;
        blockTotalLength = header.blockTotalLength;
    }

    // Function to deserialize InterfaceDescriptionBlock specific fields
    void deserializeInterfaceFields(std::ifstream& stream) {
        stream.read(reinterpret_cast<char*>(&linkType), sizeof(linkType));
        stream.read(reinterpret_cast<char*>(&reserved), sizeof(reserved));
        stream.read(reinterpret_cast<char*>(&snapLen), sizeof(snapLen));

        // Calculate the remaining bytes for options (excluding redundant block length)
        size_t optionsLength = blockTotalLength - (sizeof(uint32_t) * 3 + sizeof(uint16_t) * 2 + sizeof(uint32_t));
        options.resize(optionsLength);
        stream.read(options.data(), optionsLength);

        // Read redundant block total length
        stream.read(reinterpret_cast<char*>(&blockTotalLengthRedundant), sizeof(blockTotalLengthRedundant));

    }
};
