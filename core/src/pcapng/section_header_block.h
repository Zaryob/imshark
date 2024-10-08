#pragma once

#include <pcapng/block_header.h>

#include <cstdint>


// Derived SectionHeaderBlock struct inheriting from BlockHeader
struct SectionHeaderBlock : public BlockHeader {
    uint32_t magicNumber;        // Magic number (0x1A2B3C4D)
    uint16_t versionMajor;       // Major version number
    uint16_t versionMinor;       // Minor version number
    int64_t sectionLength;       // Length of the section (can be -1 for unknown)
    std::vector<char> options;   // Options
    uint32_t blockTotalLengthRedundant;   // Total length of the block (again)

    SectionHeaderBlock() = default;
    // Constructor that initializes the SectionHeaderBlock with BlockHeader fields
    SectionHeaderBlock(const BlockHeader& header)
    {
        // Copy the common BlockHeader fields
        blockType = header.blockType;
        blockTotalLength = header.blockTotalLength;
    }

    // Function to deserialize SectionHeaderBlock-specific fields
    void deserializeSectionFields(std::ifstream& stream) {
        stream.read(reinterpret_cast<char*>(&magicNumber), sizeof(magicNumber));
        stream.read(reinterpret_cast<char*>(&versionMajor), sizeof(versionMajor));
        stream.read(reinterpret_cast<char*>(&versionMinor), sizeof(versionMinor));
        stream.read(reinterpret_cast<char*>(&sectionLength), sizeof(sectionLength));

        // Calculate the remaining bytes for options (excluding the redundant block total length)
        size_t optionsLength = blockTotalLength - (sizeof(uint32_t) * 3 + sizeof(uint16_t) * 2 + sizeof(int64_t) + sizeof(uint32_t));
        options.resize(optionsLength);
        stream.read(options.data(), optionsLength);

        // Read the redundant block total length
        stream.read(reinterpret_cast<char*>(&blockTotalLengthRedundant), sizeof(blockTotalLengthRedundant));
    }
};

