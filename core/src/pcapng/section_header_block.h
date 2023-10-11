#pragma once

#include <pcapng/block_header.h>

#include <cstdint>
#include <vector>

namespace pcapng {
    // Derived SectionHeaderBlock struct inheriting from BlockHeader
    struct SectionHeaderBlock : public BlockHeader {
        uint32_t magic_number;        // Magic number (0x1A2B3C4D)
        uint16_t version_major;       // Major version number
        uint16_t version_minor;       // Minor version number
        int64_t section_length;       // Length of the section (can be -1 for unknown)
        std::vector<char> options;    // Options
        uint32_t block_total_length_redundant;   // Total length of the block (again)

        SectionHeaderBlock() = default;

        // Constructor that initializes the SectionHeaderBlock with BlockHeader fields
        SectionHeaderBlock(const BlockHeader& header) {
            // Copy the common BlockHeader fields
            block_type = header.block_type;
            block_total_length = header.block_total_length;
        }

        // Function to deserialize SectionHeaderBlock-specific fields
        void deserializeSectionFields(std::ifstream& stream) {
            stream.read(reinterpret_cast<char*>(&magic_number), sizeof(magic_number));
            stream.read(reinterpret_cast<char*>(&version_major), sizeof(version_major));
            stream.read(reinterpret_cast<char*>(&version_minor), sizeof(version_minor));
            stream.read(reinterpret_cast<char*>(&section_length), sizeof(section_length));

            // Calculate the remaining bytes for options (excluding the redundant block total length)
            size_t options_length = block_total_length - (sizeof(uint32_t) * 3 + sizeof(uint16_t) * 2 + sizeof(int64_t) + sizeof(uint32_t));
            options.resize(options_length);
            stream.read(options.data(), options_length);

            // Read the redundant block total length
            stream.read(reinterpret_cast<char*>(&block_total_length_redundant), sizeof(block_total_length_redundant));
        }
    };
} // namespace pcapng
