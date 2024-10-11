#pragma once

#include <cstdint>
#include <pcapng/block_header.h>

namespace pcapng {
    struct InterfaceDescriptionBlock : public BlockHeader {
        uint32_t link_type;            // The link type (e.g., Ethernet)
        uint16_t reserved;             // Reserved field, typically set to 0
        uint16_t snap_len;             // Maximum length of captured packets
        std::vector<char> options;     // Options field for extended info
        uint32_t block_total_length_redundant;   // Total length of the block (again)

        InterfaceDescriptionBlock() = default;

        // Constructor that initializes interface_description_block with block_header fields
        InterfaceDescriptionBlock(const BlockHeader& header)
        {
            block_type = header.block_type;
            block_total_length = header.block_total_length;
        }

        // Function to deserialize InterfaceDescriptionBlock specific fields
        void deserializeInterfaceFields(std::ifstream& stream) {
            stream.read(reinterpret_cast<char*>(&link_type), sizeof(link_type));
            stream.read(reinterpret_cast<char*>(&reserved), sizeof(reserved));
            stream.read(reinterpret_cast<char*>(&snap_len), sizeof(snap_len));

            // Calculate the remaining bytes for options (excluding redundant block length)
            size_t options_length = block_total_length - (sizeof(uint32_t) * 3 + sizeof(uint16_t) * 2 + sizeof(uint32_t));
            options.resize(options_length);
            stream.read(options.data(), options_length);

            // Read redundant block total length
            stream.read(reinterpret_cast<char*>(&block_total_length_redundant), sizeof(block_total_length_redundant));
        }
    };
} // namespace pcapng
