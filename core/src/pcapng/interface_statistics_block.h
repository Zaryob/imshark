#pragma once

#include <cstdint>
#include <pcapng/block_header.h>
#include <vector>

namespace pcapng {
    struct InterfaceStatisticsBlock : public BlockHeader {
        uint32_t interface_id;        // Interface ID
        uint32_t timestamp_high;      // High 32 bits of the timestamp
        uint32_t timestamp_low;       // Low 32 bits of the timestamp
        std::vector<char> options;    // Optional fields (like captured packet count, dropped packet count)
        uint32_t block_total_length_redundant;   // Total length of the block (again)

        // Constructor that initializes InterfaceStatisticsBlock with BlockHeader fields
        InterfaceStatisticsBlock(const BlockHeader& header) {
            block_type = header.block_type;
            block_total_length = header.block_total_length;
        }

        // Function to deserialize Interface Statistics Block specific fields
        void deserializeStatisticsFields(std::ifstream& stream) {
            stream.read(reinterpret_cast<char*>(&interface_id), sizeof(interface_id));
            stream.read(reinterpret_cast<char*>(&timestamp_high), sizeof(timestamp_high));
            stream.read(reinterpret_cast<char*>(&timestamp_low), sizeof(timestamp_low));

            // Calculate the remaining bytes for options
            size_t options_length = block_total_length - (sizeof(uint32_t) * 3 + sizeof(uint32_t) * 2 + sizeof(uint32_t)); // Exclude block header
            options.resize(options_length);
            stream.read(options.data(), options_length);

            // Read redundant block total length
            stream.read(reinterpret_cast<char*>(&block_total_length_redundant), sizeof(block_total_length_redundant));
        }
    };
} // namespace pcapng
