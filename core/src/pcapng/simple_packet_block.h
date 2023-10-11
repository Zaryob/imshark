#pragma once

#include <pcapng/block_header.h>

#include <cstdint>
#include <vector>

namespace pcapng {
    struct SimplePacketBlock : public BlockHeader {
        uint32_t original_packet_length;  // The length of the packet before any truncation
        std::vector<char> packet_data;    // The actual packet data
        uint32_t block_total_length_redundant;  // The redundant block total length field

        // Constructor that initializes SimplePacketBlock with BlockHeader fields
        SimplePacketBlock(const BlockHeader& header)
        {
            block_type = header.block_type;
            block_total_length = header.block_total_length;
        }

        // Function to deserialize Simple Packet Block specific fields
        void deserializePacketFields(std::ifstream& stream) {
            // Read original packet length
            stream.read(reinterpret_cast<char*>(&original_packet_length), sizeof(original_packet_length));

            // Calculate the remaining packet data length
            size_t packet_data_length = block_total_length - (sizeof(uint32_t) * 3 + sizeof(uint32_t)); // Exclude block header and original_packet_length
            packet_data.resize(packet_data_length);
            stream.read(packet_data.data(), packet_data_length);

            // Read redundant block total length
            stream.read(reinterpret_cast<char*>(&block_total_length_redundant), sizeof(block_total_length_redundant));
        }
    };
} // namespace pcapng
