#pragma once

#include <cstdint>
#include <pcapng/block_header.h>

namespace pcapng {
    struct EnhancedPacketBlock : public BlockHeader {
        uint32_t interface_id;        // Interface ID of the packet
        uint32_t timestamp_upper;     // High 32 bits of the timestamp
        uint32_t timestamp_lower;     // Low 32 bits of the timestamp
        uint32_t captured_length;     // Length of the captured portion of the packet
        uint32_t original_length;     // Length of the original packet
        std::vector<char> packet_data; // Packet data
        uint32_t block_total_length_redundant;

        EnhancedPacketBlock() = default;
        // Constructor that initializes EnhancedPacketBlock with BlockHeader fields
        EnhancedPacketBlock(const BlockHeader& header)
        {
            block_type = header.block_type;
            block_total_length = header.block_total_length;
        }

        // Function to deserialize EnhancedPacketBlock specific fields
        void deserializeEnhancedFields(std::ifstream& stream) {
            stream.read(reinterpret_cast<char*>(&interface_id), sizeof(interface_id));
            stream.read(reinterpret_cast<char*>(&timestamp_upper), sizeof(timestamp_upper));
            stream.read(reinterpret_cast<char*>(&timestamp_lower), sizeof(timestamp_lower));
            stream.read(reinterpret_cast<char*>(&captured_length), sizeof(captured_length));
            stream.read(reinterpret_cast<char*>(&original_length), sizeof(original_length));

            // Calculate the remaining bytes for packetData
            size_t dataLength = block_total_length - (sizeof(uint32_t) * 7 + sizeof(uint32_t)); // 7 uint32_t fields
            // std::cout<<dataLength<<std::endl;
            packet_data.resize(dataLength);
            stream.read(packet_data.data(), dataLength);

            // Read redundant block total length
            stream.read(reinterpret_cast<char*>(&block_total_length_redundant), sizeof(block_total_length_redundant));

        }
    };
} // namespace pcapng