#pragma once
#include <cstdint>
#include <pcapng/block_header.h>
#include <string>
#include <vector>

namespace pcapng {
    struct NameResolutionRecord {
        uint16_t record_type;       // 0x0001 for IPv4, 0x0002 for IPv6
        uint16_t record_length;     // Length of the record, excluding the type and length fields
        std::string address;        // IP Address (in string form for simplicity)
        std::string resolved_name;  // Resolved name (e.g., domain name)
    };

    struct NameResolutionBlock : public BlockHeader {
        std::vector<NameResolutionRecord> records;  // Name resolution records
        uint32_t block_total_length_redundant;      // Redundant total length of the block

        // Constructor that initializes NameResolutionBlock with BlockHeader fields
        NameResolutionBlock(const BlockHeader& header) {
            block_type = header.block_type;
            block_total_length = header.block_total_length;
        }

        // Function to deserialize the NameResolutionBlock
        void deserializeNameResolutionFields(std::ifstream& stream) {
            while (true) {
                NameResolutionRecord record;
                stream.read(reinterpret_cast<char*>(&record.record_type), sizeof(record.record_type));
                stream.read(reinterpret_cast<char*>(&record.record_length), sizeof(record.record_length));

                if (record.record_type == 0x0000) {  // End of Record marker
                    break;
                }

                if (record.record_type == 0x0001) {  // IPv4 Address
                    char ipv4_addr[4];  // 4 bytes for IPv4
                    stream.read(ipv4_addr, 4);
                    record.address = std::to_string((uint8_t)ipv4_addr[0]) + "." +
                                     std::to_string((uint8_t)ipv4_addr[1]) + "." +
                                     std::to_string((uint8_t)ipv4_addr[2]) + "." +
                                     std::to_string((uint8_t)ipv4_addr[3]);
                } else if (record.record_type == 0x0002) {  // IPv6 Address
                    char ipv6_addr[16];  // 16 bytes for IPv6
                    stream.read(ipv6_addr, 16);
                    record.address = "[IPv6 Address]";  // This could be properly formatted IPv6, simplified here
                }

                // Read the resolved name (record length specifies the size)
                char* name_buffer = new char[record.record_length];
                stream.read(name_buffer, record.record_length);
                record.resolved_name = std::string(name_buffer, record.record_length);
                delete[] name_buffer;

                records.push_back(record);
            }

            // Read the redundant block total length at the end of the block
            stream.read(reinterpret_cast<char*>(&block_total_length_redundant), sizeof(block_total_length_redundant));
        }
    };
} // namespace pcapng
