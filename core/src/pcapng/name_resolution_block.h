#pragma once
#include <cstdint>
#include <pcapng/block_header.h>
#include <string>
#include <vector>

struct NameResolutionRecord {
    uint16_t recordType;       // 0x0001 for IPv4, 0x0002 for IPv6
    uint16_t recordLength;     // Length of the record, excluding the type and length fields
    std::string address;       // IP Address (in string form for simplicity)
    std::string resolvedName;  // Resolved name (e.g., domain name)
};

struct NameResolutionBlock : public BlockHeader {
    std::vector<NameResolutionRecord> records;  // Name resolution records
    uint32_t blockTotalLengthRedundant;         // Redundant total length of the block

    // Constructor that initializes NameResolutionBlock with BlockHeader fields
    NameResolutionBlock(const BlockHeader& header) {
        blockType = header.blockType;
        blockTotalLength = header.blockTotalLength;
    }

    // Function to deserialize the NameResolutionBlock
    void deserializeNameResolutionFields(std::ifstream& stream) {
        while (true) {
            NameResolutionRecord record;
            stream.read(reinterpret_cast<char*>(&record.recordType), sizeof(record.recordType));
            stream.read(reinterpret_cast<char*>(&record.recordLength), sizeof(record.recordLength));

            if (record.recordType == 0x0000) {  // End of Record marker
                break;
            }

            if (record.recordType == 0x0001) {  // IPv4 Address
                char ipv4Addr[4];  // 4 bytes for IPv4
                stream.read(ipv4Addr, 4);
                record.address = std::to_string((uint8_t)ipv4Addr[0]) + "." +
                                 std::to_string((uint8_t)ipv4Addr[1]) + "." +
                                 std::to_string((uint8_t)ipv4Addr[2]) + "." +
                                 std::to_string((uint8_t)ipv4Addr[3]);
            } else if (record.recordType == 0x0002) {  // IPv6 Address
                char ipv6Addr[16];  // 16 bytes for IPv6
                stream.read(ipv6Addr, 16);
                record.address = "[IPv6 Address]";  // This could be properly formatted IPv6, simplified here
            }

            // Read the resolved name (record length specifies the size)
            char* nameBuffer = new char[record.recordLength];
            stream.read(nameBuffer, record.recordLength);
            record.resolvedName = std::string(nameBuffer, record.recordLength);
            delete[] nameBuffer;

            records.push_back(record);
        }

        // Read the redundant block total length at the end of the block
        stream.read(reinterpret_cast<char*>(&blockTotalLengthRedundant), sizeof(blockTotalLengthRedundant));
    }


};
