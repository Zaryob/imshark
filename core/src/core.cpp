
#include <core.h>
#include <iostream>
#include <fstream>
#include <iomanip>

#include <pcap/global_header.h>
#include <pcap/packet_header.h>
#include <pcapng/enhanced_packet_block.h>

/// PCAP FILE PROCESSING

void core::FileProcessor::processPcapFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets) {
    std::ifstream file(filepath, std::ios::binary);
    pcap::GlobalHeader gHeader;
    file.read(reinterpret_cast<char *>(&gHeader), sizeof(pcap::GlobalHeader));

    if (gHeader.magic_number != 0xa1b2c3d4) {
        std::cerr << "Incompatible PCAP file format" << std::endl;
        return;
    }

    uint32_t tsTimeOffset = 0;
    uint32_t usTimeOffset = 0;
    int packetNumber = 0;

    while (file.peek() != EOF) {
        pcap::PacketHeader pHeader = {0};
        file.read(reinterpret_cast<char *>(&pHeader), sizeof(pcap::PacketHeader));

        std::vector<char> packetData(pHeader.incl_len);
        file.read(packetData.data(), pHeader.incl_len);

        packet::PacketInfo pack(++packetNumber);
        pack.time = (pHeader.ts_sec) + 10e-7 * (pHeader.ts_usec) - (tsTimeOffset + 10e-7 * (usTimeOffset));
        // Process the packet data using the shared packet processor
        pack.raw_data = packetData;
        parser.parsePacket(pack, packetData);

        packets.emplace_back(pack);
    }

    file.close();
}

/// PCAPNG FILE PROCESSING


void core::FileProcessor::processSectionHeaderBlock(std::ifstream &file, pcapng::SectionHeaderBlock section) {
    // std::cout << "Section Header Block:" << std::endl;
    // std::cout << "Magic Number: " << std::hex << section.magicNumber << std::dec << std::endl;
    // std::cout << "Version: " << section.versionMajor << "." << section.versionMinor << std::endl;
    // std::cout << "Section Length: " << section.sectionLength << std::endl;

    // Verify block length trailer to match header
    if (section.block_total_length != section.block_total_length_redundant) {
        std::cerr << "Mismatched block length at end of block. Expected: " << section.block_total_length << ", Got: " <<
                section.block_total_length_redundant << std::endl;
        file.close();
        return;
    }
}

void core::FileProcessor::processEnhancedPacketBlock(pcapng::EnhancedPacketBlock &section, packet::PacketInfo &pack, uint32_t &tsTimeOffset,
                                uint32_t &usTimeOffset) {
    // std::cout << "Process Packet Block" << std::endl;

    // Check for mismatched block length
    if (section.block_total_length != section.block_total_length_redundant) {
        std::cerr << "Mismatched block length at end of block" << std::endl;
        return;
    }

    double timestampResolution = 1.0 / 1000; // Default milliseconds
    uint64_t fullTimestamp = ((uint64_t) section.timestamp_upper << 32) | section.timestamp_lower;
    fullTimestamp *= timestampResolution;
    uint64_t seconds = fullTimestamp / 1'000'000;
    uint64_t milliseconds = fullTimestamp % 1'000'000;

    if (tsTimeOffset == 0) tsTimeOffset = seconds;
    if (usTimeOffset == 0) usTimeOffset = milliseconds;

    pack.time = (seconds + 10e-7 * (milliseconds)) - (tsTimeOffset + 10e-7 * (usTimeOffset));
    pack.raw_data = section.packet_data;
    // Process the packet data using the shared packet processor
    parser.parsePacket(pack, section.packet_data);
}

void core::FileProcessor::processInterfaceDescriptionBlock(std::ifstream &file, pcapng::InterfaceDescriptionBlock &idb) {
    // std::cout << "Interface Description Block: " << std::endl;
    // std::cout << "Block Type: " << std::hex << idb.blockType << std::dec << std::endl;
    // std::cout << "Block Total Length: " << idb.blockTotalLength << std::endl;
    // std::cout << "Link Type: " << idb.linkType << std::endl;
    // std::cout << "Snap Length: " << idb.snapLen << std::endl;
    // std::cout << "TL Red Length: " << idb.blockTotalLengthRedundant << std::endl;
    if (idb.block_total_length != idb.block_total_length_redundant) {
        std::cerr << "Mismatched block length at end of block. Expected: " << idb.block_total_length << ", Got: " << idb
                .block_total_length_redundant << std::endl;
        file.close();
        return;
    }
}


void core::FileProcessor::processSimplePacketBlock(pcapng::SimplePacketBlock spb, packet::PacketInfo &pack, uint32_t &tsTimeOffset,
                              uint32_t &usTimeOffset) {
    if (spb.block_total_length != spb.block_total_length_redundant) {
        std::cerr << "Mismatched block length at end of block. Expected: " << spb.block_total_length << ", Got: " << spb
                .block_total_length_redundant << std::endl;
        exit(0);
        return;
    }
}

// Function to print the statistics data
void core::FileProcessor::printStatistics(pcapng::InterfaceStatisticsBlock isb) {
    if (isb.block_total_length != isb.block_total_length_redundant) {
        std::cerr << "Mismatched block length at end of block. Expected: " << isb.block_total_length << ", Got: " << isb
                .block_total_length_redundant << std::endl;
        exit(0);
        return;
    }
    uint64_t fullTimestamp = ((uint64_t) isb.timestamp_high << 32) | isb.timestamp_low;
    // std::cout << "Interface ID: " << isb.interfaceID << std::endl;
    // std::cout << "Timestamp: " << fullTimestamp << " (high: " << isb.timestampHigh << ", low: " << isb.timestampLow << ")" << std::endl;
    // std::cout << "Options Size: " << isb.options.size() << " bytes" << std::endl;

    // Additional parsing of options could be done here (if required).
}

// Function to print the name resolution records
void core::FileProcessor::printNameResolutionRecords(pcapng::NameResolutionBlock nrb) {
    // std::cout << "Name Resolution Records:" << std::endl;
    for (const auto &record: nrb.records) {
        // std::cout << "Address: " << record.address << ", Resolved Name: " << record.resolvedName << std::endl;
    }
}

void core::FileProcessor::processPcapngFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filepath << std::endl;
        return;
    }

    uint64_t blockIdx = 0;
    uint32_t packetNumber = 0;
    uint32_t tsTimeOffset = 0;
    uint32_t usTimeOffset = 0;

    while (file.peek() != EOF) {
        pcapng::BlockHeader header;
        header.deserialize(file);
        // std::cout << "Block Type: "<<std::setfill('0') << std::setw(8) << std::hex << header.blockTotalLength << std::dec<< std::endl;
        // std::cout << "Block Length: "<< header.blockTotalLength << std::endl;
        switch (header.block_type) {
            case static_cast<uint32_t>(pcapng::BlockType::SHB): {
                pcapng::SectionHeaderBlock section(header);
                // Read SHB fields
                section.deserializeSectionFields(file);
                processSectionHeaderBlock(file, section);
            }
            break;
            case static_cast<uint32_t>(pcapng::BlockType::IDB): {
                pcapng::InterfaceDescriptionBlock idb(header);
                idb.deserializeInterfaceFields(file);
                processInterfaceDescriptionBlock(file, idb);
            }
            break;
            case static_cast<uint32_t>(pcapng::BlockType::SPB): {
                pcapng::SimplePacketBlock spb(header);

                spb.deserializePacketFields(file);

                packet::PacketInfo pack(++packetNumber);
                processSimplePacketBlock(spb, pack, tsTimeOffset, usTimeOffset);
                packets.emplace_back(pack);
            }
            break;
            case static_cast<uint32_t>(pcapng::BlockType::ISB): {
                pcapng::InterfaceStatisticsBlock isb(header);
                isb.deserializeStatisticsFields(file);

                // Process Interface Statistics Block
                printStatistics(isb);
            }
            break;
            case static_cast<uint32_t>(pcapng::BlockType::EPB): {
                pcapng::EnhancedPacketBlock pb(header);
                pb.deserializeEnhancedFields(file);
                packet::PacketInfo pack(++packetNumber);
                processEnhancedPacketBlock(pb, pack, tsTimeOffset, usTimeOffset);

                packets.emplace_back(pack);
            }
            break;
            case static_cast<uint32_t>(pcapng::BlockType::NRB): {
                pcapng::NameResolutionBlock nrb(header);
                nrb.deserializeNameResolutionFields(file);

                // Process Name Resolution Block
                printNameResolutionRecords(nrb);
            }
            break;
            // Add cases for other block types...
            default:
                // std::cout << "Unhandled block type:" << std::hex << header.blockType << std::dec <<std::endl;
                // Skip unknown block
                file.seekg(header.block_total_length - sizeof(pcapng::BlockHeader), std::ios::cur);
                break;
        }
    }

    // std::cout <<"File processed successfully"<<std::endl;
    file.close();
    return;
}
