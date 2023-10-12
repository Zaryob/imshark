#pragma once

#include <string>

#include <packet/packet_info.h>
#include <packet/packet_parser.h>
#include <pcapng/enhanced_packet_block.h>
#include <pcapng/interface_statistics_block.h>
#include <pcapng/name_resolution_block.h>
#include <pcapng/section_header_block.h>
#include <pcapng/simple_packet_block.h>
#include <pcapng/interface_description_block.h>

namespace core {
    class FileProcessor {
        packet::PacketParser parser;
    public:
        void processPcapFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets);


        void processSectionHeaderBlock(std::ifstream &file, pcapng::SectionHeaderBlock section);

        void processEnhancedPacketBlock(pcapng::EnhancedPacketBlock &section, packet::PacketInfo &pack, uint32_t &tsTimeOffset,
                                        uint32_t &usTimeOffset);


        void processInterfaceDescriptionBlock(std::ifstream &file, pcapng::InterfaceDescriptionBlock &idb);

        void processSimplePacketBlock(pcapng::SimplePacketBlock spb, packet::PacketInfo &pack, uint32_t &tsTimeOffset,
                                      uint32_t &usTimeOffset);

        // Function to print the statistics data
        void printStatistics(pcapng::InterfaceStatisticsBlock isb);

        // Function to print the name resolution records
        void printNameResolutionRecords(pcapng::NameResolutionBlock nrb);

        void processPcapngFile(const std::string &filepath, std::vector<packet::PacketInfo> &packets);
    };
} // namespace core

