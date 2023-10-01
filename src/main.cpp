#include <iostream>
#include <fstream>
#include <vector>
#include <cstdint>
#include <pcap/pcap_global_header.h>
#include <pcap/pcap_packet_header.h>


int main() {
    std::ifstream file("/home/suleymanpoyraz/Downloads/udp.pcap", std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening file" << std::endl;
        return 1;
    }

    // Read the global header
    PcapGlobalHeader gHeader;
    file.read(reinterpret_cast<char*>(&gHeader), sizeof(PcapGlobalHeader));

    // Check magic number for byte order compatibility
    if (gHeader.magic_number != 0xa1b2c3d4) {
        std::cerr << "Incompatible file format or byte order" << std::endl;
        return 1;
    }

    while (file.peek() != EOF) {
        // Read packet header
        PcapPacketHeader pHeader;
        file.read(reinterpret_cast<char*>(&pHeader), sizeof(PcapPacketHeader));

        // Read packet data
        std::vector<char> packetData(pHeader.incl_len);
        file.read(packetData.data(), pHeader.incl_len);

        // Process packet (for example, just print packet size)
        std::cout << "Read a packet of size " << pHeader.incl_len << " bytes" << std::endl;
    }

    file.close();
    return 0;
}
