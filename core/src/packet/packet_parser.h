//
// Created by Süleyman Poyraz on 12.10.2024.
//

#pragma once

#include <packet/packet_info.h>

// Layer 2: Data link header
#include <network/l2_data_link/ethernet_header.h>

// Layer 3: Network header
#include <network/l3_network/arp_header.h>
#include <network/l3_network/ip6_header.h>
#include <network/l3_network/ip_header.h>

// Layer 4: Transport header
#include <network/l4_transport/tcp_header.h>
#include <network/l4_transport/udp_header.h>
#include <network/l4_transport/icmp_header.h>

// Layer 7: Application headers
#include <network/l7_application/dhcp_header.h>
#include <network/l7_application/dns_header.h>

#include <network/tcp_connection.h>

namespace packet {
    class PacketParser {
        PacketInfo pack;
    public:
        void parsePacket(packet::PacketInfo& pack, std::vector<char>& packetData);
        network::TCPConnection connection;
    protected:
        void parseDNSQuestion(const char* data, size_t& offset, size_t length, std::ostringstream& oss);
        void parseDNSAnswer(const char* data, size_t& offset, size_t length, std::ostringstream& oss);
        void parseDNSPacket(const char* data, size_t length);
        void parseICMP(const char* data);
        void parseARP(network::ARPHeader arp_header);
        void parseDHCP(const network::DHCPHeader* dhcpHeader);
        void parseSNMP(const char* data, size_t length);
        void parseTelnet(const char* data, size_t length);
        void parseBGP(const char* data, size_t length);
        void parseSMTP(const char* data, size_t length);
        void parseProtocolPacket( char* pack_data, uint8_t protocol);
    private:
        // Function to parse and print TCP flags
        std::string getTCPFlags(const network::TCPHeader& tcpHeader) {
            std::string flags;
            if (tcpHeader.flags & network::TCPFlags::FIN) flags += "FIN";
            if (tcpHeader.flags & network::TCPFlags::SYN) flags = flags + (flags.empty() ? "" : ", ") + "SYN";
            if (tcpHeader.flags & network::TCPFlags::RST) flags = flags + (flags.empty() ? "" : ", ") +  "RST";
            if (tcpHeader.flags & network::TCPFlags::PSH) flags = flags + (flags.empty() ? "" : ", ") +  "PSH";
            if (tcpHeader.flags & network::TCPFlags::ACK) flags = flags + (flags.empty() ? "" : ", ") +  "ACK";
            if (tcpHeader.flags & network::TCPFlags::URG) flags = flags + (flags.empty() ? "" : ", ") +  "URG";
            return flags;
        }



    };
} // namespace packet
