//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

#include <string>
#include <vector>

#include <network/l2_data_link/ethernet_header.h>

#include <network/l3_network/arp_header.h>
#include <network/l3_network/ip6_header.h>
#include <network/l3_network/ip_header.h>

#include <network/l4_transport/tcp_header.h>
#include <network/l4_transport/udp_header.h>
#include <network/l4_transport/icmp_header.h>

#include <network/l7_application/dhcp_header.h>
#include <network/l7_application/dns_header.h>


namespace packet {
    struct PacketInfo {
        int number;
        double time;
        std::string source;
        std::string destination;
        std::string protocol;
        uint32_t length;
        std::string info;

        std::variant<network::EthernetHeader> l2_header;
        std::variant<network::ARPHeader,
                     network::IPv6Header,
                     network::IPHeader> l3_header;

        std::variant<network::ICMPHeader,
                     network::TCPHeader,
                     network::UDPHeader> l4_header;

        std::variant<network::DHCPHeader,
                     network::DNSHeader> l7_header;  // Extend with all possible types you might need

        std::vector<char> raw_data;

        PacketInfo() = default;
        PacketInfo(int num) : number(num){}

        PacketInfo(int num, double t, const std::string& src, const std::string& dest,
                   const std::string& proto, uint32_t len, const std::string& inf)
            : number(num), time(t), source(src), destination(dest), protocol(proto), length(len), info(inf) {}
    };
} // namespace core