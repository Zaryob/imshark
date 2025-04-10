//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

#include <string>
#include <variant>
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
    /// One node of the protocol tree shown in the packet details pane: a label plus the byte range
    /// of the frame (`raw_data`) it was decoded from. `length == 0` means "no bytes" (derived values).
    struct Field {
        std::string text;
        uint32_t offset = 0;
        uint32_t length = 0;
        std::vector<Field> children;

        Field &add(std::string label, size_t off = 0, size_t len = 0) {
            children.push_back(Field{std::move(label), static_cast<uint32_t>(off), static_cast<uint32_t>(len), {}});
            return children.back();
        }

        bool contains(size_t byte) const { return byte >= offset && byte < size_t(offset) + length; }
    };

    struct PacketInfo {
        int number;
        double time;
        std::string source;
        std::string destination;
        std::string protocol;
        uint32_t length;
        std::string info;

        // Capture link type (LINKTYPE_* from the pcap/pcapng file); 1 = Ethernet.
        uint32_t link_type = 1;
        // Number of link-layer bytes in front of the network header (0 for raw IP).
        uint16_t l2_size = 0;
        // 802.1Q/802.1ad VLAN IDs found in the Ethernet header, outermost first.
        std::vector<uint16_t> vlan_ids;

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

        /// Decoded protocol layers, outermost first (Frame, Ethernet, IP, TCP, ...). Offsets are absolute
        /// positions in `raw_data`.
        std::vector<Field> fields;

        PacketInfo() = default;
        PacketInfo(int num) : number(num){}

        PacketInfo(int num, double t, const std::string& src, const std::string& dest,
                   const std::string& proto, uint32_t len, const std::string& inf)
            : number(num), time(t), source(src), destination(dest), protocol(proto), length(len), info(inf) {}
    };
} // namespace core