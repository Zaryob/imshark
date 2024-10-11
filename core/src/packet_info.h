//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

#include <string>
#include <vector>

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
    PacketInfo(int num) : number(num){}

    PacketInfo(int num, double t, const std::string& src, const std::string& dest,
               const std::string& proto, uint32_t len, const std::string& inf)
        : number(num), time(t), source(src), destination(dest), protocol(proto), length(len), info(inf) {}
};
