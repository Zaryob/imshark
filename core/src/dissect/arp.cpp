#include "protocols.h"

#include "util.h"

#include <network/l3_network/arp_header.h>
#include <network/utils.h>

using packet::Field;

void dissect::dissectArp(Context &ctx, const char *data, size_t length, bool reverse) {
    auto &pack = ctx.pack;
    const char *name = reverse ? "RARP" : "ARP";
    network::ARPHeader arp;
    if (!readStruct(data, length, 0, arp)) {
        ctx.markMalformed("ARP packet truncated");
        pack.protocol = name;
        return;
    }
    pack.protocol = name;
    pack.length = sizeof(network::ARPHeader);
    pack.destination = network::getMACAddressString(arp.target_hw_addr);
    pack.source = network::getMACAddressString(arp.sender_hw_addr);
    if (reverse ? pack.destination == pack.source : pack.destination == "00:00:00:00:00:00") {
        pack.destination = "Broadcast";
    }

    std::ostringstream oss;
    oss << "ARP ";
    switch (network::ntoh16(arp.opcode)) {
        case 1:
            oss << "Request: Who has " << ip4(arp.target_protocol_addr) << "? Tell " << ip4(arp.sender_protocol_addr);
            break;
        case 2:
            oss << "Reply: " << ip4(arp.sender_protocol_addr) << " is at "
                << network::getMACAddressString(arp.sender_hw_addr);
            break;
        case 3:
            oss << "Announce: My IP is associated with MAC " << network::getMACAddressString(arp.sender_hw_addr);
            break;
        default:
            oss << "Unknown operation";
    }
    pack.info = oss.str();

    if (!ctx.wantFields()) return;
    const size_t o = ctx.offsetOf(data);
    const uint16_t opcode = network::ntoh16(arp.opcode);
    Field &l = ctx.addLayer(std::string("Address Resolution Protocol (") +
                                (opcode == 1 ? "request" : opcode == 2 ? "reply" : "other") + ")",
                            o, sizeof(network::ARPHeader));
    l.add("Hardware type: " + std::to_string(network::ntoh16(arp.hw_type)), o, 2);
    l.add("Protocol type: " + hexString(network::ntoh16(arp.protocol_type), 4), o + 2, 2);
    l.add("Hardware size: " + std::to_string(arp.hw_addr_len), o + 4, 1);
    l.add("Protocol size: " + std::to_string(arp.protocol_addr_len), o + 5, 1);
    l.add("Opcode: " + std::to_string(opcode), o + 6, 2);
    l.add("Sender MAC address: " + network::getMACAddressString(arp.sender_hw_addr), o + 8, 6);
    l.add("Sender IP address: " + ip4(arp.sender_protocol_addr), o + 14, 4);
    l.add("Target MAC address: " + network::getMACAddressString(arp.target_hw_addr), o + 18, 6);
    l.add("Target IP address: " + ip4(arp.target_protocol_addr), o + 24, 4);
}
