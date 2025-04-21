#include "protocols.h"

#include "util.h"

#include <network/l4_transport/icmp_header.h>

using packet::Field;

void dissect::dissectIcmp(Context &ctx, const char *data, size_t length, bool v6) {
    auto &pack = ctx.pack;
    network::ICMPHeader icmp;
    if (!readStruct(data, length, 0, icmp)) {
        ctx.markMalformed("ICMP message too short");
        return;
    }
    pack.l4_header = icmp;
    pack.protocol = v6 ? "ICMPv6" : "ICMP";

    std::ostringstream oss;
    switch (icmp.type) {
        case 8: // Echo Request (Ping)
            oss << "ICMP Echo Request, Identifier=" << ntohs(icmp.identifier) << ", Sequence=" << ntohs(icmp.sequence);
            break;
        case 0: // Echo Reply
            oss << "ICMP Echo Reply, Identifier=" << ntohs(icmp.identifier) << ", Sequence=" << ntohs(icmp.sequence);
            break;
        case 3: // Destination Unreachable
            oss << "ICMP Destination Unreachable, Code=" << (int) icmp.code;
            break;
        case 11: // Time Exceeded
            oss << "ICMP Time Exceeded, Code=" << (int) icmp.code;
            break;
        default:
            oss << "ICMP Type=" << (int) icmp.type << ", Code=" << (int) icmp.code;
            break;
    }
    pack.info = oss.str();

    const size_t o = ctx.offsetOf(data);
    Field &l = ctx.addLayer(v6 ? "Internet Control Message Protocol v6" : "Internet Control Message Protocol", o, length);
    l.add("Type: " + std::to_string(icmp.type), o, 1);
    l.add("Code: " + std::to_string(icmp.code), o + 1, 1);
    l.add("Checksum: " + hexString(ntohs(icmp.checksum), 4), o + 2, 2);
    l.add("Identifier: " + std::to_string(ntohs(icmp.identifier)), o + 4, 2);
    l.add("Sequence Number: " + std::to_string(ntohs(icmp.sequence)), o + 6, 2);
    if (length > sizeof(icmp)) {
        l.add("Data (" + std::to_string(length - sizeof(icmp)) + " bytes)", o + sizeof(icmp), length - sizeof(icmp));
    }
}
