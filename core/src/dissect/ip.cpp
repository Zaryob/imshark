#include "protocols.h"

#include "registry.h"
#include "util.h"

#include <network/l3_network/ip6_header.h>
#include <network/l3_network/ip_header.h>
#include <network/utils.h>

using packet::Field;

void dissect::dissectIPv4(Context &ctx, const char *base, size_t len) {
    auto &pack = ctx.pack;
    network::IPHeader ipHeader;
    if (!readStruct(base, len, 0, ipHeader)) {
        ctx.markMalformed("IPv4 header truncated");
        pack.protocol = "IPv4";
        return;
    }
    pack.l3_header = ipHeader;
    pack.destination = ip4(ipHeader.dst_addr);
    pack.source = ip4(ipHeader.src_addr);

    const size_t ipHeaderLen = static_cast<size_t>(ipHeader.ihl) * 4;
    if (ipHeaderLen < sizeof(network::IPHeader) || ipHeaderLen > len) {
        ctx.markMalformed("invalid IPv4 header length");
        pack.protocol = "IPv4";
        return;
    }

    const size_t o = ctx.offsetOf(base);
    const size_t totalLen = network::ntoh16(ipHeader.tot_length);
    {
        Field &l = ctx.addLayer("Internet Protocol Version 4, Src: " + pack.source + ", Dst: " + pack.destination, o, ipHeaderLen);
        l.add("Version: " + std::to_string(ipHeader.version), o, 1);
        l.add("Header Length: " + std::to_string(ipHeaderLen) + " bytes (" + std::to_string(ipHeader.ihl) + ")", o, 1);
        l.add("Differentiated Services: " + hexString(ipHeader.tos, 2), o + 1, 1);
        l.add("Total Length: " + std::to_string(totalLen), o + 2, 2);
        l.add("Identification: " + hexString(network::ntoh16(ipHeader.id), 4) + " (" + std::to_string(network::ntoh16(ipHeader.id)) + ")", o + 4, 2);
        Field &flags = l.add("Flags: " + hexString(ipHeader.flags(), 1) + ((ipHeader.flags() & 2) ? ", Don't fragment" : "") +
                                 ((ipHeader.flags() & 1) ? ", More fragments" : ""), o + 6, 1);
        flags.add(std::string("Don't fragment: ") + ((ipHeader.flags() & 2) ? "Set" : "Not set"), o + 6, 1);
        flags.add(std::string("More fragments: ") + ((ipHeader.flags() & 1) ? "Set" : "Not set"), o + 6, 1);
        l.add("Fragment Offset: " + std::to_string(ipHeader.fragmentOffset() * 8), o + 6, 2);
        l.add("Time to Live: " + std::to_string(ipHeader.ttl), o + 8, 1);
        l.add("Protocol: " + std::to_string(ipHeader.protocol), o + 9, 1);
        l.add("Header Checksum: " + hexString(network::ntoh16(ipHeader.check), 4), o + 10, 2);
        l.add("Source Address: " + pack.source, o + 12, 4);
        l.add("Destination Address: " + pack.destination, o + 16, 4);
        if (ipHeaderLen > sizeof(network::IPHeader)) l.add("Options", o + 20, ipHeaderLen - sizeof(network::IPHeader));
    }

    pack.length = totalLen >= ipHeaderLen ? totalLen - ipHeaderLen : 0;
    const size_t avail = std::min<size_t>(pack.length, len - ipHeaderLen); // drops Ethernet padding
    if (const Dissector *next = ctx.registry.findIpProtocol(ipHeader.protocol)) {
        (*next)(ctx, base + ipHeaderLen, avail);
    } else {
        pack.protocol = "Other";
    }
}

void dissect::dissectIPv6(Context &ctx, const char *base, size_t len) {
    auto &pack = ctx.pack;
    network::IPv6Header ipv6Header;
    if (!readStruct(base, len, 0, ipv6Header)) {
        ctx.markMalformed("IPv6 header truncated");
        pack.protocol = "IPv6";
        return;
    }
    pack.l3_header = ipv6Header;

    pack.source = network::getIPv6AddressString(ipv6Header.src_addr);
    pack.destination = network::getIPv6AddressString(ipv6Header.dst_addr);
    pack.protocol = "IPv6";

    std::ostringstream infoStream;
    infoStream << "IPv6 Version: " << (int) ipv6Header.version()
               << ", Traffic Class: " << (int) ipv6Header.trafficClass()
               << ", Flow Label: " << ipv6Header.flowLabel()
               << ", Hop Limit: " << (int) ipv6Header.hop_limit;
    pack.info = infoStream.str();

    pack.length = network::ntoh16(ipv6Header.payload_len); // payload only, no need to subtract the header size
    size_t next = sizeof(network::IPv6Header);   // offset of the next header, relative to `base`
    size_t avail = std::min<size_t>(pack.length, len - next);
    uint8_t nextHeader = ipv6Header.next_header;

    const size_t o = ctx.offsetOf(base);
    Field &l = ctx.addLayer("Internet Protocol Version 6, Src: " + pack.source + ", Dst: " + pack.destination, o,
                            sizeof(network::IPv6Header));
    l.add("Version: " + std::to_string(ipv6Header.version()), o, 1);
    l.add("Traffic Class: " + hexString(ipv6Header.trafficClass(), 2), o, 2);
    l.add("Flow Label: " + hexString(ipv6Header.flowLabel(), 5), o + 1, 3);
    l.add("Payload Length: " + std::to_string(network::ntoh16(ipv6Header.payload_len)), o + 4, 2);
    l.add("Next Header: " + std::to_string(ipv6Header.next_header), o + 6, 1);
    l.add("Hop Limit: " + std::to_string(ipv6Header.hop_limit), o + 7, 1);
    l.add("Source Address: " + pack.source, o + 8, 16);
    l.add("Destination Address: " + pack.destination, o + 24, 16);

    // Skip extension headers (hop-by-hop, routing, fragment, destination options, AH)
    while (nextHeader == 0 || nextHeader == 43 || nextHeader == 44 || nextHeader == 51 || nextHeader == 60) {
        if (avail < 8) { ctx.markMalformed("IPv6 extension header truncated"); return; }
        const uint8_t following = static_cast<uint8_t>(base[next]);
        const size_t extLen = nextHeader == 44 ? 8
                              : nextHeader == 51 ? (static_cast<size_t>(static_cast<uint8_t>(base[next + 1])) + 2) * 4
                              : (static_cast<size_t>(static_cast<uint8_t>(base[next + 1])) + 1) * 8;
        if (extLen > avail) { ctx.markMalformed("IPv6 extension header truncated"); return; }
        l.add("Extension Header (type " + std::to_string(nextHeader) + ", " + std::to_string(extLen) + " bytes)",
              o + next, extLen);
        next += extLen;
        avail -= extLen;
        nextHeader = following;
    }

    if (const Dissector *d = ctx.registry.findIpProtocol(nextHeader)) {
        (*d)(ctx, base + next, avail);
    } else {
        pack.protocol = "Other";
    }
}
