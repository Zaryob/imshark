#include "protocols.h"

#include "registry.h"
#include "util.h"

#include <network/l3_network/ip6_header.h>
#include <network/l3_network/ip_header.h>
#include <network/utils.h>

using packet::Field;

namespace {
    std::string ipProtocolName(uint8_t p) {
        switch (p) {
            case 1: return "ICMP 1";
            case 6: return "TCP 6";
            case 17: return "UDP 17";
            case 58: return "ICMPv6 58";
            default: return "protocol " + std::to_string(p);
        }
    }

    void zeroRanges(Field &f) {
        f.offset = 0;
        f.length = 0;
        for (auto &c: f.children) zeroRanges(c);
    }

    void ipv6Chain(dissect::Context &ctx, const char *data, size_t avail, uint8_t nextHeader, Field *layer, bool allowFragment);

    // A fragment of an IPv4 or IPv6 datagram: wait for the rest; once the datagram is complete, decode its payload.
    // `protocol` is the upper layer protocol this fragment announces (only the offset 0 fragment's value is used).
    void dissectFragment(dissect::Context &ctx, const char *payload, size_t avail, uint8_t protocol, bool moreFragments,
                         uint32_t fragOffset, bool v6) {
        using namespace dissect;
        auto &pack = ctx.pack;
        const bool replay = ctx.mode == ParseMode::Replay;
        const char *family = v6 ? "IPv6" : "IPv4";

        bool complete = false, overlap = false;
        std::vector<char> whole;
        std::vector<uint32_t> numbers;
        uint8_t wholeProtocol = protocol;
        if (replay) {
            if (pack.ip_frag == 2 && ctx.reassembledPayload) {
                complete = true;
                whole = *ctx.reassembledPayload;
                wholeProtocol = ctx.reassembledProtocol;
                if (ctx.fragmentNumbers) numbers = *ctx.fragmentNumbers;
            }
        } else if (ctx.reassembler) {
            network::IpFragment f;
            f.offset = fragOffset;
            f.moreFragments = moreFragments;
            f.data.assign(payload, payload + avail);
            f.packetNumber = static_cast<uint32_t>(pack.number);
            f.protocol = protocol;
            f.time = pack.time;
            const std::string key = std::string(family) + ":" + pack.source + ">" + pack.destination + "#" + std::to_string(pack.ip_id) + "/" +
                                    (v6 ? "" : std::to_string(protocol));
            auto r = ctx.reassembler->add(key, f, /*strictOverlap=*/v6);   // RFC 5722: IPv6 drops datagrams with overlaps
            overlap = r.overlapDiscarded;
            if (r.complete) {
                complete = true;
                whole = std::move(r.payload);
                numbers = std::move(r.fragmentNumbers);
                wholeProtocol = r.protocol;
                if (ctx.completed) {
                    for (uint32_t n: numbers) if (n != static_cast<uint32_t>(pack.number)) ctx.completed->push_back({n, static_cast<uint32_t>(pack.number)});
                }
            }
        }

        if (ctx.wantFields() && !ctx.pack.fields.empty()) {
            ctx.pack.fields.back().add("[Fragment: offset " + std::to_string(fragOffset) + ", " + std::to_string(avail) + " bytes" +
                                       (moreFragments ? ", more fragments follow]" : ", last fragment]"));
        }

        if (!complete) {
            pack.ip_frag = 1;
            pack.protocol = family;
            pack.ip_protocol = protocol;
            pack.info = std::string("Fragmented ") + (v6 ? "IPv6" : "IP") + " protocol (proto=" + ipProtocolName(protocol) + ", off=" + std::to_string(fragOffset) +
                        ", ID=" + hexString(pack.ip_id, v6 ? 8 : 4) + ")" +
                        (overlap ? " [Overlapping fragments: datagram discarded (RFC 5722)]" : "") +
                        (pack.reassembled_in ? " [Reassembled in #" + std::to_string(pack.reassembled_in) + "]" : "");
            return;
        }

        // decode the reassembled payload as if it had arrived in one piece
        pack.ip_frag = 2;
        pack.length = static_cast<uint32_t>(whole.size());
        packet::PacketInfo nested = pack;
        nested.fields.clear();
        Context nctx{nested, whole.data(), whole.size(), ctx.tcp, ctx.registry, ctx.mode};
        nested.ip_protocol = wholeProtocol;
        if (v6) {
            ipv6Chain(nctx, whole.data(), whole.size(), wholeProtocol, nullptr, /*allowFragment=*/false);
        } else if (const Dissector *next = ctx.registry.findIpProtocol(wholeProtocol)) {
            (*next)(nctx, whole.data(), whole.size());
        } else {
            nested.protocol = "Other";
        }

        pack.protocol = nested.protocol;
        pack.info = nested.info;
        pack.ip_protocol = nested.ip_protocol;
        pack.src_port = nested.src_port;
        pack.dst_port = nested.dst_port;
        pack.tcp_flags = nested.tcp_flags;
        pack.tcp_relative_seq = nested.tcp_relative_seq;
        pack.tcp_relative_ack = nested.tcp_relative_ack;
        pack.tcp_analysis = nested.tcp_analysis;
        pack.tcp_dup_ack = nested.tcp_dup_ack;
        pack.length = nested.length;
        pack.tcp_len = nested.tcp_len;
        pack.payload_offset = pack.payload_length = 0; // the payload is not contiguous in this frame

        if (ctx.wantFields()) {
            std::string from;
            for (uint32_t n: numbers) from += (from.empty() ? "#" : ", #") + std::to_string(n);
            Field &layer = ctx.addLayer(std::string("[Reassembled ") + family + " payload (" + std::to_string(whole.size()) + " bytes) from frames " + from + "]", 0, 0);
            layer.children = std::move(nested.fields);
            for (auto &c: layer.children) zeroRanges(c); // offsets inside the reassembled data do not map to bytes of this frame
        }
    }

    // Walks the IPv6 extension headers (hop-by-hop, routing, destination options, AH and - at the top level - the
    // fragment header) starting at `data`, then hands the upper layer to its dissector.
    void ipv6Chain(dissect::Context &ctx, const char *data, size_t avail, uint8_t nextHeader, Field *layer, bool allowFragment) {
        using namespace dissect;
        auto &pack = ctx.pack;
        size_t pos = 0;
        while (nextHeader == 0 || nextHeader == 43 || nextHeader == 44 || nextHeader == 51 || nextHeader == 60) {
            if (avail - pos < 8) { ctx.markMalformed("IPv6 extension header truncated"); return; }
            const uint8_t following = static_cast<uint8_t>(data[pos]);
            const size_t extLen = nextHeader == 44 ? 8
                                  : nextHeader == 51 ? (static_cast<size_t>(static_cast<uint8_t>(data[pos + 1])) + 2) * 4
                                  : (static_cast<size_t>(static_cast<uint8_t>(data[pos + 1])) + 1) * 8;
            if (extLen > avail - pos) { ctx.markMalformed("IPv6 extension header truncated"); return; }
            const size_t o = ctx.offsetOf(data + pos);

            if (nextHeader == 44) { // Fragment Header (RFC 8200 4.5)
                const uint16_t field = be16(data + pos + 2);
                const uint32_t fragOffset = static_cast<uint32_t>(field >> 3) * 8;
                const bool more = field & 1;
                const uint32_t id = be32(data + pos + 4);
                if (layer) {
                    Field &f = layer->add("Fragment Header (" + std::string(more || fragOffset ? "fragment" : "atomic fragment") + ", ID " + hexString(id, 8) + ")", o, 8);
                    f.add("Next Header: " + ipProtocolName(following), o, 1);
                    f.add("Offset: " + std::to_string(fragOffset), o + 2, 2);
                    f.add(std::string("More Fragments: ") + (more ? "Yes" : "No"), o + 3, 1);
                    f.add("Identification: " + hexString(id, 8), o + 4, 4);
                }
                if (!allowFragment) { ctx.markMalformed("IPv6 fragment header inside reassembled data"); return; }
                if (fragOffset != 0 || more) { // a real fragment (an "atomic fragment" with offset 0 and M = 0 is a whole packet)
                    pack.ip_id = id;
                    pack.length = pack.length >= extLen ? pack.length - static_cast<uint32_t>(extLen) : 0;
                    dissectFragment(ctx, data + pos + 8, avail - pos - 8, following, more, fragOffset, /*v6=*/true);
                    return;
                }
            } else if (layer) {
                layer->add("Extension Header (type " + std::to_string(nextHeader) + ", " + std::to_string(extLen) + " bytes)", o, extLen);
            }
            pack.length = pack.length >= extLen ? pack.length - static_cast<uint32_t>(extLen) : 0; // the payload excludes extension headers
            pos += extLen;
            nextHeader = following;
        }

        pack.ip_protocol = nextHeader;
        if (const Dissector *d = ctx.registry.findIpProtocol(nextHeader)) {
            (*d)(ctx, data + pos, avail - pos);
        } else {
            pack.protocol = "Other";
        }
    }
} // namespace

void dissect::dissectIPv4(Context &ctx, const char *base, size_t len) {
    auto &pack = ctx.pack;
    network::IPHeader ipHeader;
    if (!readStruct(base, len, 0, ipHeader)) {
        ctx.markMalformed("IPv4 header truncated");
        pack.protocol = "IPv4";
        return;
    }
    pack.destination = ip4(ipHeader.dst_addr);
    pack.source = ip4(ipHeader.src_addr);
    pack.ip_version = 4;
    pack.ttl = ipHeader.ttl;

    const size_t ipHeaderLen = static_cast<size_t>(ipHeader.ihl) * 4;
    if (ipHeaderLen < sizeof(network::IPHeader) || ipHeaderLen > len) {
        ctx.markMalformed("invalid IPv4 header length");
        pack.protocol = "IPv4";
        return;
    }

    const size_t o = ctx.offsetOf(base);
    const size_t totalLen = network::ntoh16(ipHeader.tot_length);
    if (ctx.wantFields()) {
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
    pack.ip_protocol = ipHeader.protocol;
    pack.ip_id = network::ntoh16(ipHeader.id);
    const uint16_t fragField = network::ntoh16(ipHeader.flags_frag_off);
    if ((fragField & 0x2000) || (fragField & 0x1FFF) != 0) { // More Fragments flag set, or not the first piece
        dissectFragment(ctx, base + ipHeaderLen, avail, ipHeader.protocol, (fragField & 0x2000) != 0, (fragField & 0x1FFF) * 8u, /*v6=*/false);
        return;
    }
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

    pack.source = network::getIPv6AddressString(ipv6Header.src_addr);
    pack.destination = network::getIPv6AddressString(ipv6Header.dst_addr);
    pack.protocol = "IPv6";
    pack.ip_version = 6;
    pack.ttl = ipv6Header.hop_limit;

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
    Field *l = nullptr; // the IPv6 layer of the field tree (null in summary mode)
    if (ctx.wantFields()) {
        l = &ctx.addLayer("Internet Protocol Version 6, Src: " + pack.source + ", Dst: " + pack.destination, o,
                          sizeof(network::IPv6Header));
        l->add("Version: " + std::to_string(ipv6Header.version()), o, 1);
        l->add("Traffic Class: " + hexString(ipv6Header.trafficClass(), 2), o, 2);
        l->add("Flow Label: " + hexString(ipv6Header.flowLabel(), 5), o + 1, 3);
        l->add("Payload Length: " + std::to_string(network::ntoh16(ipv6Header.payload_len)), o + 4, 2);
        l->add("Next Header: " + std::to_string(ipv6Header.next_header), o + 6, 1);
        l->add("Hop Limit: " + std::to_string(ipv6Header.hop_limit), o + 7, 1);
        l->add("Source Address: " + pack.source, o + 8, 16);
        l->add("Destination Address: " + pack.destination, o + 24, 16);
    }

    ipv6Chain(ctx, base + next, avail, nextHeader, l, /*allowFragment=*/true);
}
