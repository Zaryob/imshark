#include "gre.h"
#include "protocols.h"
#include "registry.h"
#include "util.h"

#include <string>

using packet::Field;

namespace {
    using dissect::be16;
    using dissect::be32;
    using dissect::hexString;

    // GRE protocol types (RFC 2784/2890, RFC 1701, Cisco ERSPAN).
    std::string greProtocolName(uint16_t type) {
        switch (type) {
            case 0x0800: return "IPv4";
            case 0x0806: return "ARP";
            case 0x6558: return "Transparent Ethernet Bridging";
            case 0x86DD: return "IPv6";
            case 0x880B: return "PPP";
            case 0x8847: return "MPLS unicast";
            case 0x88BE: return "ERSPAN Type II";
            case 0x22EB: return "ERSPAN Type III";
            default: return hexString(type, 4);
        }
    }

    // Cisco ERSPAN: a feature header follows the GRE header and precedes the mirrored Ethernet frame.
    // Type II (GRE protocol 0x88BE) has an 8-octet header; Type III (0x22EB) has a 12-octet header.
    void dissectErspan(dissect::Context &ctx, const char *data, size_t length, bool type3, size_t baseOffset) {
        const size_t hdr = type3 ? 12 : 8;
        if (length < hdr) {
            ctx.markMalformed("ERSPAN header truncated");
            if (ctx.pack.protocol.empty()) ctx.pack.protocol = type3 ? "ERSPAN Type III" : "ERSPAN Type II";
            return;
        }
        const uint8_t version = static_cast<uint8_t>(data[0]) >> 4;
        const uint16_t vlan = static_cast<uint16_t>((static_cast<uint8_t>(data[0]) & 0x0F) << 8) | static_cast<uint8_t>(data[1]);
        const uint16_t word1 = be16(data + 2);
        const uint16_t session = word1 & 0x03FF;

        if (ctx.wantFields()) {
            std::string name = type3 ? "ERSPAN Type III" : "ERSPAN Type II";
            Field &l = ctx.addLayer(name + ", Version: " + std::to_string(version) + ", VLAN: " + std::to_string(vlan) +
                                    ", Session ID: " + std::to_string(session), baseOffset, hdr);
            l.add("Version: " + std::to_string(version), baseOffset, 1);
            l.add("VLAN: " + std::to_string(vlan), baseOffset, 2);
            l.add("Session ID: " + std::to_string(session), baseOffset + 2, 2);
            if (type3) {
                const uint32_t timestamp = be32(data + 4);
                const uint16_t sgt = be16(data + 8);
                l.add("Timestamp: " + std::to_string(timestamp), baseOffset + 4, 4);
                l.add("Security Group Tag: " + std::to_string(sgt), baseOffset + 8, 2);
            }
        }

        if (ctx.pack.info.find("[Malformed Packet") == std::string::npos)
            ctx.pack.info = std::string("ERSPAN ") + (type3 ? "III" : "II") + " VLAN " + std::to_string(vlan) + " Session " + std::to_string(session);

        const char *inner = data + hdr;
        const size_t rem = length - hdr;
        if (rem >= 14) {
            const uint16_t innerType = be16(inner + 12);
            if (const dissect::Dissector *next = ctx.registry.findEtherType(innerType)) {
                (*next)(ctx, inner + 14, rem - 14);
                return;
            }
        }
        ctx.addLayer("Data (" + std::to_string(rem) + " bytes)", baseOffset + hdr, rem);
    }
} // namespace

namespace dissect {
    void dissectGre(Context &ctx, const char *data, size_t length) {
        ctx.pack.has_gre = 1;
        if (length < 4) {
            ctx.markMalformed("GRE header truncated");
            if (ctx.pack.protocol.empty()) ctx.pack.protocol = "GRE";
            return;
        }

        const size_t baseOffset = ctx.offsetOf(data);
        const uint16_t flags = be16(data);
        const uint16_t protocol = be16(data + 2);
        const bool hasChecksum = (flags & 0x8000) != 0; // C
        const bool hasRouting = (flags & 0x4000) != 0;  // R
        const bool hasKey = (flags & 0x2000) != 0;      // K
        const bool hasSequence = (flags & 0x1000) != 0; // S
        const uint8_t version = flags & 0x0007;

        ctx.pack.gre_flags = flags;
        ctx.pack.gre_proto = protocol;

        size_t offset = 4;
        uint16_t checksum = 0, routingOffset = 0;
        uint32_t key = 0, sequence = 0;

        if (hasChecksum || hasRouting) {
            if (offset + 4 > length) {
                ctx.markMalformed("GRE checksum/routing header truncated");
                if (ctx.pack.protocol.empty()) ctx.pack.protocol = "GRE";
                return;
            }
            checksum = be16(data + offset);
            routingOffset = be16(data + offset + 2);
            offset += 4;
        }
        if (hasKey) {
            if (offset + 4 > length) {
                ctx.markMalformed("GRE key header truncated");
                if (ctx.pack.protocol.empty()) ctx.pack.protocol = "GRE";
                return;
            }
            key = be32(data + offset);
            ctx.pack.gre_key = static_cast<uint16_t>(key & 0xFFFF);
            offset += 4;
        }
        if (hasSequence) {
            if (offset + 4 > length) {
                ctx.markMalformed("GRE sequence header truncated");
                if (ctx.pack.protocol.empty()) ctx.pack.protocol = "GRE";
                return;
            }
            sequence = be32(data + offset);
            ctx.pack.gre_seq = static_cast<uint16_t>(sequence & 0xFFFF);
            offset += 4;
        }

        if (ctx.wantFields()) {
            Field &l = ctx.addLayer("Generic Routing Encapsulation, Flags: " + hexString(flags, 4) +
                                    ", Protocol: " + greProtocolName(protocol), baseOffset, offset);
            l.add("Checksum present: " + std::string(hasChecksum ? "Yes" : "No"), baseOffset, 2);
            l.add("Routing present: " + std::string(hasRouting ? "Yes" : "No"), baseOffset, 2);
            l.add("Key present: " + std::string(hasKey ? "Yes" : "No"), baseOffset, 2);
            l.add("Sequence number present: " + std::string(hasSequence ? "Yes" : "No"), baseOffset, 2);
            l.add("Version: " + std::to_string(version), baseOffset, 2);
            l.add("Protocol Type: " + greProtocolName(protocol) + " (" + hexString(protocol, 4) + ")", baseOffset + 2, 2);
            if (hasChecksum || hasRouting) {
                l.add("Checksum: " + hexString(checksum, 4), baseOffset + 4, 2);
                l.add("Routing Offset: " + std::to_string(routingOffset), baseOffset + 6, 2);
            }
            if (hasKey) l.add("Key: " + hexString(key, 8), baseOffset + offset - (hasSequence ? 8 : 4), 4);
            if (hasSequence) l.add("Sequence Number: " + std::to_string(sequence), baseOffset + offset - 4, 4);
        }

        // Source Route entries (RFC 1701) — walk them so the payload offset is right.
        if (hasRouting) {
            size_t sre = offset;
            while (sre + 4 <= length) {
                const uint16_t family = be16(data + sre);
                const uint8_t sreLength = static_cast<uint8_t>(data[sre + 3]);
                sre += 4 + sreLength;
                if (family == 0 && sreLength == 0) break;
                if (sre > length) {
                    ctx.markMalformed("GRE source route entry truncated");
                    if (ctx.pack.protocol.empty()) ctx.pack.protocol = "GRE";
                    return;
                }
            }
            offset = sre <= length ? sre : length;
        }

        if (ctx.pack.info.find("[Malformed Packet") == std::string::npos)
            ctx.pack.info = "Encapsulated " + greProtocolName(protocol);

        const char *inner = data + offset;
        const size_t rem = length - offset;

        if (protocol == 0x0800) {
            dissectIPv4(ctx, inner, rem);
        } else if (protocol == 0x86DD) {
            dissectIPv6(ctx, inner, rem);
        } else if (protocol == 0x0806) {
            if (const Dissector *next = ctx.registry.findEtherType(0x0806)) (*next)(ctx, inner, rem);
        } else if (protocol == 0x880B) {
            dissectPpp(ctx, inner, rem);
        } else if (protocol == 0x8847) {
            dissectMpls(ctx, inner, rem);
        } else if (protocol == 0x88BE || protocol == 0x22EB) {
            dissectErspan(ctx, inner, rem, protocol == 0x22EB, baseOffset + offset);
        } else if (protocol == 0x6558) {
            if (rem >= 14) {
                const uint16_t innerType = be16(inner + 12);
                if (const Dissector *next = ctx.registry.findEtherType(innerType)) {
                    (*next)(ctx, inner + 14, rem - 14);
                    return;
                }
            }
            ctx.addLayer("Data (" + std::to_string(rem) + " bytes)", baseOffset + offset, rem);
        } else {
            ctx.addLayer("Data (" + std::to_string(rem) + " bytes)", baseOffset + offset, rem);
        }
    }
} // namespace dissect
