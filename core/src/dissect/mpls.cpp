#include "mpls.h"

#include <algorithm>
#include <string>

#include "protocols.h"
#include "registry.h"
#include "util.h"

using packet::Field;

namespace {
    using dissect::be16;
    using dissect::be32;

    const char *mplsReservedLabelName(uint32_t label) {
        switch (label) {
            case 0: return "IPv4 explicit NULL";
            case 1: return "Router Alert";
            case 2: return "IPv6 explicit NULL";
            case 3: return "Implicit NULL";
            case 7: return "Entropy Label Indicator";
            case 13: return "Generic Associated Channel";
            case 14: return "OAM Alert";
            default: return label < 16 ? "Reserved" : nullptr;
        }
    }
} // namespace

void dissect::dissectMpls(Context &ctx, const char *data, size_t length) {
    if (length < 4) {
        ctx.markMalformed("frame too short for MPLS header");
        ctx.pack.protocol = "MPLS";
        return;
    }

    const size_t baseOffset = ctx.offsetOf(data);
    size_t offset = 0;
    size_t labelCount = 0;
    constexpr size_t kMaxMplsLabels = 16;
    bool bottomOfStack = false;

    while (offset + 4 <= length) {
        const uint32_t entry = be32(data + offset);
        const uint32_t label = (entry >> 12) & 0xFFFFF;
        const uint8_t tc = (entry >> 9) & 0x07;
        const bool bottom = ((entry >> 8) & 0x01) != 0;
        const uint8_t ttl = entry & 0xFF;

        if (labelCount < 2) {
            ctx.pack.setMplsLse(labelCount, entry);
        }
        labelCount++;

        const char *reserved = mplsReservedLabelName(label);
        std::string labelDesc = std::to_string(label);
        if (reserved) labelDesc += " (" + std::string(reserved) + ")";

        if (ctx.wantFields()) {
            Field &layer = ctx.addLayer("MultiProtocol Label Switching Header, Label: " + labelDesc +
                                            ", Exp: " + std::to_string(tc) +
                                            ", S: " + std::to_string(bottom ? 1 : 0) +
                                            ", TTL: " + std::to_string(ttl),
                                        baseOffset + offset, 4);
            layer.add("MPLS Label: " + labelDesc, baseOffset + offset, 3);
            layer.add("MPLS Experimental Bits: " + std::to_string(tc), baseOffset + offset + 2, 1);
            layer.add("MPLS Bottom of Stack: " + std::to_string(bottom ? 1 : 0), baseOffset + offset + 2, 1);
            layer.add("MPLS TTL: " + std::to_string(ttl), baseOffset + offset + 3, 1);
        }

        offset += 4;
        if (bottom) {
            bottomOfStack = true;
            break;
        }

        if (labelCount >= kMaxMplsLabels) {
            ctx.markMalformed("MPLS label stack exceeds maximum depth");
            break;
        }

        if (offset + 4 > length) {
            ctx.markMalformed("truncated MPLS label stack (bottom of stack not reached)");
            break;
        }
    }

    ctx.pack.l2_size = static_cast<uint16_t>(ctx.pack.l2_size + offset);

    // Default protocol and info if not overwritten by inner protocol
    if (ctx.pack.protocol.empty()) {
        ctx.pack.protocol = "MPLS";
    }

    if (ctx.pack.info.rfind("[Malformed Packet", 0) != 0) {
        const uint32_t lse0 = ctx.pack.mplsLse(0);
        const uint32_t label0 = (lse0 >> 12) & 0xFFFFF;
        if (labelCount == 1) {
            ctx.pack.info = "MPLS Label: " + std::to_string(label0) +
                            ", Exp: " + std::to_string((lse0 >> 9) & 0x07) +
                            ", TTL: " + std::to_string(lse0 & 0xFF);
        } else {
            const uint32_t lse1 = ctx.pack.mplsLse(1);
            const uint32_t label1 = (lse1 >> 12) & 0xFFFFF;
            ctx.pack.info = "MPLS Labels: " + std::to_string(label0) + ", " + std::to_string(label1) +
                            (labelCount > 2 ? ", ..." : "");
        }
    }

    if (!bottomOfStack) {
        return;
    }

    // Unpack payload after bottom-of-stack
    const size_t rem = length - offset;
    if (rem == 0) {
        return;
    }

    const uint8_t firstNibble = static_cast<uint8_t>(data[offset]) >> 4;
    if (firstNibble == 4) {
        dissectIPv4(ctx, data + offset, rem);
    } else if (firstNibble == 6) {
        dissectIPv6(ctx, data + offset, rem);
    } else if (firstNibble == 0 && rem >= 18) {
        // Pseudowire Control Word (RFC 4385) followed by Ethernet frame
        const uint16_t innerEthType = be16(data + offset + 4 + 12);
        if (innerEthType > 1500) {
            if (ctx.wantFields()) {
                ctx.addLayer("Pseudowire Control Word", baseOffset + offset, 4);
            }
            if (const Dissector *inner = ctx.registry.findEtherType(innerEthType)) {
                ctx.pack.l2_size = static_cast<uint16_t>(ctx.pack.l2_size + 4 + 14);
                (*inner)(ctx, data + offset + 4 + 14, rem - 18);
                return;
            }
        }
        if (ctx.wantFields()) {
            ctx.addLayer("Data (" + std::to_string(rem) + " bytes)", baseOffset + offset, rem);
        }
    } else if (rem >= 14) {
        // Direct Ethernet frame without control word
        const uint16_t innerEthType = be16(data + offset + 12);
        if (innerEthType == 0x0800 || innerEthType == 0x86DD || innerEthType == 0x0806) {
            if (const Dissector *inner = ctx.registry.findEtherType(innerEthType)) {
                ctx.pack.l2_size = static_cast<uint16_t>(ctx.pack.l2_size + 14);
                (*inner)(ctx, data + offset + 14, rem - 14);
                return;
            }
        }
        if (ctx.wantFields()) {
            ctx.addLayer("Data (" + std::to_string(rem) + " bytes)", baseOffset + offset, rem);
        }
    } else {
        if (ctx.wantFields()) {
            ctx.addLayer("Data (" + std::to_string(rem) + " bytes)", baseOffset + offset, rem);
        }
    }
}
