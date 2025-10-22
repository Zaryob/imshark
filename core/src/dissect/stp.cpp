#include "stp.h"

#include <iomanip>
#include <sstream>

#include "protocols.h"
#include "util.h"

using packet::Field;

namespace {
    using dissect::be16;
    using dissect::be32;
    using dissect::hexString;

    std::string formatMac(const char *p) {
        std::ostringstream ss;
        ss << std::hex << std::setfill('0');
        for (int i = 0; i < 6; ++i) {
            if (i > 0) ss << ":";
            ss << std::setw(2) << static_cast<unsigned int>(static_cast<uint8_t>(p[i]));
        }
        return ss.str();
    }

    const char *portRoleName(uint8_t role) {
        switch (role) {
            case 1: return "Alternate/Backup";
            case 2: return "Root";
            case 3: return "Designated";
            default: return "Unknown";
        }
    }
} // namespace

void dissect::dissectStp(Context &ctx, const char *data, size_t length) {
    if (length < 4) {
        ctx.markMalformed("frame too short for STP header");
        ctx.pack.protocol = "STP";
        return;
    }

    const uint16_t protoId = be16(data);
    const uint8_t version = static_cast<uint8_t>(data[2]);
    const uint8_t bpduType = static_cast<uint8_t>(data[3]);

    ctx.pack.protocol = (version == 2 ? "RSTP" : version == 3 ? "MSTP" : "STP");
    ctx.pack.app_type = bpduType;
    ctx.pack.app_flags = version;

    const size_t baseOffset = ctx.offsetOf(data);

    // ---------------------------------------------------------------------------------------------
    // Topology Change Notification BPDU (Type 0x80, 4 bytes)
    // ---------------------------------------------------------------------------------------------
    if (bpduType == 0x80) {
        ctx.pack.info = "Topology Change Notification";
        if (ctx.wantFields()) {
            Field &stp = ctx.addLayer("Spanning Tree Protocol (Topology Change Notification)", baseOffset, 4);
            stp.add("Protocol Identifier: " + hexString(protoId, 4) + (protoId == 0 ? " (Spanning Tree)" : ""), baseOffset, 2);
            stp.add("Protocol Version Identifier: " + std::to_string(version), baseOffset + 2, 1);
            stp.add("BPDU Type: 0x80 (Topology Change Notification)", baseOffset + 3, 1);
        }
        return;
    }

    // ---------------------------------------------------------------------------------------------
    // Configuration BPDU (Type 0x00) or RST/MST BPDU (Type 0x02)
    // ---------------------------------------------------------------------------------------------
    if (bpduType == 0x00 || bpduType == 0x02) {
        if (length < 35) {
            ctx.markMalformed("truncated STP Configuration BPDU");
            return;
        }

        const uint8_t flags = static_cast<uint8_t>(data[4]);
        ctx.pack.app_flags = (static_cast<uint16_t>(flags) << 8) | version;
        const uint16_t rootPri = be16(data + 5);
        const std::string rootMac = formatMac(data + 7);
        const std::string rootIdStr = std::to_string(rootPri) + " / " + rootMac;

        const uint32_t cost = be32(data + 13);

        const uint16_t bridgePri = be16(data + 17);
        const std::string bridgeMac = formatMac(data + 19);
        const std::string bridgeIdStr = std::to_string(bridgePri) + " / " + bridgeMac;

        const uint16_t portId = be16(data + 25);
        const uint16_t msgAge = be16(data + 27);
        const uint16_t maxAge = be16(data + 29);
        const uint16_t helloTime = be16(data + 31);
        const uint16_t fwdDelay = be16(data + 33);

        ctx.pack.app_code = portId;
        ctx.pack.tcp_pdu_start = cost;
        ctx.pack.app_text = rootIdStr;
        ctx.pack.app_text2 = bridgeIdStr;

        const std::string prefix = (bpduType == 0x02 ? "RST." : "Conf.");
        ctx.pack.info = prefix + " Root = " + rootIdStr + "  Cost = " + std::to_string(cost) + "  Port = " + hexString(portId, 4);

        if (ctx.wantFields()) {
            const size_t bpduLen = (bpduType == 0x02 && length >= 36 ? 36 : 35);
            const std::string layerName = (version == 2 ? "Rapid Spanning Tree Protocol"
                                                        : version == 3 ? "Multiple Spanning Tree Protocol"
                                                                       : "Spanning Tree Protocol");
            Field &stp = ctx.addLayer(layerName, baseOffset, bpduLen);
            stp.add("Protocol Identifier: " + hexString(protoId, 4) + (protoId == 0 ? " (Spanning Tree)" : ""), baseOffset, 2);
            stp.add("Protocol Version Identifier: " + std::to_string(version) +
                    (version == 0 ? " (STP)" : version == 2 ? " (RSTP)" : version == 3 ? " (MSTP)" : ""), baseOffset + 2, 1);
            stp.add("BPDU Type: " + hexString(bpduType, 2) + (bpduType == 0x02 ? " (Rapid/Multiple Spanning Tree)" : " (Configuration)"), baseOffset + 3, 1);

            Field &fl = stp.add("BPDU flags: " + hexString(flags, 2), baseOffset + 4, 1);
            if (flags & 0x80) fl.add("Topology Change Acknowledgment: Yes", baseOffset + 4, 1);
            if (flags & 0x40) fl.add("Agreement: Yes", baseOffset + 4, 1);
            if (flags & 0x20) fl.add("Forwarding: Yes", baseOffset + 4, 1);
            if (flags & 0x10) fl.add("Learning: Yes", baseOffset + 4, 1);
            const uint8_t role = (flags >> 2) & 0x03;
            fl.add("Port Role: " + std::string(portRoleName(role)) + " (" + std::to_string(role) + ")", baseOffset + 4, 1);
            if (flags & 0x02) fl.add("Proposal: Yes", baseOffset + 4, 1);
            if (flags & 0x01) fl.add("Topology Change: Yes", baseOffset + 4, 1);

            Field &root = stp.add("Root Identifier: " + rootIdStr, baseOffset + 5, 8);
            root.add("Root Bridge Priority: " + std::to_string(rootPri & 0xF000), baseOffset + 5, 2);
            root.add("Root Bridge System ID Extension: " + std::to_string(rootPri & 0x0FFF), baseOffset + 5, 2);
            root.add("Root Bridge System ID: " + rootMac, baseOffset + 7, 6);

            stp.add("Root Path Cost: " + std::to_string(cost), baseOffset + 13, 4);

            Field &bridge = stp.add("Bridge Identifier: " + bridgeIdStr, baseOffset + 17, 8);
            bridge.add("Bridge Priority: " + std::to_string(bridgePri & 0xF000), baseOffset + 17, 2);
            bridge.add("Bridge System ID Extension: " + std::to_string(bridgePri & 0x0FFF), baseOffset + 17, 2);
            bridge.add("Bridge System ID: " + bridgeMac, baseOffset + 19, 6);

            stp.add("Port Identifier: " + hexString(portId, 4), baseOffset + 25, 2);
            stp.add("Message Age: " + std::to_string(msgAge / 256.0) + " s", baseOffset + 27, 2);
            stp.add("Max Age: " + std::to_string(maxAge / 256.0) + " s", baseOffset + 29, 2);
            stp.add("Hello Time: " + std::to_string(helloTime / 256.0) + " s", baseOffset + 31, 2);
            stp.add("Forward Delay: " + std::to_string(fwdDelay / 256.0) + " s", baseOffset + 33, 2);

            if (bpduType == 0x02 && length >= 36) {
                const uint8_t v1Len = static_cast<uint8_t>(data[35]);
                stp.add("Version 1 Length: " + std::to_string(v1Len), baseOffset + 35, 1);
            }
        }
        return;
    }

    ctx.pack.info = "BPDU Type " + hexString(bpduType, 2);
}
