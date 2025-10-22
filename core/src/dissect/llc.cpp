#include "llc.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "protocols.h"
#include "registry.h"
#include "stp.h"
#include "util.h"

using packet::Field;

namespace {
    using dissect::be16;
    using dissect::hexString;

    const char *sapName(uint8_t sap) {
        switch (sap) {
            case 0x00: return "Null LSAP";
            case 0x02: return "Individual LLC Sublayer Management";
            case 0x03: return "Group LLC Sublayer Management";
            case 0x04: return "SNA";
            case 0x06: return "IP";
            case 0x0e: return "PROWAY (IEC 955)";
            case 0x42: return "Spanning Tree BPDU";
            case 0x7e: return "X.25 over LLC";
            case 0x8e: return "X.75";
            case 0xaa: return "SNAP";
            case 0xbc: return "Banyan VINES";
            case 0xe0: return "Novell NetWare IPX";
            case 0xf0: return "IBM NetBIOS";
            case 0xf4: return "LAN Management";
            case 0xfe: return "ISO Network Layer (CLNP/ISIS)";
            case 0xff: return "Global LSAP";
            default: return "Unknown";
        }
    }
} // namespace

void dissect::dissectLlc(Context &ctx, const char *data, size_t length) {
    ctx.pack.has_llc = 1;
    if (length < 3) {
        ctx.markMalformed("frame too short for LLC header");
        ctx.pack.protocol = "LLC";
        return;
    }

    const uint8_t dsap = static_cast<uint8_t>(data[0]);
    const uint8_t ssap = static_cast<uint8_t>(data[1]);
    const uint8_t ctrl = static_cast<uint8_t>(data[2]);

    const size_t baseOffset = ctx.offsetOf(data);
    const size_t llcHeaderLen = ((ctrl & 0x03) == 0x03 ? 3 : (length >= 4 ? 4 : 3));

    // ---------------------------------------------------------------------------------------------
    // SNAP (Subnetwork Access Protocol): DSAP = 0xAA, SSAP = 0xAA, Ctrl = 0x03
    // ---------------------------------------------------------------------------------------------
    if (dsap == 0xaa && ssap == 0xaa && ctrl == 0x03) {
        ctx.pack.has_snap = 1;
        ctx.pack.l2_size = static_cast<uint16_t>(ctx.pack.l2_size + 8);
        if (length < 8) {
            ctx.markMalformed("truncated LLC/SNAP header");
            ctx.pack.protocol = "LLC";
            return;
        }

        const uint32_t oui = (static_cast<uint32_t>(static_cast<uint8_t>(data[3])) << 16) |
                             (static_cast<uint32_t>(static_cast<uint8_t>(data[4])) << 8) |
                             static_cast<uint32_t>(static_cast<uint8_t>(data[5]));
        const uint16_t etherType = be16(data + 6);
        ctx.pack.ether_type = etherType;
        ctx.pack.app_type = dsap;
        ctx.pack.app_flags = ssap;
        ctx.pack.app_code = ctrl;
        ctx.pack.tcp_pdu_start = oui;

        if (ctx.wantFields()) {
            Field &llc = ctx.addLayer("Logical-Link Control, DSAP: SNAP (0xaa), SSAP: SNAP (0xaa)", baseOffset, 8);
            llc.add("DSAP: SNAP (" + hexString(dsap, 2) + ")", baseOffset, 1);
            llc.add("SSAP: SNAP (" + hexString(ssap, 2) + ")", baseOffset + 1, 1);
            llc.add("Control field: " + hexString(ctrl, 2) + " (Unnumbered Information)", baseOffset + 2, 1);

            Field &snap = llc.add("Subnetwork Access Protocol (SNAP)", baseOffset + 3, 5);
            snap.add("Organization Unique Code: " + hexString(oui, 6), baseOffset + 3, 3);
            snap.add("Protocol ID: " + hexString(etherType, 4) + " (" + etherTypeName(etherType) + ")", baseOffset + 6, 2);
        }

        if (const Dissector *inner = ctx.registry.findEtherType(etherType)) {
            (*inner)(ctx, data + 8, length - 8);
            return;
        }

        ctx.pack.protocol = "SNAP";
        ctx.pack.info = "Type " + etherTypeName(etherType) + " (" + hexString(etherType, 4) + ")";
        return;
    }

    ctx.pack.l2_size = static_cast<uint16_t>(ctx.pack.l2_size + llcHeaderLen);

    // ---------------------------------------------------------------------------------------------
    // Spanning Tree Protocol: DSAP = 0x42, SSAP = 0x42
    // ---------------------------------------------------------------------------------------------
    if (dsap == 0x42 && ssap == 0x42) {
        if (ctx.wantFields()) {
            Field &llc = ctx.addLayer("Logical-Link Control, DSAP: Spanning Tree BPDU (0x42), SSAP: Spanning Tree BPDU (0x42)",
                                      baseOffset, llcHeaderLen);
            llc.add("DSAP: Spanning Tree BPDU (" + hexString(dsap, 2) + ")", baseOffset, 1);
            llc.add("SSAP: Spanning Tree BPDU (" + hexString(ssap, 2) + ")", baseOffset + 1, 1);
            llc.add("Control field: " + hexString(ctrl, 2), baseOffset + 2, llcHeaderLen - 2);
        }
        dissectStp(ctx, data + llcHeaderLen, length - llcHeaderLen);
        return;
    }

    // ---------------------------------------------------------------------------------------------
    // Other LLC protocols (IP = 0x06, etc.)
    // ---------------------------------------------------------------------------------------------
    if (ctx.wantFields()) {
        Field &llc = ctx.addLayer("Logical-Link Control, DSAP: " + std::string(sapName(dsap)) + " (" + hexString(dsap, 2) + ")",
                                  baseOffset, llcHeaderLen);
        llc.add("DSAP: " + std::string(sapName(dsap)) + " (" + hexString(dsap, 2) + ")", baseOffset, 1);
        llc.add("SSAP: " + std::string(sapName(ssap)) + " (" + hexString(ssap, 2) + ")", baseOffset + 1, 1);
        llc.add("Control field: " + hexString(ctrl, 2), baseOffset + 2, llcHeaderLen - 2);
    }

    if (dsap == 0x06 && ssap == 0x06) { // IPv4 over LLC
        dissectIPv4(ctx, data + llcHeaderLen, length - llcHeaderLen);
        return;
    }

    ctx.pack.protocol = "LLC";
    ctx.pack.app_type = dsap;
    ctx.pack.app_flags = ssap;
    ctx.pack.app_code = ctrl;
    ctx.pack.info = "DSAP " + std::string(sapName(dsap)) + " (" + hexString(dsap, 2) + "), SSAP " +
                    std::string(sapName(ssap)) + " (" + hexString(ssap, 2) + ")";
}
