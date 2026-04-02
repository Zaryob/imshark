// DCE/RPC connection-oriented PDUs (C706 chapter 12, RPC version 5). Common header (16 bytes): rpc_vers, rpc_vers_minor, PTYPE,
// pfc_flags (1 first fragment, 2 last fragment, 0x80 object UUID), packed_drep (byte 0: 0x10 = little-endian integers),
// frag_length, auth_length, call_id. Decoded: Bind / Alter_context (every presentation context: id, abstract syntax UUID and
// version, transfer syntaxes), Bind_ack / Alter_context_resp (results), Request (context id, opnum, object UUID), Response, Fault
// (status), Bind_nak. Not decoded: connectionless (version 4) PDUs, fragment reassembly, the stub data of Request / Response.
#include "dcerpc.h"

#include <cstdio>
#include <string>
#include <vector>

#include "reader.h"
#include "util.h"

using packet::Field;

namespace dissect {

namespace {

constexpr uint8_t kPfcFirst = 0x01, kPfcLast = 0x02, kPfcObjectUuid = 0x80;
constexpr uint16_t kFlagRequest = 1;   // app_flags: app_code holds the opnum

const char *pduTypeName(uint8_t pduType) {
    switch (pduType) {
        case 0: return "Request";
        case 1: return "Ping";
        case 2: return "Response";
        case 3: return "Fault";
        case 4: return "Working";
        case 5: return "Nocall";
        case 6: return "Reject";
        case 7: return "Ack";
        case 8: return "Cl_cancel";
        case 9: return "Fack";
        case 10: return "Cancel_ack";
        case 11: return "Bind";
        case 12: return "Bind_ack";
        case 13: return "Bind_nak";
        case 14: return "Alter_context";
        case 15: return "Alter_context_resp";
        case 16: return "Auth3";
        case 17: return "Shutdown";
        case 18: return "Co_cancel";
        case 19: return "Orphaned";
        default: return "Unknown";
    }
}

// 16-byte UUID: the first three fields follow the integer representation of the PDU, the rest are bytes
std::string formatUuid(const uint8_t *b, bool littleEndian) {
    char buf[48];
    uint32_t d1;
    uint16_t d2, d3;
    if (littleEndian) {
        d1 = static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) | (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
        d2 = static_cast<uint16_t>(b[4] | (b[5] << 8));
        d3 = static_cast<uint16_t>(b[6] | (b[7] << 8));
    } else {
        d1 = (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) | (static_cast<uint32_t>(b[2]) << 8) | b[3];
        d2 = static_cast<uint16_t>((b[4] << 8) | b[5]);
        d3 = static_cast<uint16_t>((b[6] << 8) | b[7]);
    }
    std::snprintf(buf, sizeof buf, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return buf;
}

const char *interfaceName(const std::string &uuid) {
    static const struct { const char *uuid, *name; } known[] = {
        {"e1af8308-5d1f-11c9-91a4-08002b14a0fa", "EPM (Endpoint Mapper)"},
        {"e1af830d-5d1f-11c9-91a4-08002b14a0fa", "EPM (Endpoint Mapper)"},
        {"12345778-1234-abcd-ef00-0123456789ac", "SAMR (Security Account Manager)"},
        {"12345678-1234-abcd-ef00-0123456789ab", "LSA (Local Security Authority)"},
        {"12345678-1234-abcd-ef00-01234567cffb", "NETLOGON"},
        {"338cd001-2244-31f1-aaaa-900038001003", "WINREG (Remote Registry)"},
        {"4b324fc8-1670-01d3-1278-5a47bf6ee188", "SRVSVC (Server Service)"},
        {"6bffd098-a112-3610-9833-46c3f87e345a", "WKSSVC (Workstation Service)"},
        {"8d9f4e40-a03d-11ce-8f69-08003e30051b", "SPOOLSS (Print Spooler)"},
        {"367abb81-9844-35f1-ad32-98f038001003", "SVCCTL (Service Control)"},
        {"1ff70682-0a51-30e8-076d-740be8cee98b", "ATSVC (Task Scheduler)"},
        {"e3514235-4b06-11d1-ab04-00c04fc2dcd2", "DRSUAPI (Directory Replication)"},
        {"99fcfec4-5260-101b-bbcb-00aa0021347a", "IOXIDResolver"},
        {"000001a0-0000-0000-c000-000000000046", "ISystemActivator"},
        {"8a885d04-1ceb-11c9-9fe8-08002b104860", "NDR transfer syntax"},
        {"71710533-beba-4937-8319-b5dbef9ccc36", "NDR64 transfer syntax"},
        {"00000000-0000-0000-0000-000000000000", "Null"},
    };
    for (const auto &k: known) if (uuid == k.uuid) return k.name;
    return nullptr;
}

const char *ackResultName(uint16_t r) {
    switch (r) {
        case 0: return "acceptance";
        case 1: return "user-rejection";
        case 2: return "provider-rejection";
        default: return "unknown";
    }
}

const char *nakReasonName(uint16_t r) {
    switch (r) {
        case 0: return "reason not specified";
        case 1: return "temporary congestion";
        case 2: return "local limit exceeded";
        case 3: return "called presentation address unknown";
        case 4: return "protocol version not supported";
        case 5: return "default context not supported";
        case 6: return "user data not readable";
        case 7: return "no psap available";
        default: return "unknown";
    }
}

} // namespace

StreamFrame frameDceRpc(const char *data, size_t length) {
    if (length == 0) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    if (bytes[0] != 5) return StreamFrame{StreamFrame::Kind::Reject, 0};   // connection-oriented RPC; version 4 is connectionless
    if (length >= 2 && bytes[1] > 1) return StreamFrame{StreamFrame::Kind::Reject, 0};
    if (length >= 3 && bytes[2] > 19) return StreamFrame{StreamFrame::Kind::Reject, 0};
    if (length >= 5 && (bytes[4] & 0xEE) != 0) return StreamFrame{StreamFrame::Kind::Reject, 0};   // integer rep 0/1, ASCII (EBCDIC 0x01 allowed)
    if (length < 10) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const bool littleEndian = (bytes[4] & 0x10) != 0;
    const size_t fragLen = littleEndian ? static_cast<size_t>(bytes[8] | (bytes[9] << 8)) : static_cast<size_t>((bytes[8] << 8) | bytes[9]);
    if (fragLen < 16) return StreamFrame{StreamFrame::Kind::Reject, 0};
    return StreamFrame{length < fragLen ? StreamFrame::Kind::NeedMore : StreamFrame::Kind::Complete, fragLen};
}

void dissectDceRpc(Context &ctx, const char *data, size_t length) {
    if (!data || length < 16) return;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    if (bytes[0] != 5) return;   // only connection-oriented PDUs

    auto &pack = ctx.pack;
    const uint8_t rpcMinor = bytes[1], pduType = bytes[2], pfcFlags = bytes[3];
    const bool le = (bytes[4] & 0x10) != 0;
    ByteReader hr(bytes + 8, 8);
    const uint16_t fragLen = le ? hr.u16_le() : hr.u16_be();
    const uint16_t authLen = le ? hr.u16_le() : hr.u16_be();
    const uint32_t callId = le ? hr.u32_le() : hr.u32_be();
    const size_t o = ctx.offsetOf(data);
    const size_t have = std::min<size_t>(fragLen < 16 ? 16 : fragLen, length);   // the PDU as captured
    const bool cut = fragLen > length;

    const std::string typeName = pduTypeName(pduType);
    pack.protocol = "DCERPC";
    pack.app_type = pduType;
    pack.app_stream = callId;

    std::string summary = typeName + " (CallID: " + std::to_string(callId) + ")";
    std::vector<std::pair<std::string, std::pair<size_t, size_t>>> items;   // detail-tree children: text, offset, length
    auto add = [&](const std::string &text, size_t off, size_t len) { items.push_back({text, {o + off, len}}); };
    ByteReader r(bytes, have);
    r.seek(16);
    const auto rd16 = [&](ByteReader &x) { return le ? x.u16_le() : x.u16_be(); };
    const auto rd32 = [&](ByteReader &x) { return le ? x.u32_le() : x.u32_be(); };
    auto uuidAt = [&](size_t at) { return formatUuid(bytes + at, le); };

    std::string firstUuid;
    const char *malformed = nullptr;   // set when the PDU is complete (not cut) but its body does not decode
    {   // the fixed part of each PDU type must be there in a complete PDU
        size_t minimum = 16;
        switch (pduType) {
            case 0: case 2: minimum = 24; break;
            case 3: minimum = 28; break;
            case 11: case 14: minimum = 28; break;
            case 12: case 15: minimum = 26; break;
            case 13: minimum = 18; break;
            default: break;
        }
        if (!cut && fragLen >= 16 && fragLen < minimum) malformed = "DCE/RPC PDU shorter than the fixed part of its type";
    }
    // Bind (11) / Alter_context (14): max_xmit_frag, max_recv_frag, assoc_group_id, then the presentation context list
    if ((pduType == 11 || pduType == 14) && have >= 28) {
        const uint16_t maxXmit = rd16(r), maxRecv = rd16(r);
        const uint32_t assoc = rd32(r);
        const uint8_t nctx = r.u8();
        r.skip(3);
        add("Max Xmit Frag: " + std::to_string(maxXmit) + ", Max Recv Frag: " + std::to_string(maxRecv), 16, 4);
        add("Assoc Group: " + hexString(assoc, 8), 20, 4);
        add("Num Ctx Items: " + std::to_string(nctx), 24, 1);
        std::string ifaces;
        unsigned read = 0;
        for (unsigned i = 0; i < nctx && i < 16; ++i) {
            const size_t at = r.offset();
            if (r.remaining() < 4 + 20 + 20) break;
            const uint16_t ctxId = rd16(r);
            const uint8_t ntrans = r.u8();
            r.skip(1);
            const std::string uuid = uuidAt(r.offset());
            r.skip(16);
            const uint32_t ver = rd32(r);
            const char *kn = interfaceName(uuid);
            std::string name = kn ? kn : uuid;
            ++read;
            if (firstUuid.empty()) firstUuid = uuid;
            ifaces += (ifaces.empty() ? "" : ", ") + name;
            add("Context " + std::to_string(ctxId) + ": " + name + " v" + std::to_string(ver & 0xffff) + "." + std::to_string(ver >> 16), at, 4 + 20 + 20ul * ntrans);
            for (unsigned t = 0; t < ntrans && r.remaining() >= 20 && t < 8; ++t) {
                const std::string tuuid = uuidAt(r.offset());
                const char *tn = interfaceName(tuuid);
                add("  Transfer Syntax: " + std::string(tn ? tn : tuuid.c_str()), r.offset(), 20);
                r.skip(20);
            }
            if (ntrans > 8) r.skip(std::min<size_t>(r.remaining(), 20ul * (ntrans - 8)));
        }
        if (!cut && read < std::min<unsigned>(nctx, 16)) malformed = "DCE/RPC Bind announces more presentation contexts than it holds";
        if (!ifaces.empty()) summary += (pduType == 11 ? ", Bind: " : ", Alter: ") + ifaces;
    } else if ((pduType == 12 || pduType == 15) && have >= 26) { // Bind_ack: ..., sec_addr_len, sec_addr, pad to 4, n_results, results
        const uint16_t maxXmit = rd16(r), maxRecv = rd16(r);
        const uint32_t assoc = rd32(r);
        const uint16_t secLen = rd16(r);
        add("Max Xmit Frag: " + std::to_string(maxXmit) + ", Max Recv Frag: " + std::to_string(maxRecv), 16, 4);
        add("Assoc Group: " + hexString(assoc, 8), 20, 4);
        if (r.remaining() >= secLen) {
            const std::string addr = printableText(bytes + r.offset(), secLen > 0 ? secLen - 1 : 0, 63);
            if (!addr.empty()) add("Secondary Address: " + addr, r.offset(), secLen);
            r.skip(secLen);
            while (r.offset() % 4 != 0 && r.remaining() > 0) r.skip(1);   // pad so that n_results is aligned
            if (r.remaining() >= 4) {
                const uint8_t n = r.u8();
                r.skip(3);
                std::string results;
                for (unsigned i = 0; i < n && i < 16 && r.remaining() >= 24; ++i) {
                    const uint16_t result = rd16(r), reason = rd16(r);
                    r.skip(20);
                    results += (results.empty() ? "" : ", ") + std::string(ackResultName(result));
                    add("Result " + std::to_string(i) + ": " + ackResultName(result) + (result ? " (reason " + std::to_string(reason) + ")" : ""), r.offset() - 24, 24);
                }
                if (!results.empty()) summary += ", " + results;
            }
        }
    } else if (pduType == 13 && have >= 18) { // Bind_nak
        const uint16_t reason = rd16(r);
        summary += std::string(", ") + nakReasonName(reason);
        add(std::string("Reject Reason: ") + nakReasonName(reason) + " (" + std::to_string(reason) + ")", 16, 2);
    } else if (pduType == 0 && have >= 24) { // Request: alloc_hint (4), p_cont_id (2), opnum (2), [object UUID (16) if PFC_OBJECT_UUID]
        const uint32_t hint = rd32(r);
        const uint16_t ctxId = rd16(r), opnum = rd16(r);
        pack.app_code = opnum;
        pack.app_flags |= kFlagRequest;
        summary += ", Opnum: " + std::to_string(opnum);
        add("Alloc Hint: " + std::to_string(hint), 16, 4);
        add("Context ID: " + std::to_string(ctxId), 20, 2);
        add("Operation: " + std::to_string(opnum), 22, 2);
        if ((pfcFlags & kPfcObjectUuid) && r.remaining() >= 16) add("Object: " + uuidAt(r.offset()), r.offset(), 16);
    } else if (pduType == 2 && have >= 24) { // Response: alloc_hint (4), p_cont_id (2), cancel_count (1), reserved (1)
        const uint32_t hint = rd32(r);
        const uint16_t ctxId = rd16(r);
        add("Alloc Hint: " + std::to_string(hint), 16, 4);
        add("Context ID: " + std::to_string(ctxId), 20, 2);
    } else if (pduType == 3 && have >= 28) { // Fault: alloc_hint (4), p_cont_id (2), cancel_count (1), reserved (1), status (4)
        r.skip(8);
        const uint32_t status = rd32(r);
        summary += ", Status: " + hexString(status, 8);
        add("Fault Status: " + hexString(status, 8), 24, 4);
    }
    pack.app_text = firstUuid;

    if (authLen > 0) add("Auth Length: " + std::to_string(authLen), 10, 2);
    if (!(pfcFlags & kPfcFirst) || !(pfcFlags & kPfcLast)) {
        summary += std::string(" [") + ((pfcFlags & kPfcFirst) ? "first fragment" : (pfcFlags & kPfcLast) ? "last fragment" : "middle fragment") + "]";
    }
    pack.info = summary;

    if (ctx.wantFields()) {
        Field &root = ctx.addLayer("DCE/RPC (" + typeName + ")", o, have);
        root.add("Version: 5." + std::to_string(rpcMinor), o, 2);
        root.add("PDU Type: " + typeName + " (" + std::to_string(pduType) + ")", o + 2, 1);
        root.add("Flags: " + hexString(pfcFlags, 2) + ((pfcFlags & kPfcFirst) ? " First" : "") + ((pfcFlags & kPfcLast) ? " Last" : "") + ((pfcFlags & kPfcObjectUuid) ? " Object" : ""), o + 3, 1);
        root.add(std::string("Data Representation: ") + (le ? "little-endian" : "big-endian") + " (" + hexString(bytes[4], 2) + ")", o + 4, 4);
        root.add("Frag Length: " + std::to_string(fragLen), o + 8, 2);
        root.add("Call ID: " + std::to_string(callId), o + 12, 4);
        for (const auto &it: items) {
            if (it.second.first <= o + length) root.add(it.first, it.second.first, std::min(it.second.second, o + length - it.second.first));
        }
    }
    if (fragLen < 16) ctx.markMalformed("DCE/RPC fragment length below the 16 byte header");
    else if (malformed) ctx.markMalformed(malformed);   // after the summary: it replaces it
}

} // namespace dissect
