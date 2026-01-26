#include "dcerpc.h"
#include "reader.h"
#include "util.h"
#include <cstdio>
#include <string>

namespace dissect {

namespace {

const char *dceRpcPduTypeName(uint8_t pduType) {
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

// Formats 16-byte DCE/RPC UUID: 4-byte le, 2-byte le, 2-byte le, 2-byte be, 6-byte be
std::string formatDceRpcUuid(const uint8_t *b) {
    char buf[48];
    uint32_t d1 = static_cast<uint32_t>(b[0]) | (static_cast<uint32_t>(b[1]) << 8) |
                  (static_cast<uint32_t>(b[2]) << 16) | (static_cast<uint32_t>(b[3]) << 24);
    uint16_t d2 = static_cast<uint16_t>(b[4]) | (static_cast<uint16_t>(b[5]) << 8);
    uint16_t d3 = static_cast<uint16_t>(b[6]) | (static_cast<uint16_t>(b[7]) << 8);
    std::snprintf(buf, sizeof(buf), "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                  d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return buf;
}

const char *knownInterfaceUuidName(const std::string &uuid) {
    if (uuid == "00000000-0000-0000-0000-000000000000") return "Null";
    if (uuid == "e1af830d-5d1f-11c9-91a4-08002b14a0fa") return "EPM (Endpoint Mapper)";
    if (uuid == "12345778-1234-abcd-ef00-0123456789ac") return "SAMR (Security Account Manager)";
    if (uuid == "12345678-1234-abcd-ef00-0123456789ab") return "LSA (Local Security Authority)";
    if (uuid == "338cd001-2244-31f1-aaaa-900038001003") return "WINREG (Remote Registry)";
    if (uuid == "4b324fc8-1670-01d3-1278-5a47bf6ee188") return "SRVSVC (Server Service)";
    if (uuid == "6bffd098-a112-3610-9833-46c3f87e345a") return "WKSSVC (Workstation Service)";
    if (uuid == "8d9f4e40-a03d-11ce-8f69-08003e30051b") return "SPOOLSS (Print Spooler)";
    return nullptr;
}

} // namespace

StreamFrame frameDceRpc(const char *data, size_t length) {
    if (length < 10) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    // DCE/RPC version must be 5 (connection-oriented)
    if (bytes[0] != 5) {
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }
    bool littleEndian = ((bytes[4] & 0x10) != 0);
    uint16_t fragLen = 0;
    if (littleEndian) {
        fragLen = static_cast<uint16_t>(bytes[8]) | (static_cast<uint16_t>(bytes[9]) << 8);
    } else {
        fragLen = (static_cast<uint16_t>(bytes[8]) << 8) | static_cast<uint16_t>(bytes[9]);
    }

    if (fragLen < 16 || fragLen > 65535) {
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }

    if (length < fragLen) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    return StreamFrame{StreamFrame::Kind::Complete, fragLen};
}

void dissectDceRpc(Context &ctx, const char *data, size_t length) {
    if (!data || length < 16) return;

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    uint8_t rpcVersion = bytes[0];
    uint8_t rpcMinor = bytes[1];
    uint8_t pduType = bytes[2];
    uint8_t pfcFlags = bytes[3];
    uint8_t drep0 = bytes[4]; // Data representation (0x10 = little-endian)
    bool littleEndian = ((drep0 & 0x10) != 0);

    if (rpcVersion != 5) {
        return; // Only v5 CO supported
    }

    ByteReader r(bytes, length);
    r.skip(8);
    uint16_t fragLen = littleEndian ? r.u16_le() : r.u16_be();
    r.skip(2); // auth length
    uint32_t callId = littleEndian ? r.u32_le() : r.u32_be();

    std::string typeName = dceRpcPduTypeName(pduType);

    ctx.pack.protocol = "DCERPC";
    ctx.pack.app_type = pduType;

    std::string summary = typeName + " (CallID: " + std::to_string(callId) + ")";
    std::string ifaceName;
    uint16_t opnum = 0;
    bool hasOpnum = false;

    // Type 0: Request (alloc_hint: 4, context_id: 2, opnum: 2)
    if (pduType == 0 && length >= 24) {
        r.seek(16);
        r.skip(6); // alloc hint (4), context id (2)
        opnum = littleEndian ? r.u16_le() : r.u16_be();
        hasOpnum = true;
        summary += ", Opnum: " + std::to_string(opnum);
    }
    // Type 11: Bind (max_xmit: 2, max_recv: 2, assoc_group: 4, ctx_items: 1, reserved: 3, ctx_id: 2, num_transfers: 1, reserved2: 1, abstract_syntax UUID: 16)
    else if (pduType == 11 && length >= 48) {
        r.seek(32); // Jump to abstract syntax UUID (16 bytes header + 16 bytes bind header)
        if (r.remaining() >= 16) {
            std::string uuid = formatDceRpcUuid(r.current());
            const char *kn = knownInterfaceUuidName(uuid);
            if (kn) {
                ifaceName = kn;
                summary += ", Interface: " + ifaceName;
            } else {
                ifaceName = uuid;
                summary += ", UUID: " + uuid;
            }
        }
    }

    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("DCE/RPC (" + typeName + ")", o, fragLen <= length ? fragLen : length);
        root.add("Version: " + std::to_string(rpcVersion) + "." + std::to_string(rpcMinor));
        root.add("PDU Type: " + typeName + " (" + std::to_string(pduType) + ")");
        root.add("Flags: 0x" + hexString(pfcFlags, 2));
        root.add("Call ID: " + std::to_string(callId));
        root.add("Frag Length: " + std::to_string(fragLen));
        if (hasOpnum) {
            root.add("Operation: " + std::to_string(opnum));
        }
        if (!ifaceName.empty()) {
            root.add("Interface: " + ifaceName);
        }
    }
}

} // namespace dissect
