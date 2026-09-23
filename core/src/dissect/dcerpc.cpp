// DCE/RPC connection-oriented PDUs (C706 chapter 12, RPC version 5). Common header (16 bytes): rpc_vers, rpc_vers_minor, PTYPE,
// pfc_flags (1 first fragment, 2 last fragment, 0x80 object UUID), packed_drep (byte 0: 0x10 = little-endian integers),
// frag_length, auth_length, call_id. Decoded: Bind / Alter_context (every presentation context: id, abstract syntax UUID and
// version, transfer syntaxes), Bind_ack / Alter_context_resp (results), Request (context id, opnum, object UUID), Response, Fault
// (status), Bind_nak, and the authentication verifier of every PDU ([MS-RPCE] 2.2.2.11: auth type, level, padding, context id,
// credentials; the credentials of Bind / Bind_ack / Alter_context / Auth3 go through the SPNEGO decoder, those of Request /
// Response are a signature and are only labelled). Stub data of an authenticated Request / Response at packet privacy is sealed:
// it is labelled and never read as plaintext.
// What an earlier packet decided comes from the session table (dcerpc_session.h): the interface of a context id (Bind / Bind_ack),
// the opnum of a Response's request, the fragment chain a PDU belongs to and the endpoint mapper's answers.
#include "dcerpc.h"

#include <cstdio>
#include <string>
#include <vector>

#include "dcerpc_session.h"
#include "reader.h"
#include "spnego.h"
#include "util.h"

using packet::Field;

namespace dissect {

namespace {

constexpr uint8_t kPfcFirst = 0x01, kPfcLast = 0x02, kPfcObjectUuid = 0x80;
constexpr uint8_t kAuthPrivacy = 6;   // RPC_C_AUTHN_LEVEL_PKT_PRIVACY

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

const char *interfaceName(const std::string &uuid) {
    static const struct { const char *uuid, *name; } known[] = {
        {"e1af8308-5d1f-11c9-91a4-08002b14a0fa", "EPM (Endpoint Mapper)"},
        {"12345778-1234-abcd-ef00-0123456789ac", "SAMR (Security Account Manager)"},
        {"12345778-1234-abcd-ef00-0123456789ab", "LSARPC (Local Security Authority)"},
        {"12345678-1234-abcd-ef00-0123456789ab", "SPOOLSS (Print Spooler)"},
        {"12345678-1234-abcd-ef00-01234567cffb", "NETLOGON"},
        {"338cd001-2244-31f1-aaaa-900038001003", "WINREG (Remote Registry)"},
        {"4b324fc8-1670-01d3-1278-5a47bf6ee188", "SRVSVC (Server Service)"},
        {"6bffd098-a112-3610-9833-46c3f87e345a", "WKSSVC (Workstation Service)"},
        {"8d9f4e40-a03d-11ce-8f69-08003e30051b", "PNP (Plug and Play)"},
        {"367abb81-9844-35f1-ad32-98f038001003", "SVCCTL (Service Control)"},
        {"1ff70682-0a51-30e8-076d-740be8cee98b", "ATSVC (Task Scheduler)"},
        {"86d35949-83c9-4044-b424-db363231fd0c", "TSCH (Task Scheduler Service)"},
        {"82273fdc-e32a-18c3-3f78-827929dc23ea", "EVENTLOG"},
        {"4fc742e0-4a10-11cf-8273-00aa004ae673", "NETDFS (Distributed File System)"},
        {"c681d488-d850-11d0-8c52-00c04fd90f7e", "EFSRPC (Encrypting File System)"},
        {"e3514235-4b06-11d1-ab04-00c04fc2dcd2", "DRSUAPI (Directory Replication)"},
        {"50abc2a4-574d-40b3-9d66-ee4fd5fba076", "DNSSERVER"},
        {"99fcfec4-5260-101b-bbcb-00aa0021347a", "IOXIDResolver"},
        {"000001a0-0000-0000-c000-000000000046", "ISystemActivator"},
        {"4d9f4ab8-7d1c-11cf-861e-0020af6e7c57", "IActivation"},
        {"00000131-0000-0000-c000-000000000046", "IRemUnknown"},
        {"00000143-0000-0000-c000-000000000046", "IRemUnknown2"},
        {"f309ad18-d86a-11d0-a075-00c04fb68820", "IWbemLevel1Login"},
        {"9556dc99-828c-11cf-a37e-00aa003240c7", "IWbemServices"},
        {"8a885d04-1ceb-11c9-9fe8-08002b104860", "NDR transfer syntax"},
        {"71710533-beba-4937-8319-b5dbef9ccc36", "NDR64 transfer syntax"},
        {"6cb71c2c-9812-4540-0300-000000000000", "Bind Time Feature Negotiation"},
        {"00000000-0000-0000-0000-000000000000", "Null"},
    };
    for (const auto &k: known) if (uuid == k.uuid) return k.name;
    return nullptr;
}

std::string interfaceText(const std::string &uuid) {
    const char *name = interfaceName(uuid);
    return name ? name : uuid;
}

std::string versionText(uint32_t version) { return std::to_string(version & 0xffff) + "." + std::to_string(version >> 16); }

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

// [MS-RPCE] 2.2.1.1.7 authentication services (auth_type)
std::string authServiceName(uint8_t type) {
    switch (type) {
        case 0: return "None";
        case 1: return "DCE private key";
        case 2: return "DCE public key";
        case 9: return "SPNEGO";
        case 10: return "NTLMSSP";
        case 14: return "Schannel";
        case 16: return "Kerberos";
        case 68: return "Netlogon secure channel";
        case 0xFF: return "Default";
        default: return "Unknown (" + std::to_string(type) + ")";
    }
}

// [MS-RPCE] 2.2.1.1.8 authentication levels (auth_level)
std::string authLevelName(uint8_t level) {
    switch (level) {
        case 0: return "Default";
        case 1: return "None";
        case 2: return "Connect";
        case 3: return "Call";
        case 4: return "Packet";
        case 5: return "Packet integrity";
        case 6: return "Packet privacy";
        default: return "Unknown (" + std::to_string(level) + ")";
    }
}

// everything the callers (TCP, later named pipes) need to know about a decoded PDU
struct Decoded {
    bool ok = false;
    uint8_t type = 0;
    uint32_t callId = 0;
    bool request = false;
    uint16_t opnum = 0;
    std::string iface;          // the interface the PDU's context / header named (UUID), else the first Bind context
    uint8_t authLevel = 0;
    std::string authService;
    bool sealed = false, fragment = false, reassembled = false;
    std::string info;
    const char *malformed = nullptr;   // why a complete PDU does not decode (the caller marks the packet after naming it)
};

// where the PDU comes from: the key of its stream in the session table and of its note
struct Carrier {
    std::string stream;
    int64_t seq = -1;
    uint8_t index = 0;
    std::string fallback;       // the interface to assume when no accepted Bind named one (well known port, endpoint mapper's port map)
};

// Decodes the connection-oriented PDU at data[0..length) and fills the layer and the facts; false if it is not a version 5 PDU.
bool decodeConnectionOriented(Context &ctx, const char *data, size_t length, const Carrier &carrier, Decoded &out) {
    if (!data || length < 16) return false;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    if (bytes[0] != 5) return false;   // only connection-oriented PDUs

    const uint8_t rpcMinor = bytes[1], pduType = bytes[2], pfcFlags = bytes[3];
    const bool le = (bytes[4] & 0x10) != 0;
    ByteReader hr(bytes + 8, 8);
    const uint16_t fragLen = le ? hr.u16_le() : hr.u16_be();
    const uint16_t authLen = le ? hr.u16_le() : hr.u16_be();
    const uint32_t callId = le ? hr.u32_le() : hr.u32_be();
    const size_t o = ctx.offsetOf(data);
    const size_t have = std::min<size_t>(fragLen < 16 ? 16 : fragLen, length);   // the PDU as captured
    const bool cut = fragLen > length;
    const auto rd16 = [&](ByteReader &x) { return le ? x.u16_le() : x.u16_be(); };
    const auto rd32 = [&](ByteReader &x) { return le ? x.u32_le() : x.u32_be(); };
    const auto uuidAt = [&](size_t at) { return dceFormatUuid(bytes + at, le); };
    // a node under `parent` for bytes [at, at + len) of the PDU, clipped to what was captured
    const auto node = [&](Field &parent, const std::string &text, size_t at, size_t len) -> Field & {
        if (at > have) { at = have; len = 0; }
        return parent.add(text, o + at, std::min(len, have - at));
    };

    const std::string typeName = pduTypeName(pduType);
    out.ok = true;
    out.type = pduType;
    out.callId = callId;
    auto &pack = ctx.pack;
    SessionTables *sessions = ctx.sessions;
    const bool loadPass = ctx.mode != ParseMode::Replay && sessions && !sessions->isFrozen();

    // ---- the authentication verifier: auth_length bytes of credentials behind an 8 byte header, at the end of the PDU ----------
    size_t trailerAt = 0;                 // offset of the 8 byte header (0: none)
    uint8_t authType = 0, authLevel = 0, authPad = 0;
    uint32_t authCtx = 0;
    const char *malformed = nullptr;      // set when the PDU is complete (not cut) but does not decode
    if (authLen > 0) {
        if (fragLen >= 16u + 8u + authLen) trailerAt = fragLen - authLen - 8u;
        else if (!cut) malformed = "DCE/RPC authentication verifier does not fit in the fragment";
    }
    const bool trailerCaptured = trailerAt != 0 && trailerAt + 8 <= have;
    if (trailerCaptured) {
        ByteReader tr(bytes + trailerAt, 8);
        authType = tr.u8();
        authLevel = tr.u8();
        authPad = tr.u8();
        tr.u8();
        authCtx = rd32(tr);
        out.authLevel = authLevel;
        out.authService = authServiceName(authType);
    }
    // the stub data of a Request / Response at packet privacy is sealed; so is any stub whose verifier could not be read
    out.sealed = (pduType == 0 || pduType == 2) && authLen > 0 && (!trailerCaptured || authLevel == kAuthPrivacy);

    {   // the fixed part of each PDU type must be there in a complete PDU
        size_t minimum = 16;
        switch (pduType) {
            case 0: minimum = (pfcFlags & kPfcObjectUuid) ? 40 : 24; break;
            case 2: minimum = 24; break;
            case 3: minimum = 28; break;
            case 11: case 14: minimum = 28; break;
            case 12: case 15: minimum = 26; break;
            case 13: minimum = 18; break;
            default: break;
        }
        if (!cut && fragLen >= 16 && fragLen < minimum) malformed = "DCE/RPC PDU shorter than the fixed part of its type";
        else if (!cut && !malformed && trailerAt != 0 && trailerAt < minimum) malformed = "DCE/RPC authentication verifier overlaps the fixed part of the PDU";
    }
    const size_t bodyEnd = trailerAt != 0 ? std::min(trailerAt, have) : have;   // the body proper ends where the verifier starts

    std::string summary = typeName + " (CallID: " + std::to_string(callId) + ")";
    std::vector<std::pair<std::string, std::pair<size_t, size_t>>> items;   // detail-tree children: text, offset, length
    auto add = [&](const std::string &text, size_t off, size_t len) { items.push_back({text, {off, len}}); };
    ByteReader r(bytes, bodyEnd);
    r.seek(16);

    DcePdu pdu;
    pdu.type = pduType;
    pdu.callId = callId;
    pdu.first = (pfcFlags & kPfcFirst) != 0;
    pdu.last = (pfcFlags & kPfcLast) != 0;
    pdu.little = le;
    pdu.encrypted = out.sealed;

    std::string firstUuid;
    size_t stubAt = 0;                    // stub data of a Request / Response / Fault inside the PDU (0: none)
    // Bind (11) / Alter_context (14): max_xmit_frag, max_recv_frag, assoc_group_id, then the presentation context list
    if ((pduType == 11 || pduType == 14) && bodyEnd >= 28) {
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
            pdu.contexts.push_back({ctxId, uuid, ver});
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
    } else if ((pduType == 12 || pduType == 15) && bodyEnd >= 26) { // Bind_ack: ..., sec_addr_len, sec_addr, pad to 4, n_results, results
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
                    pdu.results.push_back(result);
                    results += (results.empty() ? "" : ", ") + std::string(ackResultName(result));
                    add("Result " + std::to_string(i) + ": " + ackResultName(result) + (result ? " (reason " + std::to_string(reason) + ")" : ""), r.offset() - 24, 24);
                }
                if (!results.empty()) summary += ", " + results;
            }
        }
    } else if (pduType == 13 && bodyEnd >= 18) { // Bind_nak
        const uint16_t reason = rd16(r);
        summary += std::string(", ") + nakReasonName(reason);
        add(std::string("Reject Reason: ") + nakReasonName(reason) + " (" + std::to_string(reason) + ")", 16, 2);
    } else if (pduType == 0 && bodyEnd >= 24) { // Request: alloc_hint (4), p_cont_id (2), opnum (2), [object UUID (16) if PFC_OBJECT_UUID]
        const uint32_t hint = rd32(r);
        const uint16_t ctxId = rd16(r), opnum = rd16(r);
        out.request = true;
        out.opnum = opnum;
        pdu.contextId = ctxId;
        pdu.opnum = opnum;
        summary += ", Opnum: " + std::to_string(opnum);
        add("Alloc Hint: " + std::to_string(hint), 16, 4);
        add("Context ID: " + std::to_string(ctxId), 20, 2);
        add("Operation: " + std::to_string(opnum), 22, 2);
        stubAt = 24;
        if (pfcFlags & kPfcObjectUuid) {
            if (r.remaining() >= 16) add("Object: " + uuidAt(r.offset()), r.offset(), 16);
            stubAt = 40;
        }
    } else if (pduType == 2 && bodyEnd >= 24) { // Response: alloc_hint (4), p_cont_id (2), cancel_count (1), reserved (1)
        const uint32_t hint = rd32(r);
        const uint16_t ctxId = rd16(r);
        pdu.contextId = ctxId;
        add("Alloc Hint: " + std::to_string(hint), 16, 4);
        add("Context ID: " + std::to_string(ctxId), 20, 2);
        stubAt = 24;
    } else if (pduType == 3 && bodyEnd >= 28) { // Fault: alloc_hint (4), p_cont_id (2), cancel_count (1), reserved (1), status (4), reserved (4)
        r.skip(4);
        pdu.contextId = rd16(r);
        r.skip(2);
        const uint32_t status = rd32(r);
        summary += ", Status: " + hexString(status, 8);
        add("Fault Status: " + hexString(status, 8), 24, 4);
        stubAt = 32;
    }
    // the stub data ends where the padding in front of the verifier starts
    size_t stubLen = 0;
    if (stubAt != 0) {
        size_t end = trailerAt != 0 ? std::min<size_t>(trailerAt, fragLen) : fragLen;
        if (trailerAt != 0) {
            if (authPad <= end && end - authPad >= stubAt) end -= authPad;
            else if (trailerCaptured && !cut && !malformed) malformed = "DCE/RPC authentication padding does not fit in the fragment";
        }
        end = std::min(end, have);
        stubLen = end > stubAt ? end - stubAt : 0;
    }
    out.iface = firstUuid;

    // ---- what the session table knows ---------------------------------------------------------------------------------------
    const DceNote *note = nullptr;
    if (sessions && !cut && !malformed && (pduType == 0 || pduType == 2 || pduType == 3 || pduType == 11 || pduType == 12 || pduType == 14 || pduType == 15)) {
        const uint32_t number = static_cast<uint32_t>(pack.number);
        if (loadPass) {
            const std::string_view stub = stubLen ? std::string_view(reinterpret_cast<const char *>(bytes + stubAt), stubLen) : std::string_view();
            note = sessions->observeDceRpc(carrier.stream, number, carrier.seq, carrier.index, pdu, stub, pack.source, carrier.fallback);
        } else {
            note = sessions->dceRpcNote(number, carrier.seq, carrier.index);
        }
    }
    const bool interfaceBound = note && !note->iface.empty() && !(note->flags & DceNote::kAssumed);
    if (note && !note->iface.empty()) out.iface = note->iface;
    if (interfaceBound) summary += ", " + interfaceText(note->iface);
    if (trailerCaptured) summary += ", Auth: " + out.authService + " (" + authLevelName(authLevel) + ")";

    // ---- fragments ----------------------------------------------------------------------------------------------------------
    const bool fragmented = !(pfcFlags & kPfcFirst) || !(pfcFlags & kPfcLast);
    out.fragment = fragmented;
    if (fragmented) {
        summary += std::string(" [") + ((pfcFlags & kPfcFirst) ? "first fragment" : (pfcFlags & kPfcLast) ? "last fragment" : "middle fragment") + "]";
    }
    const DceMessage *message = nullptr;
    if (note && (note->flags & DceNote::kCompletes)) {
        message = sessions->dceRpcMessage(note->message);
        if (message && message->fragments > 1) {
            out.reassembled = true;
            summary += " [Reassembled: " + std::to_string(message->fragments) + " fragments, " + std::to_string(message->bytes) + " bytes]";
        }
    }

    // ---- the authentication credentials of the exchanges that set up the security context --------------------------------------
    const bool setup = pduType == 11 || pduType == 12 || pduType == 14 || pduType == 15 || pduType == 16;
    SecurityBlob blob;
    if (setup && trailerCaptured && (authType == 9 || authType == 10 || authType == 16) && trailerAt + 8 + authLen <= have) {
        blob = decodeSecurityBlob(ctx, bytes + trailerAt + 8, authLen, nullptr);
        if (blob.ok && !blob.summary.empty()) summary += ", " + blob.summary;
    }

    out.info = summary;
    if (ctx.wantFields()) {
        Field &root = ctx.addLayer("DCE/RPC (" + typeName + ")", o, have);
        root.add("Version: 5." + std::to_string(rpcMinor), o, 2);
        root.add("PDU Type: " + typeName + " (" + std::to_string(pduType) + ")", o + 2, 1);
        {
            Field &f = root.add("Flags: " + hexString(pfcFlags, 2) + ((pfcFlags & kPfcFirst) ? " First" : "") + ((pfcFlags & kPfcLast) ? " Last" : "") + ((pfcFlags & kPfcObjectUuid) ? " Object" : ""), o + 3, 1);
            f.add(std::string("First Fragment: ") + ((pfcFlags & kPfcFirst) ? "Set" : "Not set"), o + 3, 1);
            f.add(std::string("Last Fragment: ") + ((pfcFlags & kPfcLast) ? "Set" : "Not set"), o + 3, 1);
        }
        root.add(std::string("Data Representation: ") + (le ? "little-endian" : "big-endian") + " (" + hexString(bytes[4], 2) + ")", o + 4, 4);
        root.add("Frag Length: " + std::to_string(fragLen), o + 8, 2);
        if (authLen > 0) root.add("Auth Length: " + std::to_string(authLen), o + 10, 2);
        root.add("Call ID: " + std::to_string(callId), o + 12, 4);
        for (const auto &it: items) {
            if (it.second.first <= length) node(root, it.first, it.second.first, it.second.second);
        }
        if (note) {   // what the earlier packets decided
            if (!note->iface.empty()) {
                root.add("[Interface: " + interfaceText(note->iface) + (note->ifVersion ? " v" + versionText(note->ifVersion) : std::string()) +
                         ((note->flags & DceNote::kAssumed) ? " (assumed from the endpoint, no Bind)" : "") + "]");
            }
            if (note->flags & DceNote::kUnknownContext) root.add("[Context " + std::to_string(pdu.contextId) + " was not accepted by a Bind in the capture]");
            if (note->flags & DceNote::kMatched) {
                root.add("[Request in frame " + std::to_string(note->requestPacket) + "]");
                if (pduType != 0) root.add("[Operation of the request: " + std::to_string(note->opnum) + "]");
            }
            if (note->flags & DceNote::kMissingStart) root.add("[The first fragment of this call was not captured: it is not reassembled]");
            if (note->flags & DceNote::kCompletedLater) root.add("[Reassembled in frame " + std::to_string(note->completedIn) + "]");
            if (message && message->fragments > 1) {
                std::string frames;
                for (uint32_t p: message->packets) frames += (frames.empty() ? "#" : ", #") + std::to_string(p);
                root.add("[Reassembled stub data: " + std::to_string(message->bytes) + " bytes in " + std::to_string(message->fragments) + " fragments, frames " + frames + "]");
            }
            if (message && message->epm) {
                Field &epm = root.add("Endpoint mapper answer: " + std::to_string(message->towers.size()) + " tower(s)");
                for (const DceTower &t: message->towers) {
                    std::string text = interfaceText(t.uuid) + " v" + versionText(t.version) + ": " + (t.protocol.empty() ? std::string("unknown protocol") : t.protocol);
                    if (t.port) text += " " + (t.host.empty() ? std::string("*") : t.host) + ":" + std::to_string(t.port);
                    else if (!t.address.empty()) text += " " + t.address;
                    epm.add(text);
                }
            }
        } else if (sessions && sessions->isTableStateLost("dcerpc")) {
            root.add("[DCE/RPC session state lost: the interface and fragments of this PDU are not known]");
        }
        if (stubLen > 0) node(root, "Stub data (" + std::to_string(stubLen) + " bytes" + (out.sealed ? ", sealed: packet privacy, not interpreted" : "") + ")", stubAt, stubLen);
        if (trailerAt != 0) {
            if (authPad > 0 && trailerAt >= authPad) node(root, "Auth Padding (" + std::to_string(authPad) + " bytes)", trailerAt - authPad, authPad);
            if (trailerCaptured) {
                Field &a = node(root, "Auth Verifier: " + out.authService + ", " + authLevelName(authLevel) + (out.sealed ? " [stub data sealed]" : ""), trailerAt, 8u + authLen);
                node(a, "Auth Type: " + out.authService + " (" + std::to_string(authType) + ")", trailerAt, 1);
                node(a, "Auth Level: " + authLevelName(authLevel) + " (" + std::to_string(authLevel) + ")", trailerAt + 1, 1);
                node(a, "Auth Pad Length: " + std::to_string(authPad), trailerAt + 2, 1);
                node(a, "Auth Context ID: " + std::to_string(authCtx), trailerAt + 4, 4);
                const size_t credAt = trailerAt + 8;
                if (setup && blob.ok) {
                    Field &c = node(a, "Auth Credentials (" + std::to_string(authLen) + " bytes): security token", credAt, authLen);
                    if (credAt + authLen <= have) decodeSecurityBlob(ctx, bytes + credAt, authLen, &c);
                } else if (setup) {
                    node(a, "Auth Credentials (" + std::to_string(authLen) + " bytes): " + out.authService + " token, not interpreted", credAt, authLen);
                } else {
                    node(a, "Auth Verifier Data (" + std::to_string(authLen) + " bytes): " + std::string(authLevel >= 5 ? "signature" : "checksum") + ", not interpreted", credAt, authLen);
                }
            } else {
                node(root, "Auth Verifier (" + std::to_string(authLen) + " bytes, cut)", trailerAt, authLen + 8u);
            }
        }
    }
    out.malformed = fragLen < 16 ? "DCE/RPC fragment length below the 16 byte header" : malformed;
    return true;
}

// the interface to assume for a TCP connection that has no accepted Bind in the capture: the endpoint mapper's well known port, else
// the interface the endpoint mapper announced for the server's port
std::string assumedInterface(const Context &ctx) {
    const auto &p = ctx.pack;
    if (p.src_port == 135 || p.dst_port == 135) return kDceEpmUuid;
    if (!ctx.sessions) return {};
    const uint32_t number = static_cast<uint32_t>(p.number);
    if (const DceMappedEndpoint *e = ctx.sessions->dceRpcEndpoint(p.destination, p.dst_port, false, number)) return e->uuid;
    if (const DceMappedEndpoint *e = ctx.sessions->dceRpcEndpoint(p.source, p.src_port, false, number)) return e->uuid;
    return {};
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
    auto &pack = ctx.pack;
    Carrier carrier;
    carrier.stream = smb2ConnectionKey(pack.source, pack.src_port, pack.destination, pack.dst_port);
    carrier.seq = ctx.tcpStreamSeq;
    carrier.fallback = assumedInterface(ctx);
    Decoded d;
    // the packet is named before the body is decoded: a malformed PDU keeps the name
    if (!data || length < 16 || static_cast<uint8_t>(data[0]) != 5) return;
    pack.protocol = "DCERPC";
    if (!decodeConnectionOriented(ctx, data, length, carrier, d)) return;
    pack.app_type = d.type;
    pack.app_stream = d.callId;
    if (d.request) pack.app_code = d.opnum;
    pack.app_flags = static_cast<uint16_t>((d.request ? kDceFlagOpnum : 0) | (static_cast<uint16_t>(d.authLevel & 7) << kDceAuthShift) | (d.sealed ? kDceFlagSealed : 0) |
                                           (d.reassembled ? kDceFlagReassembled : 0) | (d.fragment ? kDceFlagFragment : 0));
    pack.app_text = d.iface;
    pack.app_text2 = d.authService;
    pack.info = d.info;
    if (d.malformed) ctx.markMalformed(d.malformed);   // after the summary: it replaces it
}

} // namespace dissect
