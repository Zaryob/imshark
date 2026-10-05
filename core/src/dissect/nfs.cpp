// ONC RPC (RFC 5531) with the programs NFS (RFC 1813 v3, RFC 7530 / 5661 v4), Portmap / rpcbind (RFC 1833) and Mount (RFC 1813
// appendix I). TCP carries the record marking of RFC 5531 section 11 (bit 31 = last fragment, 31 bit fragment length); UDP does not.
//
// This file is the RPC layer: record marking, the call header with its credential (AUTH_SYS machine / uid / gid; RPCSEC_GSS and the
// other flavors are only named), the reply status (accepted / denied with the reason), and what the session table (onc_rpc_session.h)
// knows: the fragments of a record are joined, a reply is shown with the program and procedure of its call (xid matching), a call seen
// again is a retransmission. The programs' own arguments and results are decoded in nfs3.cpp, nfs4.cpp and rpc_programs.cpp
// (nfs_decode.h is the interface).
#include "nfs.h"

#include <algorithm>
#include <string>
#include <vector>

#include "nfs_decode.h"
#include "session.h"
#include "util.h"
#include "xdr.h"

using packet::Field;

namespace dissect {

namespace {

constexpr size_t kMaxRecord = 8u << 20;   // not more than the stream table buffers

// PacketInfo::app_flags of an ONC RPC message (the version of the program is kept in bits 8..15)
constexpr uint16_t kFlagReply = 1, kFlagDenied = 2, kFlagMatched = 4, kFlagRepeat = 8, kFlagReassembled = 16, kFlagFragment = 32, kFlagResult = 64;
constexpr int kVersionShift = 8;

const char *authFlavorName(uint32_t f) {
    switch (f) {
        case 0: return "AUTH_NULL";
        case 1: return "AUTH_SYS";
        case 2: return "AUTH_SHORT";
        case 3: return "AUTH_DH";
        case 6: return "RPCSEC_GSS";
        default: return "unknown flavor";
    }
}

const char *acceptStatName(uint32_t s) {
    switch (s) {
        case 0: return "SUCCESS";
        case 1: return "PROG_UNAVAIL";
        case 2: return "PROG_MISMATCH";
        case 3: return "PROC_UNAVAIL";
        case 4: return "GARBAGE_ARGS";
        case 5: return "SYSTEM_ERR";
        default: return "accept_stat ?";
    }
}

const char *authStatName(uint32_t s) {
    switch (s) {
        case 0: return "AUTH_OK";
        case 1: return "AUTH_BADCRED";
        case 2: return "AUTH_REJECTEDCRED";
        case 3: return "AUTH_BADVERF";
        case 4: return "AUTH_REJECTEDVERF";
        case 5: return "AUTH_TOOWEAK";
        case 6: return "AUTH_INVALIDRESP";
        case 7: return "AUTH_FAILED";
        default: return "auth_stat ?";
    }
}

// the program (and protocol name) of a call, or of the call a reply answers
struct Program {
    std::string protocol, name, proc;
};

Program programOf(uint32_t prog, uint32_t vers, uint32_t proc) {
    Program p;
    const char *progName = rpcdec::rpcProgramName(prog);
    p.name = progName ? progName : "Prog " + std::to_string(prog);
    if (prog == kRpcProgNfs) {
        p.proc = vers == 4 ? rpcdec::nfs4ProcName(proc) : vers == 3 ? rpcdec::nfs3ProcName(proc) : "PROC " + std::to_string(proc);
        p.protocol = vers == 4 ? "NFSv4" : "NFS";
    } else if (prog == kRpcProgPortmap) {
        p.proc = rpcdec::portmapProcName(vers, proc);
        p.protocol = "Portmap";
    } else if (prog == kRpcProgMount) {
        p.proc = rpcdec::mountProcName(proc);
        p.protocol = "Mount";
    } else {
        p.proc = "PROC " + std::to_string(proc);
        p.protocol = "RPC";
    }
    return p;
}

// one decoded message (a datagram, a record of one fragment, or a record joined from several)
struct Decoded {
    bool named = false;               // the protocol and summary are set
    bool call = false, reply = false;
    uint32_t xid = 0, prog = 0, vers = 0, proc = 0;
    std::string protocol, summary, layerName;
    std::vector<rpcdec::Item> items;  // the lines of the header, then the program's lines (Out::items)
    rpcdec::Out out;
    RpcMessage msg;
    uint16_t flags = 0, type = 0, code = 0;
    const char *malformed = nullptr;
    bool notAMessage = false;         // not the first fragment of a record: its bytes are the middle of a message
    // positions (in the message body) where the program's arguments / results start; 0 if they are not readable
    size_t argsAt = 0, resultAt = 0;
    bool accepted = false;
    std::string tail;                 // the part of a reply's summary that follows "(XID: ...)": " Accepted SUCCESS", " Denied ..."
};

// the header of one message; `complete`: every byte of it is here (a body that does not decode is malformed, not cut)
void decodeHeader(const uint8_t *bytes, size_t bodyLen, bool complete, Decoded &d) {
    XdrReader r(bytes, bodyLen);
    d.xid = r.readUnsignedInt();
    const uint32_t mtype = r.readUnsignedInt();   // 0 = CALL, 1 = REPLY
    auto add = [&](const std::string &t, size_t at, size_t len) { d.items.push_back({t, at, len, 0}); };

    if (mtype == 0) { // RPC CALL
        d.call = true;
        const uint32_t rpcvers = r.readUnsignedInt(), prog = r.readUnsignedInt(), vers = r.readUnsignedInt(), proc = r.readUnsignedInt();
        d.protocol = "RPC";
        if (!r.ok()) {
            d.summary = "RPC Call (XID: " + hexString(d.xid, 8) + ") [cut]";
            if (complete) d.malformed = "RPC call header shorter than its fixed fields";
            d.call = false;
            d.named = true;
            return;
        }
        d.prog = prog; d.vers = vers; d.proc = proc;
        const Program pr = programOf(prog, vers, proc);
        d.protocol = pr.protocol;
        d.type = static_cast<uint16_t>(proc);
        d.code = static_cast<uint16_t>(vers);
        d.flags = static_cast<uint16_t>(std::min<uint32_t>(vers, 255) << kVersionShift);
        d.summary = pr.name + " v" + std::to_string(vers) + " " + pr.proc + " Call (XID: " + hexString(d.xid, 8) + ")";
        d.layerName = "Remote Procedure Call (Call " + pr.name + ")";
        d.named = true;
        add("XID: " + hexString(d.xid, 8), 0, 4);
        add("Type: Call (0)", 4, 4);
        add("RPC Version: " + std::to_string(rpcvers), 8, 4);
        add("Program: " + pr.name + " (" + std::to_string(prog) + ")", 12, 4);
        add("Program Version: " + std::to_string(vers), 16, 4);
        add("Procedure: " + pr.proc + " (" + std::to_string(proc) + ")", 20, 4);
        d.msg.call = true; d.msg.xid = d.xid; d.msg.prog = prog; d.msg.vers = vers; d.msg.proc = proc;

        // credential and verifier: flavor, opaque body (<= 400 bytes, RFC 5531 8.2)
        bool credOk = true;
        for (int which = 0; which < 2 && r.ok(); ++which) {
            const size_t at = r.pos();
            const uint32_t flavor = r.readUnsignedInt();
            const uint32_t len = r.readUnsignedInt();
            if (!r.ok() || len > 400 || len > r.remaining()) { credOk = false; if (complete) d.malformed = "RPC credential / verifier length does not fit"; break; }
            const size_t bodyAt = r.pos();
            if (which == 0 && flavor == 1 && len >= 20) { // AUTH_SYS: stamp, machinename, uid, gid, gids
                XdrReader c(bytes + bodyAt, len);
                c.readUnsignedInt();
                const std::string machine = c.readString(255);
                const uint32_t uid = c.readUnsignedInt(), gid = c.readUnsignedInt();
                if (c.ok()) add("Credential: AUTH_SYS machine=" + rpcdec::text(machine, 63) + " uid=" + std::to_string(uid) + " gid=" + std::to_string(gid), at, 8 + len);
                else add(std::string("Credential: ") + authFlavorName(flavor), at, 8 + len);
            } else {
                add(std::string(which == 0 ? "Credential: " : "Verifier: ") + authFlavorName(flavor), at, 8 + len);
            }
            r.readFixedOpaque(len);
        }
        if (credOk && r.ok()) d.argsAt = r.pos();
        return;
    }
    if (mtype == 1) { // RPC REPLY
        d.reply = true;
        d.protocol = "RPC";
        const uint32_t replyStat = r.readUnsignedInt();   // 0 = MSG_ACCEPTED, 1 = MSG_DENIED
        if (!r.ok()) {
            d.summary = "RPC Reply (XID: " + hexString(d.xid, 8) + ") [cut]";
            if (complete) d.malformed = "RPC reply without a reply status";
            d.reply = false;
            d.named = true;
            return;
        }
        d.flags = kFlagReply;
        d.msg.xid = d.xid;
        d.summary = "RPC Reply (XID: " + hexString(d.xid, 8) + ")";
        d.layerName = "Remote Procedure Call (Reply)";
        d.named = true;
        add("XID: " + hexString(d.xid, 8), 0, 4);
        add("Type: Reply (1)", 4, 4);
        add(std::string("Reply Status: ") + (replyStat == 0 ? "Accepted (0)" : "Denied (1)"), 8, 4);
        if (replyStat == 0) {
            d.tail = " Accepted";
            d.accepted = true;
            // verifier (flavor, opaque), accept_stat, [mismatch: low, high]
            r.readUnsignedInt();
            const uint32_t vlen = r.readUnsignedInt();
            if (r.ok() && vlen <= 400 && vlen <= r.remaining()) {
                r.readFixedOpaque(vlen);
                const size_t at = r.pos();
                const uint32_t stat = r.readUnsignedInt();
                if (r.ok()) {
                    d.code = static_cast<uint16_t>(stat);
                    d.tail += std::string(" ") + acceptStatName(stat);
                    add(std::string("Accept State: ") + acceptStatName(stat) + " (" + std::to_string(stat) + ")", at, 4);
                    if (stat == 0) {
                        d.resultAt = r.pos();
                    } else if (stat == 2) {
                        const uint32_t low = r.readUnsignedInt(), high = r.readUnsignedInt();
                        if (r.ok()) { d.tail += " (versions " + std::to_string(low) + "-" + std::to_string(high) + ")"; add("Supported Versions: " + std::to_string(low) + " - " + std::to_string(high), at + 4, 8); }
                    }
                }
            }
        } else {
            d.flags |= kFlagDenied;
            d.tail = " Denied";
            const size_t at = r.pos();
            const uint32_t rejectStat = r.readUnsignedInt();   // 0 = RPC_MISMATCH, 1 = AUTH_ERROR
            if (r.ok() && rejectStat == 0) {
                const uint32_t low = r.readUnsignedInt(), high = r.readUnsignedInt();
                if (r.ok()) { d.tail += " RPC_MISMATCH (versions " + std::to_string(low) + "-" + std::to_string(high) + ")"; add("Reject State: RPC_MISMATCH", at, 4); }
            } else if (r.ok() && rejectStat == 1) {
                const uint32_t auth = r.readUnsignedInt();
                if (r.ok()) {
                    d.code = static_cast<uint16_t>(auth);
                    d.tail += std::string(" AUTH_ERROR ") + authStatName(auth);
                    add(std::string("Auth Error: ") + authStatName(auth) + " (" + std::to_string(auth) + ")", at + 4, 4);
                }
            }
        }
        d.summary += d.tail;
        return;
    }
    d.notAMessage = true;
}

// the arguments of a call, by program
void decodeArguments(const uint8_t *bytes, size_t bodyLen, Decoded &d) {
    rpcdec::Cursor a(bytes + d.argsAt, bodyLen - d.argsAt, d.argsAt);
    if (d.prog == kRpcProgNfs && d.vers == 3) rpcdec::nfs3Call(d.proc, a, d.out);
    else if (d.prog == kRpcProgNfs && d.vers == 4) rpcdec::nfs4Call(d.proc, a, d.out);
    else if (d.prog == kRpcProgPortmap) rpcdec::portmapCall(d.vers, d.proc, a, d.out, d.msg);
    else if (d.prog == kRpcProgMount) rpcdec::mountCall(d.proc, a, d.out);
}

// the results of a reply to a call the table matched, by program
void decodeResults(const uint8_t *bytes, size_t bodyLen, const RpcNote &call, size_t resultAt, Decoded &d) {
    rpcdec::Cursor a(bytes + resultAt, bodyLen - resultAt, resultAt);
    if (call.prog == kRpcProgNfs && call.vers == 3) rpcdec::nfs3Reply(call.proc, a, d.out);
    else if (call.prog == kRpcProgPortmap) rpcdec::portmapReply(call, a, d.out);
    else if (call.prog == kRpcProgMount) rpcdec::mountReply(call.vers, call.proc, a, d.out);
}

} // namespace

namespace rpcdec {

const char *rpcProgramName(uint32_t prog) {
    switch (prog) {
        case 100000: return "Portmap";
        case 100003: return "NFS";
        case 100005: return "Mount";
        case 100021: return "NLM (Network Lock Manager)";
        case 100024: return "NSM (Network Status Monitor)";
        default: return nullptr;
    }
}

} // namespace rpcdec

StreamFrame frameRpc(const char *data, size_t length) {
    if (length < 4) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    // RFC 5531 11: bit 31 = last fragment, bits 0..30 = fragment length
    const uint32_t rm = (static_cast<uint32_t>(bytes[0]) << 24) | (static_cast<uint32_t>(bytes[1]) << 16) | (static_cast<uint32_t>(bytes[2]) << 8) | bytes[3];
    const size_t fragLen = rm & 0x7FFFFFFFu;
    if (fragLen == 0 || 4 + fragLen > kMaxRecord) return StreamFrame{StreamFrame::Kind::Reject, 0};
    // the first fragment of a record starts with xid, msg_type (0 call, 1 reply) and, for a call, rpcvers 2
    if (length >= 12 && fragLen >= 8 && be32(data + 8) > 1) return StreamFrame{StreamFrame::Kind::Reject, 0};
    if (length >= 20 && fragLen >= 16 && be32(data + 8) == 0 && be32(data + 12) != 2) return StreamFrame{StreamFrame::Kind::Reject, 0};
    const size_t total = 4 + fragLen;
    StreamFrame f{length < total ? StreamFrame::Kind::NeedMore : StreamFrame::Kind::Complete, total};
    f.continues = (rm & 0x80000000u) == 0;
    return f;
}

StreamFrame frameRpcContinuation(const char *data, size_t length) {
    if (length < 4) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const uint32_t rm = be32(data);
    const size_t fragLen = rm & 0x7FFFFFFFu;
    if (fragLen == 0 || 4 + fragLen > kMaxRecord) return StreamFrame{StreamFrame::Kind::Reject, 0};
    const size_t total = 4 + fragLen;
    StreamFrame f{length < total ? StreamFrame::Kind::NeedMore : StreamFrame::Kind::Complete, total};
    f.continues = (rm & 0x80000000u) == 0;
    return f;
}

void dissectNfs(Context &ctx, const char *data, size_t length) {
    if (!data || length < 8) return;
    auto &pack = ctx.pack;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    const size_t o = ctx.offsetOf(data);

    // record marking: TCP only
    size_t offset = 0;
    size_t fragLen = length;
    bool lastFragment = true;
    bool complete = true;   // every byte of the fragment (TCP) or datagram (UDP) is here: a body that does not decode is malformed, not cut
    const bool tcp = pack.ip_protocol == 6 && length >= 4;
    if (tcp) {
        const uint32_t rm = be32(data);
        fragLen = rm & 0x7FFFFFFFu;
        lastFragment = (rm & 0x80000000u) != 0;
        complete = fragLen + 4 <= length;
        offset = 4;
        if (!complete) fragLen = length - 4;
    }
    const size_t bodyLen = tcp ? fragLen : length;   // this fragment's bytes (the datagram's)
    if (bodyLen < 8) {
        if (complete) { pack.protocol = "RPC"; pack.info = "RPC"; ctx.markMalformed("RPC message shorter than xid and message type"); }
        return;
    }
    const uint8_t *body = bytes + offset;

    // ---- what the session table knows about this fragment ------------------------------------------------------------------
    SessionTables *sessions = ctx.sessions;
    const uint32_t number = static_cast<uint32_t>(pack.number);
    const bool loadPass = ctx.mode != ParseMode::Replay && sessions && !sessions->isFrozen();
    const RpcNote *note = nullptr;
    if (sessions && complete) {
        if (loadPass) {
            const std::string stream = tcp ? pack.source + ":" + std::to_string(pack.src_port) + ">" + pack.destination + ":" + std::to_string(pack.dst_port) : std::string();
            const uint32_t endSeq = static_cast<uint32_t>(ctx.tcpStreamSeq) + 4 + static_cast<uint32_t>(bodyLen);
            note = sessions->observeRpcFragment(stream, number, tcp ? ctx.tcpStreamSeq : -1, std::string_view(reinterpret_cast<const char *>(body), bodyLen), lastFragment, endSeq);
        } else {
            note = sessions->rpcNote(number, tcp ? ctx.tcpStreamSeq : -1);
        }
    }
    const bool multi = note && (note->flags & RpcNote::kFragment);
    const bool middle = multi && !(note->flags & RpcNote::kCompletes);   // a fragment that does not end its record
    const bool continuation = multi && (note->flags & RpcNote::kContinuation);

    // the bytes of the message this packet decodes: the fragment, or the whole record when this fragment ends it
    const uint8_t *msg = body;
    size_t msgLen = bodyLen;
    bool msgComplete = complete && lastFragment;   // the first fragment of a longer record is not the whole message
    const RpcRecord *record = nullptr;
    size_t lastStart = 0;
    if (multi && !middle) {
        record = note->fragments > 1 ? sessions->rpcRecord(note->record) : nullptr;
        if (record) {
            msg = reinterpret_cast<const uint8_t *>(record->bytes.data());
            msgLen = record->bytes.size();
            msgComplete = complete && record->bytes.size() == record->total;
            lastStart = std::min<size_t>(record->lastStart, msgLen);
        }
    }

    Decoded d;
    std::string recordNote;
    if (continuation && (middle || !record)) {
        d.notAMessage = true;   // the middle of a record (or its end, which the table could not keep)
    } else {
        decodeHeader(msg, msgLen, msgComplete, d);
    }

    if (d.notAMessage && !tcp) return;   // a datagram is not a record fragment: not RPC (UDP names it)
    if (d.notAMessage) {
        // not the first fragment of a record: its bytes are the middle of a message
        pack.protocol = "RPC";
        pack.info = "RPC record fragment (" + std::to_string(bodyLen) + " bytes)";
        if (multi) pack.app_flags = kFlagFragment;
        if (ctx.wantFields()) {
            Field &root = ctx.addLayer("Remote Procedure Call (record fragment)", o + offset, bodyLen);
            if (offset) root.add(std::string("Record Mark: ") + (lastFragment ? "last fragment, " : "more fragments, ") + std::to_string(be32(data) & 0x7FFFFFFFu) + " bytes", o, 4);
        }
        return;
    }

    pack.protocol = d.protocol;
    pack.app_stream = d.xid;
    pack.app_flags = d.flags;
    pack.app_type = d.type;
    pack.app_code = d.code;
    if (d.call) pack.app_text = std::to_string(d.prog);

    // ---- the program's arguments, then what the table knows about the call or reply ------------------------------------------
    const bool wholeMessage = !middle;   // the first fragment of a longer record shows what it has but registers nothing
    if (d.call && d.argsAt) {
        decodeArguments(msg, msgLen, d);
        pack.app_text2 = d.out.name.empty() ? d.out.ops : d.out.name;
    }
    const RpcNote *msgNote = nullptr;
    std::string repeated;   // " [Retransmission of #n]" / " [Duplicate reply]"
    if (sessions && wholeMessage && msgComplete && (d.call || d.reply)) {
        if (loadPass) {
            bool fromLow = false;
            const std::string conversation = rpcConversationKey(pack.source, pack.src_port, pack.destination, pack.dst_port, fromLow);
            msgNote = sessions->observeRpcMessage(conversation, fromLow, number, tcp ? ctx.tcpStreamSeq : -1, d.msg);
        } else {
            msgNote = note;
        }
    }
    if (msgNote && (msgNote->flags & RpcNote::kMatched)) {
        if (d.reply) {
            const Program pr = programOf(msgNote->prog, msgNote->vers, msgNote->proc);
            d.prog = msgNote->prog; d.vers = msgNote->vers; d.proc = msgNote->proc;
            d.protocol = pr.protocol;
            pack.protocol = pr.protocol;
            pack.app_type = static_cast<uint16_t>(msgNote->proc);
            pack.app_text = std::to_string(msgNote->prog);
            pack.app_flags = static_cast<uint16_t>(d.flags | kFlagMatched | (std::min<uint32_t>(msgNote->vers, 255) << kVersionShift) | ((msgNote->flags & RpcNote::kDuplicateReply) ? kFlagRepeat : 0));
            if (d.resultAt) decodeResults(msg, msgLen, *msgNote, d.resultAt, d);
            if (d.out.hasResult) {
                pack.app_flags |= kFlagResult;
                pack.app_code = static_cast<uint16_t>(std::min<uint32_t>(d.out.result, 0xFFFF));
                if (loadPass && !d.out.mappings.empty()) sessions->learnRpcPorts(number, pack.source, d.out.mappings);
            }
            if (!d.out.ops.empty()) pack.app_text2 = d.out.ops;
            // a decoded result says more than "Accepted SUCCESS"
            const bool decoded = d.out.hasResult || !d.out.info.empty();
            d.summary = pr.name + " v" + std::to_string(msgNote->vers) + " " + pr.proc + " Reply (XID: " + hexString(d.xid, 8) + ")" + (decoded ? std::string() : d.tail);
            d.layerName = "Remote Procedure Call (Reply " + pr.name + ")";
            if (msgNote->flags & RpcNote::kDuplicateReply) repeated = " [Duplicate reply]";
        } else if (msgNote->flags & RpcNote::kRetransmission) {
            pack.app_flags = static_cast<uint16_t>(d.flags | kFlagRepeat);
            repeated = " [Retransmission of #" + std::to_string(msgNote->callPacket) + "]";
        }
    }
    if (!d.out.info.empty()) d.summary += ", " + d.out.info;
    d.summary += repeated;

    if (!lastFragment && tcp && !record) {
        d.summary += " [not the last fragment of the record]";
        pack.app_flags |= kFlagFragment;
    }
    if (record) {
        pack.app_flags |= kFlagReassembled;
        d.summary += " [Reassembled: " + std::to_string(record->fragments) + " fragments, " + std::to_string(record->total) + " bytes]";
    }
    pack.info = d.summary;

    if (ctx.wantFields()) {
        Field &root = ctx.addLayer(d.layerName, o + offset, bodyLen);
        if (offset) root.add(std::string("Record Mark: ") + (lastFragment ? "last fragment, " : "more fragments, ") + std::to_string(be32(data) & 0x7FFFFFFFu) + " bytes", o, 4);
        if (record) {
            Field &rf = root.add("Reassembled record: " + std::to_string(record->fragments) + " fragments, " + std::to_string(record->total) + " bytes", o + offset, 0);
            for (const uint32_t p: record->packets) rf.add("Fragment in frame " + std::to_string(p), o + offset, 0);
        }
        if (msgNote && (msgNote->flags & RpcNote::kMatched)) {
            if (d.reply) root.add("Call in frame " + std::to_string(msgNote->callPacket), o + offset, 0);
            else root.add("Retransmission of the call in frame " + std::to_string(msgNote->callPacket), o + offset, 0);
        } else if (msgNote && d.call && msgNote->replyPacket) {
            root.add("Reply in frame " + std::to_string(msgNote->replyPacket), o + offset, 0);
        }
        // the lines: header first, then the program's. A line inside the part of a record that came in an earlier fragment
        // has no bytes in this frame: it points at the start of the layer with no length.
        std::vector<Field *> stack{&root};
        const auto emit = [&](const rpcdec::Item &it) {
            size_t at, len;
            if (record && it.at < lastStart) { at = o + offset; len = 0; }
            else {
                const size_t rel = it.at - (record ? lastStart : 0);
                at = o + offset + rel;
                len = it.len;
            }
            if (at > o + length) at = o + length;
            len = std::min(len, o + length - at);
            const size_t depth = std::min<size_t>(static_cast<size_t>(it.depth), stack.size() - 1);
            Field &f = stack[depth]->add(it.text, at, len);
            stack.resize(depth + 1);
            stack.push_back(&f);
        };
        for (const auto &it: d.items) emit(it);
        for (const auto &it: d.out.items) emit(it);
    }
    if (d.malformed) ctx.markMalformed(d.malformed);   // after the summary: it replaces it
}

} // namespace dissect
