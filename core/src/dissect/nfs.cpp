// ONC RPC (RFC 5531) with the programs NFS (RFC 1813 v3, RFC 7530 v4), Portmap (RFC 1833), Mount (RFC 1813 appendix I).
// TCP carries the record marking of RFC 5531 section 11 (bit 31 = last fragment, 31 bit fragment length); UDP does not. Decoded: the
// call header with its credential (AUTH_SYS machine / uid / gid), reply status (accepted / denied with the reason), the NFS v3 arguments
// that name something (file handle, file name, offset and count), the first operation of an NFS v4 COMPOUND, the Portmap and Mount
// arguments. Not decoded: matching replies to their calls (a reply shows its status only), the results of any procedure, records of
// several fragments (every fragment is shown on its own).
#include "nfs.h"

#include <string>
#include <vector>

#include "util.h"
#include "xdr.h"

using packet::Field;

namespace dissect {

namespace {

constexpr size_t kMaxRecord = 8u << 20;   // not more than the stream table buffers

// app_flags
constexpr uint16_t kFlagReply = 1, kFlagDenied = 2;

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

const char *nfs3ProcName(uint32_t proc) {
    static const char *const names[] = {"NULL", "GETATTR", "SETATTR", "LOOKUP", "ACCESS", "READLINK", "READ", "WRITE", "CREATE", "MKDIR", "SYMLINK",
                                        "MKNOD", "REMOVE", "RMDIR", "RENAME", "LINK", "READDIR", "READDIRPLUS", "FSSTAT", "FSINFO", "PATHCONF", "COMMIT"};
    return proc < 22 ? names[proc] : "PROC";
}

const char *nfs4ProcName(uint32_t proc) {
    switch (proc) {
        case 0: return "NULL";
        case 1: return "COMPOUND";
        default: return "PROC";
    }
}

const char *portmapProcName(uint32_t proc) {
    switch (proc) {
        case 0: return "NULL";
        case 1: return "SET";
        case 2: return "UNSET";
        case 3: return "GETPORT";
        case 4: return "DUMP";
        case 5: return "CALLIT";
        default: return "PROC";
    }
}

const char *mountProcName(uint32_t proc) {
    switch (proc) {
        case 0: return "NULL";
        case 1: return "MNT";
        case 2: return "DUMP";
        case 3: return "UMNT";
        case 4: return "UMNTALL";
        case 5: return "EXPORT";
        default: return "PROC";
    }
}

// NFS v4 operation numbers (RFC 7530 16, RFC 5661 18)
const char *nfs4OpName(uint32_t op) {
    switch (op) {
        case 3: return "ACCESS"; case 4: return "CLOSE"; case 5: return "COMMIT"; case 6: return "CREATE"; case 7: return "DELEGPURGE";
        case 8: return "DELEGRETURN"; case 9: return "GETATTR"; case 10: return "GETFH"; case 11: return "LINK"; case 12: return "LOCK";
        case 13: return "LOCKT"; case 14: return "LOCKU"; case 15: return "LOOKUP"; case 16: return "LOOKUPP"; case 17: return "NVERIFY";
        case 18: return "OPEN"; case 19: return "OPENATTR"; case 20: return "OPEN_CONFIRM"; case 21: return "OPEN_DOWNGRADE";
        case 22: return "PUTFH"; case 23: return "PUTPUBFH"; case 24: return "PUTROOTFH"; case 25: return "READ"; case 26: return "READDIR";
        case 27: return "READLINK"; case 28: return "REMOVE"; case 29: return "RENAME"; case 30: return "RENEW"; case 31: return "RESTOREFH";
        case 32: return "SAVEFH"; case 33: return "SECINFO"; case 34: return "SETATTR"; case 35: return "SETCLIENTID";
        case 36: return "SETCLIENTID_CONFIRM"; case 37: return "VERIFY"; case 38: return "WRITE"; case 39: return "RELEASE_LOCKOWNER";
        case 40: return "BACKCHANNEL_CTL"; case 41: return "BIND_CONN_TO_SESSION"; case 42: return "EXCHANGE_ID"; case 43: return "CREATE_SESSION";
        case 44: return "DESTROY_SESSION"; case 45: return "FREE_STATEID"; case 46: return "GET_DIR_DELEGATION"; case 47: return "GETDEVICEINFO";
        case 48: return "GETDEVICELIST"; case 49: return "LAYOUTCOMMIT"; case 50: return "LAYOUTGET"; case 51: return "LAYOUTRETURN";
        case 52: return "SECINFO_NO_NAME"; case 53: return "SEQUENCE"; case 54: return "SET_SSV"; case 55: return "TEST_STATEID";
        case 56: return "WANT_DELEGATION"; case 57: return "DESTROY_CLIENTID"; case 58: return "RECLAIM_COMPLETE";
        default: return nullptr;
    }
}

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

std::string hexPreview(const uint8_t *p, size_t n, size_t max = 8) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < n && i < max; ++i) { out += digits[p[i] >> 4]; out += digits[p[i] & 15]; }
    if (n > max) out += "...";
    return out;
}

std::string text(const std::string &s, size_t max = 100) { return printableText(s.data(), s.size(), max); }

} // namespace

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
    return StreamFrame{length < total ? StreamFrame::Kind::NeedMore : StreamFrame::Kind::Complete, total};
}

void dissectNfs(Context &ctx, const char *data, size_t length) {
    if (!data || length < 8) return;
    auto &pack = ctx.pack;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    const size_t o = ctx.offsetOf(data);

    // record marking: TCP only
    size_t offset = 0;
    bool lastFragment = true;
    bool complete = true;   // every byte of the fragment (TCP) or datagram (UDP) is here: a body that does not decode is malformed, not cut
    if (pack.ip_protocol == 6 && length >= 4) {
        const uint32_t rm = be32(data);
        const size_t fragLen = rm & 0x7FFFFFFFu;
        lastFragment = (rm & 0x80000000u) != 0;
        complete = fragLen + 4 <= length;
        offset = 4;
    }
    const size_t bodyLen = length - offset;
    if (bodyLen < 8) {
        if (complete) { pack.protocol = "RPC"; pack.info = "RPC"; ctx.markMalformed("RPC message shorter than xid and message type"); }
        return;
    }

    XdrReader r(bytes + offset, bodyLen);
    const uint32_t xid = r.readUnsignedInt();
    const uint32_t mtype = r.readUnsignedInt();   // 0 = CALL, 1 = REPLY
    pack.app_stream = xid;
    std::vector<std::pair<std::string, std::pair<size_t, size_t>>> items;   // detail-tree children: text, offset, length
    auto add = [&](const std::string &t, size_t at, size_t len) { items.push_back({t, {o + offset + at, len}}); };
    std::string summary, layerName;
    const char *malformed = nullptr;

    if (mtype == 0) { // RPC CALL
        const uint32_t rpcvers = r.readUnsignedInt(), prog = r.readUnsignedInt(), vers = r.readUnsignedInt(), proc = r.readUnsignedInt();
        if (!r.ok()) {
            pack.protocol = "RPC";
            pack.info = "RPC Call (XID: " + hexString(xid, 8) + ") [cut]";
            if (complete) ctx.markMalformed("RPC call header shorter than its fixed fields");
            return;
        }
        const char *progName = rpcProgramName(prog);
        const std::string progStr = progName ? progName : "Prog " + std::to_string(prog);
        std::string procStr;
        if (prog == 100003) {
            procStr = vers == 4 ? nfs4ProcName(proc) : vers == 3 ? nfs3ProcName(proc) : "PROC " + std::to_string(proc);
            pack.protocol = vers == 4 ? "NFSv4" : "NFS";
        } else if (prog == 100000) {
            procStr = portmapProcName(proc);
            pack.protocol = "Portmap";
        } else if (prog == 100005) {
            procStr = mountProcName(proc);
            pack.protocol = "Mount";
        } else {
            procStr = "PROC " + std::to_string(proc);
            pack.protocol = "RPC";
        }
        pack.app_type = static_cast<uint16_t>(proc);
        pack.app_code = static_cast<uint16_t>(vers);
        pack.app_text = std::to_string(prog);
        summary = progStr + " v" + std::to_string(vers) + " " + procStr + " Call (XID: " + hexString(xid, 8) + ")";
        layerName = "Remote Procedure Call (Call " + progStr + ")";
        add("XID: " + hexString(xid, 8), 0, 4);
        add("Type: Call (0)", 4, 4);
        add("RPC Version: " + std::to_string(rpcvers), 8, 4);
        add("Program: " + progStr + " (" + std::to_string(prog) + ")", 12, 4);
        add("Program Version: " + std::to_string(vers), 16, 4);
        add("Procedure: " + procStr + " (" + std::to_string(proc) + ")", 20, 4);

        // credential and verifier: flavor, opaque body (<= 400 bytes, RFC 5531 8.2)
        bool credOk = true;
        for (int which = 0; which < 2 && r.ok(); ++which) {
            const size_t at = r.pos();
            const uint32_t flavor = r.readUnsignedInt();
            const uint32_t len = r.readUnsignedInt();
            if (!r.ok() || len > 400 || len > r.remaining()) { credOk = false; if (complete) malformed = "RPC credential / verifier length does not fit"; break; }
            const size_t bodyAt = r.pos();
            if (which == 0 && flavor == 1 && len >= 20) { // AUTH_SYS: stamp, machinename, uid, gid, gids
                XdrReader c(bytes + offset + bodyAt, len);
                c.readUnsignedInt();
                const std::string machine = c.readString(255);
                const uint32_t uid = c.readUnsignedInt(), gid = c.readUnsignedInt();
                if (c.ok()) add("Credential: AUTH_SYS machine=" + text(machine, 63) + " uid=" + std::to_string(uid) + " gid=" + std::to_string(gid), at, 8 + len);
                else add(std::string("Credential: ") + authFlavorName(flavor), at, 8 + len);
            } else {
                add(std::string(which == 0 ? "Credential: " : "Verifier: ") + authFlavorName(flavor), at, 8 + len);
            }
            r.readFixedOpaque(len);
        }

        // the arguments, only where they name something
        if (credOk && r.ok()) {
            const size_t argsAt = r.pos();
            auto fileHandle = [&](XdrReader &x, std::string &out) {
                const size_t at = x.pos();
                const auto fh = x.readOpaque(64);
                if (x.ok()) { out = hexPreview(fh.data(), fh.size()); add("File Handle: " + out + " (" + std::to_string(fh.size()) + " bytes)", at, 4 + fh.size()); }
                return x.ok();
            };
            std::string fh, name, extra;
            if (prog == 100003 && vers == 3 && proc >= 1 && proc <= 21) {
                XdrReader a(bytes + offset + argsAt, bodyLen - argsAt);
                if (fileHandle(a, fh)) {
                    extra = " fh=" + fh;
                    if (proc == 3 || proc == 8 || proc == 9 || proc == 12 || proc == 13) { // LOOKUP, CREATE, MKDIR, REMOVE, RMDIR: diropargs3
                        const size_t at = a.pos();
                        name = a.readString(255);
                        if (a.ok()) { extra += " name=" + text(name, 80); add("Name: " + text(name, 80), at, 4 + name.size()); }
                    } else if (proc == 6 || proc == 21) { // READ, COMMIT: offset, count
                        const size_t at = a.pos();
                        const uint64_t off = a.readUnsignedHyper();
                        const uint32_t count = a.readUnsignedInt();
                        if (a.ok()) { extra += " offset=" + std::to_string(off) + " count=" + std::to_string(count); add("Offset: " + std::to_string(off), at, 8); add("Count: " + std::to_string(count), at + 8, 4); }
                    } else if (proc == 7) { // WRITE: offset, count, stable
                        const size_t at = a.pos();
                        const uint64_t off = a.readUnsignedHyper();
                        const uint32_t count = a.readUnsignedInt();
                        if (a.ok()) { extra += " offset=" + std::to_string(off) + " count=" + std::to_string(count); add("Offset: " + std::to_string(off), at, 8); add("Count: " + std::to_string(count), at + 8, 4); }
                    }
                }
            } else if (prog == 100003 && vers == 4 && proc == 1) { // COMPOUND: tag, minorversion, operations (the first one is named)
                XdrReader a(bytes + offset + argsAt, bodyLen - argsAt);
                const std::string tag = a.readString(255);
                const uint32_t minor = a.readUnsignedInt(), nops = a.readUnsignedInt();
                if (a.ok()) {
                    extra = " minor=" + std::to_string(minor) + " ops=" + std::to_string(nops);
                    add("Tag: " + text(tag, 63), argsAt, 4);
                    add("Minor Version: " + std::to_string(minor), argsAt, 0);
                    add("Operations: " + std::to_string(nops), argsAt, 0);
                    if (nops > 0 && a.remaining() >= 4) {
                        const uint32_t op = a.readUnsignedInt();
                        const char *on = nfs4OpName(op);
                        extra += std::string(" first=") + (on ? on : "op " + std::to_string(op));
                        add(std::string("First Operation: ") + (on ? on : "unknown") + " (" + std::to_string(op) + ")", a.pos() - 4, 4);
                    }
                }
            } else if (prog == 100000 && (proc == 1 || proc == 2 || proc == 3)) { // SET, UNSET, GETPORT: mapping (prog, vers, prot, port)
                XdrReader a(bytes + offset + argsAt, bodyLen - argsAt);
                const uint32_t mprog = a.readUnsignedInt(), mvers = a.readUnsignedInt(), mprot = a.readUnsignedInt(), mport = a.readUnsignedInt();
                if (a.ok()) {
                    const char *pn = rpcProgramName(mprog);
                    extra = " prog=" + (pn ? std::string(pn) : std::to_string(mprog)) + " v" + std::to_string(mvers) + (mprot == 6 ? " tcp" : mprot == 17 ? " udp" : " proto " + std::to_string(mprot));
                    if (proc != 3 && mport) extra += " port=" + std::to_string(mport);
                    add("Mapping: program " + std::to_string(mprog) + " version " + std::to_string(mvers) + " protocol " + std::to_string(mprot) + " port " + std::to_string(mport), argsAt, 16);
                }
            } else if (prog == 100005 && (proc == 1 || proc == 3)) { // MNT, UMNT: dirpath
                XdrReader a(bytes + offset + argsAt, bodyLen - argsAt);
                const std::string path = a.readString(1024);
                if (a.ok()) { name = text(path, 120); extra = " path=" + name; add("Directory Path: " + name, argsAt, 4 + path.size()); }
            }
            if (!extra.empty()) summary += "," + extra;
            pack.app_text2 = name;
        }
    } else if (mtype == 1) { // RPC REPLY
        const uint32_t replyStat = r.readUnsignedInt();   // 0 = MSG_ACCEPTED, 1 = MSG_DENIED
        if (!r.ok()) {
            pack.protocol = "RPC";
            pack.info = "RPC Reply (XID: " + hexString(xid, 8) + ") [cut]";
            if (complete) ctx.markMalformed("RPC reply without a reply status");
            return;
        }
        pack.protocol = "RPC";
        pack.app_flags |= kFlagReply;
        summary = "RPC Reply (XID: " + hexString(xid, 8) + ")";
        layerName = "Remote Procedure Call (Reply)";
        add("XID: " + hexString(xid, 8), 0, 4);
        add("Type: Reply (1)", 4, 4);
        add(std::string("Reply Status: ") + (replyStat == 0 ? "Accepted (0)" : "Denied (1)"), 8, 4);
        if (replyStat == 0) {
            summary += " Accepted";
            // verifier (flavor, opaque), accept_stat, [mismatch: low, high]
            r.readUnsignedInt();
            const uint32_t vlen = r.readUnsignedInt();
            if (r.ok() && vlen <= 400 && vlen <= r.remaining()) {
                r.readFixedOpaque(vlen);
                const size_t at = r.pos();
                const uint32_t stat = r.readUnsignedInt();
                if (r.ok()) {
                    pack.app_code = static_cast<uint16_t>(stat);
                    summary += std::string(" ") + acceptStatName(stat);
                    add(std::string("Accept State: ") + acceptStatName(stat) + " (" + std::to_string(stat) + ")", at, 4);
                    if (stat == 2) {
                        const uint32_t low = r.readUnsignedInt(), high = r.readUnsignedInt();
                        if (r.ok()) { summary += " (versions " + std::to_string(low) + "-" + std::to_string(high) + ")"; add("Supported Versions: " + std::to_string(low) + " - " + std::to_string(high), at + 4, 8); }
                    }
                }
            }
        } else {
            pack.app_flags |= kFlagDenied;
            summary += " Denied";
            const size_t at = r.pos();
            const uint32_t rejectStat = r.readUnsignedInt();   // 0 = RPC_MISMATCH, 1 = AUTH_ERROR
            if (r.ok() && rejectStat == 0) {
                const uint32_t low = r.readUnsignedInt(), high = r.readUnsignedInt();
                if (r.ok()) { summary += " RPC_MISMATCH (versions " + std::to_string(low) + "-" + std::to_string(high) + ")"; add("Reject State: RPC_MISMATCH", at, 4); }
            } else if (r.ok() && rejectStat == 1) {
                const uint32_t auth = r.readUnsignedInt();
                if (r.ok()) {
                    pack.app_code = static_cast<uint16_t>(auth);
                    summary += std::string(" AUTH_ERROR ") + authStatName(auth);
                    add(std::string("Auth Error: ") + authStatName(auth) + " (" + std::to_string(auth) + ")", at + 4, 4);
                }
            }
        }
    } else {
        // not the first fragment of a record: its bytes are the middle of a message
        pack.protocol = "RPC";
        pack.info = "RPC record fragment (" + std::to_string(bodyLen) + " bytes)";
        if (ctx.wantFields()) ctx.addLayer("Remote Procedure Call (record fragment)", o + offset, bodyLen);
        return;
    }

    if (!lastFragment && pack.ip_protocol == 6) summary += " [not the last fragment of the record]";
    pack.info = summary;
    if (ctx.wantFields()) {
        Field &root = ctx.addLayer(layerName, o + offset, bodyLen);
        if (offset) root.add(std::string("Record Mark: ") + (lastFragment ? "last fragment, " : "more fragments, ") + std::to_string(be32(data) & 0x7FFFFFFFu) + " bytes", o, 4);
        for (const auto &it: items) {
            if (it.second.first <= o + length) root.add(it.first, it.second.first, std::min(it.second.second, o + length - it.second.first));
        }
    }
    if (malformed) ctx.markMalformed(malformed);   // after the summary: it replaces it
}

} // namespace dissect
