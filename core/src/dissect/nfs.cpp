#include "nfs.h"
#include "xdr.h"
#include "util.h"
#include <cstdio>
#include <string>

namespace dissect {

namespace {

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
    switch (proc) {
        case 0: return "NULL";
        case 1: return "GETATTR";
        case 2: return "SETATTR";
        case 3: return "LOOKUP";
        case 4: return "ACCESS";
        case 5: return "READLINK";
        case 6: return "READ";
        case 7: return "WRITE";
        case 8: return "CREATE";
        case 9: return "MKDIR";
        case 10: return "SYMLINK";
        case 11: return "MKNOD";
        case 12: return "REMOVE";
        case 13: return "RMDIR";
        case 14: return "RENAME";
        case 15: return "LINK";
        case 16: return "READDIR";
        case 17: return "READDIRPLUS";
        case 18: return "FSSTAT";
        case 19: return "FSINFO";
        case 20: return "PATHCONF";
        case 21: return "COMMIT";
        default: return "PROC";
    }
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

} // namespace

StreamFrame frameRpc(const char *data, size_t length) {
    if (length < 4) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    // ONC RPC record marking standard:
    // bit 31: last fragment flag
    // bits 0..30: fragment length
    uint32_t rm = (static_cast<uint32_t>(bytes[0]) << 24) |
                  (static_cast<uint32_t>(bytes[1]) << 16) |
                  (static_cast<uint32_t>(bytes[2]) << 8) |
                  static_cast<uint32_t>(bytes[3]);
    uint32_t fragLen = rm & 0x7FFFFFFF;

    if (fragLen > 16 * 1024 * 1024) { // 16 MB limit
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }

    size_t total = 4 + static_cast<size_t>(fragLen);
    if (length < total) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    return StreamFrame{StreamFrame::Kind::Complete, total};
}

void dissectNfs(Context &ctx, const char *data, size_t length) {
    if (!data || length < 16) return;

    size_t offset = 0;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);

    // Check if TCP Record Marking is present
    if (length >= 4) {
        uint32_t rm = (static_cast<uint32_t>(bytes[0]) << 24) |
                      (static_cast<uint32_t>(bytes[1]) << 16) |
                      (static_cast<uint32_t>(bytes[2]) << 8) |
                      static_cast<uint32_t>(bytes[3]);
        uint32_t fragLen = rm & 0x7FFFFFFF;
        if (fragLen + 4 == length && length > 16) {
            offset = 4;
        }
    }

    ByteReader br(bytes + offset, length - offset);
    XdrReader r(br);

    uint32_t xid = r.readUnsignedInt();
    uint32_t mtype = r.readUnsignedInt(); // 0 = CALL, 1 = REPLY

    if (!r.ok()) return;

    if (mtype == 0) { // RPC CALL
        uint32_t rpcvers = r.readUnsignedInt();
        uint32_t prog = r.readUnsignedInt();
        uint32_t vers = r.readUnsignedInt();
        uint32_t proc = r.readUnsignedInt();

        if (!r.ok()) return;

        const char *progName = rpcProgramName(prog);
        std::string progStr = progName ? progName : ("Prog " + std::to_string(prog));
        std::string procStr;

        if (prog == 100003) { // NFS
            if (vers == 4) procStr = nfs4ProcName(proc);
            else procStr = nfs3ProcName(proc);
            ctx.pack.protocol = (vers == 4 ? "NFSv4" : "NFS");
        } else if (prog == 100000) { // Portmap
            procStr = portmapProcName(proc);
            ctx.pack.protocol = "Portmap";
        } else if (prog == 100005) { // Mount
            procStr = "PROC " + std::to_string(proc);
            ctx.pack.protocol = "Mount";
        } else {
            procStr = "PROC " + std::to_string(proc);
            ctx.pack.protocol = "RPC";
        }

        ctx.pack.app_type = static_cast<uint16_t>(proc);
        std::string summary = progStr + " v" + std::to_string(vers) + " " + procStr + " Call (XID: 0x" + hexString(xid, 8) + ")";
        ctx.pack.info = summary;

        if (ctx.wantFields()) {
            const size_t o = ctx.offsetOf(data) + offset;
            auto &root = ctx.addLayer("Remote Procedure Call (Call " + progStr + ")", o, length - offset);
            root.add("XID: 0x" + hexString(xid, 8));
            root.add("Type: Call (0)");
            root.add("RPC Version: " + std::to_string(rpcvers));
            root.add("Program: " + progStr + " (" + std::to_string(prog) + ")");
            root.add("Program Version: " + std::to_string(vers));
            root.add("Procedure: " + procStr + " (" + std::to_string(proc) + ")");
        }
    } else if (mtype == 1) { // RPC REPLY
        uint32_t replyStat = r.readUnsignedInt(); // 0 = MSG_ACCEPTED, 1 = MSG_DENIED
        if (!r.ok()) return;

        std::string summary = "RPC Reply (XID: 0x" + hexString(xid, 8) + ")";
        if (replyStat == 0) {
            summary += " Accepted";
        } else {
            summary += " Denied";
        }

        ctx.pack.protocol = "RPC";
        ctx.pack.info = summary;

        if (ctx.wantFields()) {
            const size_t o = ctx.offsetOf(data) + offset;
            auto &root = ctx.addLayer("Remote Procedure Call (Reply)", o, length - offset);
            root.add("XID: 0x" + hexString(xid, 8));
            root.add("Type: Reply (1)");
            root.add("Reply Status: " + std::string(replyStat == 0 ? "Accepted (0)" : "Denied (1)"));
        }
    }
}

} // namespace dissect
