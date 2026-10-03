// NFS version 4 (RFC 7530) and 4.1 (RFC 5661): operation names and the head of a COMPOUND call.
#include "nfs_decode.h"

namespace dissect::rpcdec {

const char *nfs4ProcName(uint32_t proc) {
    switch (proc) {
        case 0: return "NULL";
        case 1: return "COMPOUND";
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

void nfs4Call(uint32_t proc, Cursor &a, Out &o) {
    if (proc != 1) return;
    auto &r = a.r;
    const size_t argsAt = a.at();
    const std::string tag = r.readString(255);
    const uint32_t minor = r.readUnsignedInt(), nops = r.readUnsignedInt();
    if (!r.ok()) return;
    o.info = "minor=" + std::to_string(minor) + " ops=" + std::to_string(nops);
    o.add("Tag: " + text(tag, 63), argsAt, 4);
    o.add("Minor Version: " + std::to_string(minor), argsAt, 0);
    o.add("Operations: " + std::to_string(nops), argsAt, 0);
    if (nops > 0 && r.remaining() >= 4) {
        const uint32_t op = r.readUnsignedInt();
        const char *on = nfs4OpName(op);
        o.info += std::string(" first=") + (on ? on : "op " + std::to_string(op));
        o.add(std::string("First Operation: ") + (on ? on : "unknown") + " (" + std::to_string(op) + ")", a.at() - 4, 4);
    }
}

} // namespace dissect::rpcdec
