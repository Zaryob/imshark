// Portmap (RFC 1833, version 2) and Mount (RFC 1813 appendix I): procedure names and the arguments of a call.
#include "nfs_decode.h"

namespace dissect::rpcdec {

const char *portmapProcName(uint32_t, uint32_t proc) {
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

void portmapCall(uint32_t, uint32_t proc, Cursor &a, Out &o, RpcMessage &) {
    if (proc != 1 && proc != 2 && proc != 3) return;   // SET, UNSET, GETPORT: mapping (prog, vers, prot, port)
    auto &r = a.r;
    const size_t at = a.at();
    const uint32_t mprog = r.readUnsignedInt(), mvers = r.readUnsignedInt(), mprot = r.readUnsignedInt(), mport = r.readUnsignedInt();
    if (!r.ok()) return;
    const char *pn = rpcProgramName(mprog);
    o.info = "prog=" + (pn ? std::string(pn) : std::to_string(mprog)) + " v" + std::to_string(mvers) + (mprot == 6 ? " tcp" : mprot == 17 ? " udp" : " proto " + std::to_string(mprot));
    if (proc != 3 && mport) o.info += " port=" + std::to_string(mport);
    o.add("Mapping: program " + std::to_string(mprog) + " version " + std::to_string(mvers) + " protocol " + std::to_string(mprot) + " port " + std::to_string(mport), at, 16);
}

void mountCall(uint32_t proc, Cursor &a, Out &o) {
    if (proc != 1 && proc != 3) return;   // MNT, UMNT: dirpath
    auto &r = a.r;
    const size_t at = a.at();
    const std::string path = r.readString(1024);
    if (!r.ok()) return;
    o.name = text(path, 120);
    o.info = "path=" + o.name;
    o.add("Directory Path: " + o.name, at, 4 + path.size());
}

} // namespace dissect::rpcdec
