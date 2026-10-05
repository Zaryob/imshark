// Portmap / rpcbind (RFC 1833) and Mount (RFC 1813 appendix I): procedure names, the arguments of a call and the results of a reply.
//
// Portmap version 2 (RFC 1833 section 3): a mapping is (prog, vers, prot, port), SET / UNSET / GETPORT take one, DUMP answers a list of
// them ("pmaplist": a boolean says whether an entry follows). rpcbind versions 3 and 4 (section 2) name the transport by a netid
// ("tcp", "udp", "tcp6", "udp6") and the address by a universal address: "h1.h2.h3.h4.p1.p2" for IPv4, the port being p1 * 256 + p2.
// What an answer tells about ports is handed to the session table (Out::mappings): a later connection to that port is ONC RPC.
//
// Mount (appendix I): MNT answers a status and a file handle (version 3: "fhandle3" opaque<64> and the accepted authentication
// flavors; versions 1 and 2: "fhstatus", a 32 byte handle), DUMP the clients with their directories, EXPORT the exported directories
// with their groups, both as boolean-prefixed lists.
#include <algorithm>

#include "nfs_decode.h"

namespace dissect::rpcdec {

namespace {

constexpr size_t kMaxListed = 1024;      // entries of a list that are decoded
constexpr size_t kMaxShown = 64;         // entries of a list that get a line in the tree

const char *protName(uint32_t prot) { return prot == 6 ? "tcp" : prot == 17 ? "udp" : nullptr; }

std::string programText(uint32_t prog) {
    const char *name = rpcProgramName(prog);
    return name ? std::string(name) : std::to_string(prog);
}

std::string protText(uint32_t prot) { return protName(prot) ? protName(prot) : "proto " + std::to_string(prot); }

// rpcbind netid -> IP protocol number (0 if it is not a TCP / UDP netid)
uint32_t netidProtocol(const std::string &netid) {
    if (netid == "tcp" || netid == "tcp6") return 6;
    if (netid == "udp" || netid == "udp6") return 17;
    return 0;
}

// "h1.h2.h3.h4.p1.p2" / "x:y::z.p1.p2": the host and the port (p1 * 256 + p2); false if the text is not an IP universal address
bool parseUniversalAddress(const std::string &uaddr, std::string &host, uint32_t &port) {
    const size_t last = uaddr.rfind('.');
    if (last == std::string::npos || last == 0) return false;
    const size_t prev = uaddr.rfind('.', last - 1);
    if (prev == std::string::npos || prev == 0) return false;
    const auto number = [](const std::string &s, uint32_t &v) {
        if (s.empty() || s.size() > 3) return false;
        v = 0;
        for (const char c: s) { if (c < '0' || c > '9') return false; v = v * 10 + static_cast<uint32_t>(c - '0'); }
        return v <= 255;
    };
    uint32_t hi, lo;
    if (!number(uaddr.substr(prev + 1, last - prev - 1), hi) || !number(uaddr.substr(last + 1), lo)) return false;
    host = uaddr.substr(0, prev);
    port = hi * 256 + lo;
    return true;
}

const char *mountStatName(uint32_t s) {
    switch (s) {
        case 0: return "MNT3_OK";
        case 1: return "MNT3ERR_PERM";
        case 2: return "MNT3ERR_NOENT";
        case 5: return "MNT3ERR_IO";
        case 13: return "MNT3ERR_ACCES";
        case 20: return "MNT3ERR_NOTDIR";
        case 22: return "MNT3ERR_INVAL";
        case 63: return "MNT3ERR_NAMETOOLONG";
        case 10004: return "MNT3ERR_NOTSUPP";
        case 10006: return "MNT3ERR_SERVERFAULT";
        default: return nullptr;
    }
}

const char *authFlavorText(uint32_t f) {
    switch (f) {
        case 0: return "AUTH_NULL";
        case 1: return "AUTH_SYS";
        case 2: return "AUTH_SHORT";
        case 3: return "AUTH_DH";
        case 6: return "RPCSEC_GSS";
        default: return nullptr;
    }
}

// one mapping learned from a portmapper / rpcbind answer
void learn(Out &o, uint32_t prog, uint32_t vers, uint32_t prot, uint32_t port, const std::string &host = std::string()) {
    if (o.mappings.size() < kMaxListed) o.mappings.push_back(RpcMapping{prog, vers, prot, port, host});
}

// the rpcb of rpcbind: r_prog, r_vers, r_netid, r_addr, r_owner
struct Rpcb {
    uint32_t prog = 0, vers = 0;
    std::string netid, addr, owner;
};

bool readRpcb(XdrReader &r, Rpcb &b) {
    b.prog = r.readUnsignedInt();
    b.vers = r.readUnsignedInt();
    b.netid = r.readString(32);
    b.addr = r.readString(255);
    b.owner = r.readString(255);
    return r.ok();
}

} // namespace

const char *portmapProcName(uint32_t vers, uint32_t proc) {
    if (vers < 3) {
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
    switch (proc) {
        case 0: return "NULL";
        case 1: return "SET";
        case 2: return "UNSET";
        case 3: return "GETADDR";
        case 4: return "DUMP";
        case 5: return vers == 3 ? "CALLIT" : "BCAST";
        case 6: return "GETTIME";
        case 7: return "UADDR2TADDR";
        case 8: return "TADDR2UADDR";
        case 9: return "GETVERSADDR";
        case 10: return "INDIRECT";
        case 11: return "GETADDRLIST";
        case 12: return "GETSTAT";
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
        case 6: return "PATHCONF";
        default: return "PROC";
    }
}

void portmapCall(uint32_t vers, uint32_t proc, Cursor &a, Out &o, RpcMessage &msg) {
    auto &r = a.r;
    if (vers < 3) {
        if (proc == 1 || proc == 2 || proc == 3) {   // SET, UNSET, GETPORT: mapping (prog, vers, prot, port)
            const size_t at = a.at();
            const uint32_t mprog = r.readUnsignedInt(), mvers = r.readUnsignedInt(), mprot = r.readUnsignedInt(), mport = r.readUnsignedInt();
            if (!r.ok()) return;
            msg.mapProg = mprog; msg.mapVers = mvers; msg.mapProt = mprot;
            o.info = "prog=" + programText(mprog) + " v" + std::to_string(mvers) + " " + protText(mprot);
            if (proc != 3 && mport) o.info += " port=" + std::to_string(mport);
            o.add("Mapping: program " + std::to_string(mprog) + " version " + std::to_string(mvers) + " protocol " + std::to_string(mprot) + " port " + std::to_string(mport), at, 16);
        } else if (proc == 5) {   // CALLIT: the program, version and procedure to call, and its arguments
            const size_t at = a.at();
            const uint32_t cprog = r.readUnsignedInt(), cvers = r.readUnsignedInt(), cproc = r.readUnsignedInt();
            const uint32_t len = r.readUnsignedInt();
            if (!r.ok()) return;
            o.info = "prog=" + programText(cprog) + " v" + std::to_string(cvers) + " proc=" + std::to_string(cproc);
            o.add("Call: program " + std::to_string(cprog) + " version " + std::to_string(cvers) + " procedure " + std::to_string(cproc) + ", " + std::to_string(len) + " bytes of arguments", at, 16);
        }
        return;
    }
    if (proc == 1 || proc == 2 || proc == 3 || proc == 9 || proc == 11) {   // SET, UNSET, GETADDR, GETVERSADDR, GETADDRLIST: rpcb
        const size_t at = a.at();
        Rpcb b;
        if (!readRpcb(r, b)) return;
        msg.mapProg = b.prog; msg.mapVers = b.vers; msg.mapProt = netidProtocol(b.netid); msg.netid = b.netid;
        o.info = "prog=" + programText(b.prog) + " v" + std::to_string(b.vers) + " netid=" + text(b.netid, 16);
        if (!b.addr.empty() && proc != 3 && proc != 9 && proc != 11) o.info += " addr=" + text(b.addr, 64);
        o.add("RPCB: program " + std::to_string(b.prog) + " version " + std::to_string(b.vers) + " netid " + text(b.netid, 16) + " addr " + text(b.addr, 64) + " owner " + text(b.owner, 32), at, a.at() - at);
    }
}

void portmapReply(const RpcNote &call, Cursor &a, Out &o) {
    auto &r = a.r;
    const uint32_t vers = call.vers, proc = call.proc;
    const auto boolResult = [&] {
        const size_t at = a.at();
        const bool v = r.readBool();
        if (!r.ok()) return;
        o.hasResult = true;
        o.result = v ? 1 : 0;
        o.info = std::string("result=") + (v ? "TRUE" : "FALSE");
        o.add(std::string("Result: ") + (v ? "TRUE" : "FALSE"), at, 4);
    };
    if (vers < 3) {
        if (proc == 1 || proc == 2) {
            boolResult();
        } else if (proc == 3) {   // GETPORT
            const size_t at = a.at();
            const uint32_t port = r.readUnsignedInt();
            if (!r.ok()) return;
            o.hasResult = true;
            o.result = port;
            o.info = port ? "port=" + std::to_string(port) : "port=0 (not registered)";
            o.add("Port: " + std::to_string(port), at, 4);
            if (port && call.mapProg) learn(o, call.mapProg, call.mapVers, call.mapProt, port);
        } else if (proc == 4) {   // DUMP
            const size_t listAt = a.at();
            size_t count = 0;
            std::vector<Item> entries;
            while (count < kMaxListed) {
                const size_t at = a.at();
                if (!r.readBool()) break;
                const uint32_t prog = r.readUnsignedInt(), pvers = r.readUnsignedInt(), prot = r.readUnsignedInt(), port = r.readUnsignedInt();
                if (!r.ok()) break;
                ++count;
                if (entries.size() < kMaxShown) entries.push_back(Item{programText(prog) + " v" + std::to_string(pvers) + " " + protText(prot) + " port " + std::to_string(port), at, 20, 1});
                learn(o, prog, pvers, prot, port);
            }
            if (!r.ok() && count == 0) return;
            o.hasResult = true;
            o.result = static_cast<uint32_t>(count);
            o.info = std::to_string(count) + (count == 1 ? " mapping" : " mappings");
            o.add("Mappings: " + std::to_string(count), listAt, a.at() - listAt);
            for (auto &e: entries) o.items.push_back(std::move(e));
        } else if (proc == 5) {   // CALLIT: port, results
            const size_t at = a.at();
            const uint32_t port = r.readUnsignedInt();
            const uint32_t len = r.readUnsignedInt();
            if (!r.ok()) return;
            o.info = "port=" + std::to_string(port) + " results=" + std::to_string(len) + " bytes";
            o.add("Port: " + std::to_string(port), at, 4);
            o.add("Results: " + std::to_string(len) + " bytes", at + 4, 4);
        }
        return;
    }
    // rpcbind versions 3 and 4
    if (proc == 1 || proc == 2) {
        boolResult();
    } else if (proc == 3 || proc == 9) {   // GETADDR, GETVERSADDR: the universal address, "" if the program is not registered
        const size_t at = a.at();
        const std::string uaddr = r.readString(255);
        if (!r.ok()) return;
        std::string host;
        uint32_t port = 0;
        if (uaddr.empty()) {
            o.info = "addr=(not registered)";
        } else if (parseUniversalAddress(uaddr, host, port)) {
            o.hasResult = true;
            o.result = port;
            o.info = "addr=" + text(uaddr, 64) + " (" + text(host, 45) + " port " + std::to_string(port) + ")";
            if (call.mapProg && netidProtocol(call.netid)) learn(o, call.mapProg, call.mapVers, netidProtocol(call.netid), port, host);
        } else {
            o.info = "addr=" + text(uaddr, 64);
        }
        o.add("Universal Address: " + text(uaddr, 64), at, 4 + uaddr.size());
    } else if (proc == 4) {   // DUMP: rpcblist
        const size_t listAt = a.at();
        size_t count = 0;
        std::vector<Item> entries;
        while (count < kMaxListed) {
            const size_t at = a.at();
            if (!r.readBool()) break;
            Rpcb b;
            if (!readRpcb(r, b)) break;
            ++count;
            if (entries.size() < kMaxShown) entries.push_back(Item{programText(b.prog) + " v" + std::to_string(b.vers) + " " + text(b.netid, 16) + " " + text(b.addr, 64) + " owner " + text(b.owner, 32), at, a.at() - at, 1});
            std::string host;
            uint32_t port = 0;
            if (netidProtocol(b.netid) && parseUniversalAddress(b.addr, host, port)) learn(o, b.prog, b.vers, netidProtocol(b.netid), port, host);
        }
        if (!r.ok() && count == 0) return;
        o.hasResult = true;
        o.result = static_cast<uint32_t>(count);
        o.info = std::to_string(count) + (count == 1 ? " mapping" : " mappings");
        o.add("Mappings: " + std::to_string(count), listAt, a.at() - listAt);
        for (auto &e: entries) o.items.push_back(std::move(e));
    } else if (proc == 11) {   // GETADDRLIST: rpcb_entry list (maddr, netid, semantics, protofmly, proto)
        const size_t listAt = a.at();
        size_t count = 0;
        while (count < kMaxListed) {
            if (!r.readBool()) break;
            const std::string maddr = r.readString(255), netid = r.readString(32);
            r.readUnsignedInt();
            r.readString(32);
            r.readString(32);
            if (!r.ok()) break;
            ++count;
            std::string host;
            uint32_t port = 0;
            if (call.mapProg && netidProtocol(netid) && parseUniversalAddress(maddr, host, port)) learn(o, call.mapProg, call.mapVers, netidProtocol(netid), port, host);
        }
        if (!r.ok() && count == 0) return;
        o.info = std::to_string(count) + (count == 1 ? " address" : " addresses");
        o.add("Addresses: " + std::to_string(count), listAt, a.at() - listAt);
    } else if (proc == 6) {   // GETTIME
        const size_t at = a.at();
        const uint32_t t = r.readUnsignedInt();
        if (!r.ok()) return;
        o.info = "time=" + std::to_string(t);
        o.add("Time: " + std::to_string(t), at, 4);
    }
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

void mountReply(uint32_t vers, uint32_t proc, Cursor &a, Out &o) {
    auto &r = a.r;
    if (proc == 1) {   // MNT: status, then the file handle (version 3: variable length and the authentication flavors; 1 and 2: 32 bytes)
        const size_t at = a.at();
        const uint32_t status = r.readUnsignedInt();
        if (!r.ok()) return;
        const char *name = mountStatName(status);
        o.hasResult = true;
        o.result = status;
        o.info = name ? name : "status " + std::to_string(status);
        o.add("Mount Status: " + (name ? std::string(name) : std::string("unknown")) + " (" + std::to_string(status) + ")", at, 4);
        if (status != 0) return;
        const size_t fhAt = a.at();
        if (vers >= 3) {
            const auto fh = r.readOpaque(64);
            if (!r.ok()) return;
            const std::string fhText = hexPreview(fh.data(), fh.size());
            o.info += " fh=" + fhText;
            o.add("File Handle: " + fhText + " (" + std::to_string(fh.size()) + " bytes)", fhAt, 4 + fh.size());
            const size_t flavorsAt = a.at();
            const uint32_t n = r.readUnsignedInt();
            std::string names;
            for (uint32_t i = 0; i < n && i < 16 && r.ok(); ++i) {
                const uint32_t f = r.readUnsignedInt();
                if (!r.ok()) break;
                const char *fn = authFlavorText(f);
                names += (names.empty() ? "" : ",") + (fn ? std::string(fn) : std::to_string(f));
            }
            if (r.ok()) {
                o.info += " flavors=" + (names.empty() ? std::string("none") : names);
                o.add("Authentication Flavors: " + (names.empty() ? std::string("none") : names), flavorsAt, 4 + 4 * static_cast<size_t>(std::min<uint32_t>(n, 16)));
            }
        } else {
            const auto fh = r.readFixedOpaque(32);
            if (!r.ok()) return;
            const std::string fhText = hexPreview(fh.data(), fh.size());
            o.info += " fh=" + fhText;
            o.add("File Handle: " + fhText + " (32 bytes)", fhAt, 32);
        }
    } else if (proc == 2) {   // DUMP: mountlist, each entry hostname + directory
        const size_t listAt = a.at();
        size_t count = 0;
        std::vector<Item> entries;
        while (count < kMaxListed) {
            const size_t at = a.at();
            if (!r.readBool()) break;
            const std::string host = r.readString(255), dir = r.readString(1024);
            if (!r.ok()) break;
            ++count;
            if (entries.size() < kMaxShown) entries.push_back(Item{text(host, 63) + ":" + text(dir, 120), at, a.at() - at, 1});
        }
        if (!r.ok() && count == 0) return;
        o.info = std::to_string(count) + (count == 1 ? " mount" : " mounts");
        o.add("Mounts: " + std::to_string(count), listAt, a.at() - listAt);
        for (auto &e: entries) o.items.push_back(std::move(e));
    } else if (proc == 5) {   // EXPORT: exportlist, each entry directory + groups
        const size_t listAt = a.at();
        size_t count = 0;
        std::vector<Item> entries;
        while (count < kMaxListed) {
            const size_t at = a.at();
            if (!r.readBool()) break;
            const std::string dir = r.readString(1024);
            std::string groups;
            size_t groupCount = 0;
            while (r.ok() && groupCount < kMaxListed) {
                if (!r.readBool()) break;
                const std::string g = r.readString(255);
                if (!r.ok()) break;
                if (++groupCount <= 8) groups += (groups.empty() ? "" : ",") + text(g, 63);
            }
            if (!r.ok()) break;
            ++count;
            if (entries.size() < kMaxShown) entries.push_back(Item{text(dir, 120) + (groups.empty() ? std::string() : " (" + groups + ")"), at, a.at() - at, 1});
        }
        if (!r.ok() && count == 0) return;
        o.info = std::to_string(count) + (count == 1 ? " export" : " exports");
        o.add("Exports: " + std::to_string(count), listAt, a.at() - listAt);
        for (auto &e: entries) o.items.push_back(std::move(e));
    }
}

} // namespace dissect::rpcdec
