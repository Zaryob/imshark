#pragma once

// What the decoders of the programs carried by ONC RPC (nfs3.cpp, nfs4.cpp, rpc_programs.cpp) share with the RPC layer (nfs.cpp): the
// cursor on the arguments / results of a message, and the lines, Info text and facts the decoders hand back.
#include <cstdint>
#include <string>
#include <vector>

#include "onc_rpc_session.h"
#include "util.h"
#include "xdr.h"

namespace dissect::rpcdec {

/// One line of the detail tree. `at` is the position in the RPC message body (after the record mark), `depth` the nesting under the
/// message layer (0 = child of the layer).
struct Item {
    std::string text;
    size_t at = 0, len = 0;
    int depth = 0;
};

/// What the decoders of one message's arguments / results produce.
struct Out {
    std::vector<Item> items;
    std::string info;                 // appended to the Info column after ", "
    std::string name;                 // a call: the file name / directory path it names (app_text2)
    std::string ops;                  // NFSv4: the operation numbers of the compound, comma separated (app_text2)
    bool hasResult = false;           // a reply: the status (NFS, Mount) or the port (GETPORT, GETADDR) it carries
    uint32_t result = 0;
    std::vector<RpcMapping> mappings; // a portmapper reply: the program ports it announced

    void add(std::string text, size_t at, size_t len, int depth = 0) { items.push_back(Item{std::move(text), at, len, depth}); }
    void appendInfo(const std::string &s) {
        if (s.empty()) return;
        if (!info.empty()) info += " ";
        info += s;
    }
};

/// A reader on the arguments / results with the position where they start in the message body.
struct Cursor {
    XdrReader r;
    size_t base;
    Cursor(const uint8_t *p, size_t n, size_t baseOffset) : r(p, n), base(baseOffset) {}
    size_t at() const { return base + r.pos(); }
};

inline std::string hexPreview(const uint8_t *p, size_t n, size_t max = 8) {
    static const char *digits = "0123456789abcdef";
    std::string out;
    for (size_t i = 0; i < n && i < max; ++i) { out += digits[p[i] >> 4]; out += digits[p[i] & 15]; }
    if (n > max) out += "...";
    return out;
}

inline std::string text(const std::string &s, size_t max = 100) { return printableText(s.data(), s.size(), max); }

/// Name of a well known program number (nullptr if it has none); defined with the RPC layer in nfs.cpp.
const char *rpcProgramName(uint32_t prog);

// ---- NFS (nfs3.cpp, nfs4.cpp) ---------------------------------------------------------------------------------------------------
const char *nfs3ProcName(uint32_t proc);
const char *nfs4ProcName(uint32_t proc);
const char *nfs4OpName(uint32_t op);
void nfs3Call(uint32_t proc, Cursor &a, Out &o);
void nfs4Call(uint32_t proc, Cursor &a, Out &o);

// ---- Portmap / rpcbind and Mount (rpc_programs.cpp) ------------------------------------------------------------------------------
const char *portmapProcName(uint32_t vers, uint32_t proc);
const char *mountProcName(uint32_t proc);
void portmapCall(uint32_t vers, uint32_t proc, Cursor &a, Out &o, RpcMessage &msg);
void mountCall(uint32_t proc, Cursor &a, Out &o);

} // namespace dissect::rpcdec
