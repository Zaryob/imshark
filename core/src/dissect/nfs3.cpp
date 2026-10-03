// NFS version 3 (RFC 1813): procedure names and the arguments of a call.
#include "nfs_decode.h"

namespace dissect::rpcdec {

const char *nfs3ProcName(uint32_t proc) {
    static const char *const names[] = {"NULL", "GETATTR", "SETATTR", "LOOKUP", "ACCESS", "READLINK", "READ", "WRITE", "CREATE", "MKDIR", "SYMLINK",
                                        "MKNOD", "REMOVE", "RMDIR", "RENAME", "LINK", "READDIR", "READDIRPLUS", "FSSTAT", "FSINFO", "PATHCONF", "COMMIT"};
    return proc < 22 ? names[proc] : "PROC";
}

void nfs3Call(uint32_t proc, Cursor &a, Out &o) {
    if (proc < 1 || proc > 21) return;
    auto &r = a.r;
    const size_t fhAt = a.at();
    const auto fh = r.readOpaque(64);
    if (!r.ok()) return;
    const std::string fhText = hexPreview(fh.data(), fh.size());
    o.add("File Handle: " + fhText + " (" + std::to_string(fh.size()) + " bytes)", fhAt, 4 + fh.size());
    std::string extra = "fh=" + fhText;
    if (proc == 3 || proc == 8 || proc == 9 || proc == 12 || proc == 13) { // LOOKUP, CREATE, MKDIR, REMOVE, RMDIR: diropargs3
        const size_t at = a.at();
        const std::string name = r.readString(255);
        if (r.ok()) { o.name = text(name, 80); extra += " name=" + o.name; o.add("Name: " + o.name, at, 4 + name.size()); }
    } else if (proc == 6 || proc == 21 || proc == 7) { // READ, COMMIT, WRITE: offset, count
        const size_t at = a.at();
        const uint64_t off = r.readUnsignedHyper();
        const uint32_t count = r.readUnsignedInt();
        if (r.ok()) {
            extra += " offset=" + std::to_string(off) + " count=" + std::to_string(count);
            o.add("Offset: " + std::to_string(off), at, 8);
            o.add("Count: " + std::to_string(count), at + 8, 4);
        }
    }
    o.info = extra;
}

} // namespace dissect::rpcdec
