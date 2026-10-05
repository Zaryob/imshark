// NFS version 3 (RFC 1813): procedure names, the arguments of a call and the results of a reply.
//
// Every reply starts with nfsstat3. The result structures follow RFC 1813 section 3.3: fattr3 is 84 bytes (type, mode, nlink, uid, gid,
// size, used, rdev, fsid, fileid, atime, mtime, ctime), post_op_attr is a boolean and, when TRUE, a fattr3, pre_op_attr a boolean and
// a 24 byte wcc_attr (size, mtime, ctime), wcc_data a pre_op_attr and a post_op_attr, post_op_fh3 a boolean and a file handle.
// READ / WRITE only need the counts (the data itself is not shown), READDIR / READDIRPLUS are boolean-prefixed entry lists.
#include <algorithm>
#include <cstdio>
#include <ctime>

#include "nfs_decode.h"

namespace dissect::rpcdec {

namespace {

constexpr size_t kMaxEntries = 1024;   // directory entries that are decoded
constexpr size_t kMaxShown = 64;       // directory entries that get a line in the tree

const char *nfsstat3Name(uint32_t s) {
    switch (s) {
        case 0: return "NFS3_OK";
        case 1: return "NFS3ERR_PERM";
        case 2: return "NFS3ERR_NOENT";
        case 5: return "NFS3ERR_IO";
        case 6: return "NFS3ERR_NXIO";
        case 13: return "NFS3ERR_ACCES";
        case 17: return "NFS3ERR_EXIST";
        case 18: return "NFS3ERR_XDEV";
        case 19: return "NFS3ERR_NODEV";
        case 20: return "NFS3ERR_NOTDIR";
        case 21: return "NFS3ERR_ISDIR";
        case 22: return "NFS3ERR_INVAL";
        case 27: return "NFS3ERR_FBIG";
        case 28: return "NFS3ERR_NOSPC";
        case 30: return "NFS3ERR_ROFS";
        case 31: return "NFS3ERR_MLINK";
        case 63: return "NFS3ERR_NAMETOOLONG";
        case 66: return "NFS3ERR_NOTEMPTY";
        case 69: return "NFS3ERR_DQUOT";
        case 70: return "NFS3ERR_STALE";
        case 71: return "NFS3ERR_REMOTE";
        case 10001: return "NFS3ERR_BADHANDLE";
        case 10002: return "NFS3ERR_NOT_SYNC";
        case 10003: return "NFS3ERR_BAD_COOKIE";
        case 10004: return "NFS3ERR_NOTSUPP";
        case 10005: return "NFS3ERR_TOOSMALL";
        case 10006: return "NFS3ERR_SERVERFAULT";
        case 10007: return "NFS3ERR_BADTYPE";
        case 10008: return "NFS3ERR_JUKEBOX";
        default: return nullptr;
    }
}

const char *ftypeName(uint32_t t) {
    switch (t) {
        case 1: return "REG";
        case 2: return "DIR";
        case 3: return "BLK";
        case 4: return "CHR";
        case 5: return "LNK";
        case 6: return "SOCK";
        case 7: return "FIFO";
        default: return "?";
    }
}

const char *stableName(uint32_t s) {
    switch (s) {
        case 0: return "UNSTABLE";
        case 1: return "DATA_SYNC";
        case 2: return "FILE_SYNC";
        default: return "?";
    }
}

std::string octal(uint32_t mode) {
    char b[16];
    std::snprintf(b, sizeof b, "%04o", mode & 07777);
    return b;
}

std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

// nfstime3: seconds and nanoseconds since 1970, shown as UTC
std::string timeText(uint32_t sec, uint32_t nsec) {
    const time_t t = static_cast<time_t>(sec);
    struct tm tmv {};
    char b[48];
    if (!gmtime_r(&t, &tmv)) return std::to_string(sec) + "." + std::to_string(nsec);
    std::snprintf(b, sizeof b, "%04d-%02d-%02d %02d:%02d:%02d.%09u UTC", tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec, nsec);
    return b;
}

// reads and shows the XDR structures of RFC 1813; every function returns false when the bytes end early
struct V3 {
    Cursor &a;
    Out &o;
    XdrReader &r;
    V3(Cursor &c, Out &out) : a(c), o(out), r(c.r) {}

    size_t at() const { return a.at(); }

    // nfs_fh3: opaque<64>
    bool fh(const char *label, std::string *brief = nullptr) {
        const size_t p = at();
        const auto f = r.readOpaque(64);
        if (!r.ok()) return false;
        const std::string t = hexPreview(f.data(), f.size());
        o.add(std::string(label) + ": " + t + " (" + std::to_string(f.size()) + " bytes)", p, 4 + f.size());
        if (brief) *brief = t;
        return true;
    }

    bool name(const char *label, std::string *out = nullptr, size_t max = 255) {
        const size_t p = at();
        const std::string n = r.readString(max);
        if (!r.ok()) return false;
        const std::string t = text(n, 80);
        o.add(std::string(label) + ": " + t, p, 4 + n.size());
        if (out) *out = t;
        return true;
    }

    // fattr3 (84 bytes)
    bool fattr(const char *label, std::string *brief = nullptr) {
        const size_t p = at();
        const uint32_t type = r.readUnsignedInt(), mode = r.readUnsignedInt(), nlink = r.readUnsignedInt(), uid = r.readUnsignedInt(), gid = r.readUnsignedInt();
        const uint64_t size = r.readUnsignedHyper(), used = r.readUnsignedHyper();
        const uint32_t rdev1 = r.readUnsignedInt(), rdev2 = r.readUnsignedInt();
        const uint64_t fsid = r.readUnsignedHyper(), fileid = r.readUnsignedHyper();
        const uint32_t as = r.readUnsignedInt(), an = r.readUnsignedInt(), ms = r.readUnsignedInt(), mn = r.readUnsignedInt(), cs = r.readUnsignedInt(), cn = r.readUnsignedInt();
        if (!r.ok()) return false;
        const std::string b = std::string(ftypeName(type)) + " mode=" + octal(mode) + " uid=" + std::to_string(uid) + " gid=" + std::to_string(gid) + " size=" + std::to_string(size);
        o.add(std::string(label) + ": " + b, p, 84);
        o.add(std::string("Type: ") + ftypeName(type) + " (" + std::to_string(type) + ")", p, 4, 1);
        o.add("Mode: " + octal(mode), p + 4, 4, 1);
        o.add("Number of Links: " + std::to_string(nlink), p + 8, 4, 1);
        o.add("UID: " + std::to_string(uid), p + 12, 4, 1);
        o.add("GID: " + std::to_string(gid), p + 16, 4, 1);
        o.add("Size: " + std::to_string(size), p + 20, 8, 1);
        o.add("Used: " + std::to_string(used), p + 28, 8, 1);
        o.add("Rdev: " + std::to_string(rdev1) + "," + std::to_string(rdev2), p + 36, 8, 1);
        o.add("FSID: " + hex(fsid), p + 44, 8, 1);
        o.add("File ID: " + std::to_string(fileid), p + 52, 8, 1);
        o.add("Access Time: " + timeText(as, an), p + 60, 8, 1);
        o.add("Modify Time: " + timeText(ms, mn), p + 68, 8, 1);
        o.add("Change Time: " + timeText(cs, cn), p + 76, 8, 1);
        if (brief) *brief = b;
        return true;
    }

    // post_op_attr
    bool postOpAttr(const char *label, std::string *brief = nullptr) {
        const size_t p = at();
        const bool present = r.readBool();
        if (!r.ok()) return false;
        if (!present) { o.add(std::string(label) + ": not present", p, 4); return true; }
        return fattr(label, brief);
    }

    // wcc_data: pre_op_attr (boolean, wcc_attr) and post_op_attr
    bool wcc(const char *label) {
        const size_t p = at();
        const bool pre = r.readBool();
        if (!r.ok()) return false;
        std::string preText = "no pre-operation attributes";
        if (pre) {
            const uint64_t size = r.readUnsignedHyper();
            const uint32_t ms = r.readUnsignedInt(), mn = r.readUnsignedInt();
            r.readUnsignedInt();
            r.readUnsignedInt();
            if (!r.ok()) return false;
            preText = "before: size=" + std::to_string(size) + " mtime=" + timeText(ms, mn);
        }
        o.add(std::string(label) + ": " + preText, p, pre ? 28 : 4);
        return postOpAttr("After");
    }

    // post_op_fh3
    bool postOpFh(std::string *brief = nullptr) {
        const size_t p = at();
        const bool present = r.readBool();
        if (!r.ok()) return false;
        if (!present) { o.add("Object Handle: not present", p, 4); return true; }
        return fh("Object Handle", brief);
    }

    bool u64(const char *label, uint64_t *out = nullptr) {
        const size_t p = at();
        const uint64_t v = r.readUnsignedHyper();
        if (!r.ok()) return false;
        o.add(std::string(label) + ": " + std::to_string(v), p, 8);
        if (out) *out = v;
        return true;
    }

    bool u32(const char *label, uint32_t *out = nullptr) {
        const size_t p = at();
        const uint32_t v = r.readUnsignedInt();
        if (!r.ok()) return false;
        o.add(std::string(label) + ": " + std::to_string(v), p, 4);
        if (out) *out = v;
        return true;
    }

    bool verifier(const char *label) {
        const size_t p = at();
        const auto v = r.readFixedOpaque(8);
        if (!r.ok()) return false;
        o.add(std::string(label) + ": " + hexPreview(v.data(), v.size()), p, 8);
        return true;
    }

    // sattr3: the attributes a call asks to set (RFC 1813 3.3.2); returns a short text of what is set
    bool sattr(std::string *brief = nullptr) {
        const size_t p = at();
        std::string b;
        const auto add = [&](const std::string &s) { b += (b.empty() ? "" : " ") + s; };
        if (r.readBool()) { const uint32_t m = r.readUnsignedInt(); add("mode=" + octal(m)); }
        if (r.readBool()) { const uint32_t u = r.readUnsignedInt(); add("uid=" + std::to_string(u)); }
        if (r.readBool()) { const uint32_t g = r.readUnsignedInt(); add("gid=" + std::to_string(g)); }
        if (r.readBool()) { const uint64_t s = r.readUnsignedHyper(); add("size=" + std::to_string(s)); }
        for (const char *which: {"atime", "mtime"}) {
            const uint32_t how = r.readUnsignedInt();   // 0 DONT_CHANGE, 1 SET_TO_SERVER_TIME, 2 SET_TO_CLIENT_TIME
            if (!r.ok()) return false;
            if (how == 1) add(std::string(which) + "=server");
            else if (how == 2) { const uint32_t s = r.readUnsignedInt(), n = r.readUnsignedInt(); add(std::string(which) + "=" + timeText(s, n)); }
        }
        if (!r.ok()) return false;
        o.add("Set Attributes: " + (b.empty() ? std::string("none") : b), p, at() - p);
        if (brief) *brief = b;
        return true;
    }
};

void callReadWrite(V3 &v, uint32_t proc, std::string &extra) {
    auto &r = v.r;
    const size_t at = v.at();
    const uint64_t off = r.readUnsignedHyper();
    const uint32_t count = r.readUnsignedInt();
    if (!r.ok()) return;
    extra += " offset=" + std::to_string(off) + " count=" + std::to_string(count);
    v.o.add("Offset: " + std::to_string(off), at, 8);
    v.o.add("Count: " + std::to_string(count), at + 8, 4);
    if (proc == 7) {   // WRITE: stable_how, then the data (opaque<>): its length only
        const size_t sAt = v.at();
        const uint32_t stable = r.readUnsignedInt(), len = r.readUnsignedInt();
        if (!r.ok()) return;
        v.o.add(std::string("Stable: ") + stableName(stable) + " (" + std::to_string(stable) + ")", sAt, 4);
        v.o.add("Data: " + std::to_string(len) + " bytes", sAt + 4, 4);
    }
}

} // namespace

const char *nfs3ProcName(uint32_t proc) {
    static const char *const names[] = {"NULL", "GETATTR", "SETATTR", "LOOKUP", "ACCESS", "READLINK", "READ", "WRITE", "CREATE", "MKDIR", "SYMLINK",
                                        "MKNOD", "REMOVE", "RMDIR", "RENAME", "LINK", "READDIR", "READDIRPLUS", "FSSTAT", "FSINFO", "PATHCONF", "COMMIT"};
    return proc < 22 ? names[proc] : "PROC";
}

void nfs3Call(uint32_t proc, Cursor &a, Out &o) {
    if (proc < 1 || proc > 21) return;
    V3 v(a, o);
    auto &r = v.r;
    std::string fhText;
    if (!v.fh("File Handle", &fhText)) return;
    std::string extra = "fh=" + fhText;
    std::string n;
    switch (proc) {
        case 2: {   // SETATTR: sattr3, guard
            std::string set;
            if (!v.sattr(&set)) break;
            if (!set.empty()) extra += " set=" + set;
            break;
        }
        case 3: case 12: case 13:   // LOOKUP, REMOVE, RMDIR: diropargs3 (the name; the directory handle is the one above)
            if (v.name("Name", &n)) { o.name = n; extra += " name=" + n; }
            break;
        case 4: {   // ACCESS
            uint32_t access = 0;
            if (v.u32("Access Check", &access)) extra += " access=" + hex(access);
            break;
        }
        case 6: case 7: case 21:   // READ, WRITE, COMMIT: offset, count
            callReadWrite(v, proc, extra);
            break;
        case 8: {   // CREATE: name, createhow3
            if (!v.name("Name", &n)) break;
            o.name = n;
            extra += " name=" + n;
            const size_t at = v.at();
            const uint32_t how = r.readUnsignedInt();
            if (!r.ok()) break;
            static const char *const hows[] = {"UNCHECKED", "GUARDED", "EXCLUSIVE"};
            extra += std::string(" mode=") + (how < 3 ? hows[how] : "?");
            o.add(std::string("Create Mode: ") + (how < 3 ? hows[how] : "?") + " (" + std::to_string(how) + ")", at, 4);
            if (how == 2) v.verifier("Verifier"); else v.sattr();
            break;
        }
        case 9: {   // MKDIR: name, sattr3
            if (!v.name("Name", &n)) break;
            o.name = n;
            extra += " name=" + n;
            v.sattr();
            break;
        }
        case 10: {   // SYMLINK: name, sattr3, path
            if (!v.name("Name", &n)) break;
            o.name = n;
            extra += " name=" + n;
            std::string target;
            if (v.sattr() && v.name("Link Target", &target, 1024)) extra += " target=" + target;
            break;
        }
        case 11: {   // MKNOD: name, ftype3 and the device data
            if (!v.name("Name", &n)) break;
            o.name = n;
            extra += " name=" + n;
            const size_t at = v.at();
            const uint32_t type = r.readUnsignedInt();
            if (!r.ok()) break;
            extra += std::string(" type=") + ftypeName(type);
            o.add(std::string("Type: ") + ftypeName(type) + " (" + std::to_string(type) + ")", at, 4);
            if ((type == 3 || type == 4 || type == 6 || type == 7) && v.sattr() && (type == 3 || type == 4)) { v.u32("Major"); v.u32("Minor"); }
            break;
        }
        case 14: {   // RENAME: from (handle, name), to (handle, name)
            std::string to;
            if (!v.name("From Name", &n)) break;
            o.name = n;
            extra += " name=" + n;
            std::string toFh;
            if (v.fh("To Directory", &toFh) && v.name("To Name", &to)) extra += " to=" + to;
            break;
        }
        case 15: {   // LINK: file handle (above), link directory handle and name
            std::string dirFh;
            if (v.fh("Link Directory", &dirFh) && v.name("Link Name", &n)) { o.name = n; extra += " name=" + n; }
            break;
        }
        case 16: case 17: {   // READDIR, READDIRPLUS: cookie, cookie verifier, sizes
            uint64_t cookie = 0;
            uint32_t count = 0;
            if (!v.u64("Cookie", &cookie) || !v.verifier("Cookie Verifier")) break;
            extra += " cookie=" + std::to_string(cookie);
            if (proc == 16) {
                if (v.u32("Count", &count)) extra += " count=" + std::to_string(count);
            } else {
                uint32_t maxCount = 0;
                if (v.u32("Directory Count", &count) && v.u32("Max Count", &maxCount)) extra += " dircount=" + std::to_string(count) + " maxcount=" + std::to_string(maxCount);
            }
            break;
        }
        default: break;   // READLINK, FSSTAT, FSINFO, PATHCONF: the handle only
    }
    o.info = extra;
}

void nfs3Reply(uint32_t proc, Cursor &a, Out &o) {
    if (proc > 21) return;
    V3 v(a, o);
    auto &r = v.r;
    const size_t statusAt = a.at();
    const uint32_t status = r.readUnsignedInt();
    if (!r.ok()) return;
    const char *sn = nfsstat3Name(status);
    o.hasResult = true;
    o.result = status;
    o.info = sn ? sn : "NFS3 status " + std::to_string(status);
    o.add(std::string("Status: ") + (sn ? sn : "unknown") + " (" + std::to_string(status) + ")", statusAt, 4);
    const bool ok = status == 0;
    const auto more = [&](const std::string &s) { if (!s.empty()) o.info += " " + s; };
    std::string b;

    switch (proc) {
        case 1:   // GETATTR: fattr3 on success
            if (ok && v.fattr("Attributes", &b)) more(b);
            break;
        case 2: case 12: case 13:   // SETATTR, REMOVE, RMDIR: wcc_data either way
            v.wcc("Object");
            break;
        case 3:   // LOOKUP: handle, object attributes, directory attributes; on failure the directory attributes
            if (ok) {
                if (v.fh("Object Handle", &b)) { more("fh=" + b); if (v.postOpAttr("Object Attributes", &b)) v.postOpAttr("Directory Attributes"); }
            } else {
                v.postOpAttr("Directory Attributes");
            }
            break;
        case 4:   // ACCESS
            if (v.postOpAttr("Object Attributes") && ok) { uint32_t access = 0; if (v.u32("Access", &access)) more("access=" + hex(access)); }
            break;
        case 5:   // READLINK
            if (v.postOpAttr("Symlink Attributes") && ok) { std::string path; if (v.name("Link Data", &path, 1024)) more("path=" + path); }
            break;
        case 6: {   // READ: attributes, count, eof, data
            if (!v.postOpAttr("Attributes") || !ok) break;
            uint32_t count = 0;
            if (!v.u32("Count", &count)) break;
            const size_t eofAt = a.at();
            const bool eof = r.readBool();
            const uint32_t len = r.readUnsignedInt();
            if (!r.ok()) { more("count=" + std::to_string(count)); break; }
            more("count=" + std::to_string(count) + (eof ? " eof" : ""));
            o.add(std::string("EOF: ") + (eof ? "True" : "False"), eofAt, 4);
            o.add("Data: " + std::to_string(len) + " bytes", eofAt + 4, 4);
            break;
        }
        case 7: {   // WRITE: wcc_data, count, committed, write verifier
            if (!v.wcc("File") || !ok) break;
            uint32_t count = 0, committed = 0;
            if (!v.u32("Count", &count)) break;
            const size_t cAt = a.at();
            committed = r.readUnsignedInt();
            if (!r.ok()) { more("count=" + std::to_string(count)); break; }
            o.add(std::string("Committed: ") + stableName(committed) + " (" + std::to_string(committed) + ")", cAt, 4);
            more("count=" + std::to_string(count) + " " + stableName(committed));
            v.verifier("Write Verifier");
            break;
        }
        case 8: case 9: case 10: case 11: {   // CREATE, MKDIR, SYMLINK, MKNOD: handle, attributes, directory wcc_data
            if (ok) {
                if (v.postOpFh(&b)) { if (!b.empty()) more("fh=" + b); if (v.postOpAttr("Object Attributes")) v.wcc("Directory"); }
            } else {
                v.wcc("Directory");
            }
            break;
        }
        case 14:   // RENAME: both directories
            if (v.wcc("From Directory")) v.wcc("To Directory");
            break;
        case 15:   // LINK: file attributes, directory wcc_data
            if (v.postOpAttr("File Attributes")) v.wcc("Directory");
            break;
        case 16: case 17: {   // READDIR, READDIRPLUS
            if (!v.postOpAttr("Directory Attributes") || !ok) break;
            if (!v.verifier("Cookie Verifier")) break;
            const size_t listAt = a.at();
            size_t count = 0;
            std::vector<Item> entries;
            bool complete = true;
            while (count < kMaxEntries) {
                const size_t at = a.at();
                if (!r.readBool()) break;
                const uint64_t fileid = r.readUnsignedHyper();
                const std::string name = r.readString(255);
                const uint64_t cookie = r.readUnsignedHyper();
                if (proc == 17) {   // entryplus3: name_attributes (post_op_attr), name_handle (post_op_fh3)
                    if (r.ok()) {
                        if (r.readBool()) r.readFixedOpaque(84);
                        if (r.readBool()) r.readOpaque(64);
                    }
                }
                if (!r.ok()) { complete = false; break; }
                ++count;
                if (entries.size() < kMaxShown) entries.push_back(Item{text(name, 80) + " (fileid " + std::to_string(fileid) + ", cookie " + std::to_string(cookie) + ")", at, a.at() - at, 1});
            }
            if (!r.ok()) complete = false;
            bool eof = false;
            if (complete) {
                eof = r.readBool();
                if (!r.ok()) complete = false;
            }
            more(std::to_string(count) + (count == 1 ? " entry" : " entries") + (complete ? (eof ? " eof" : "") : " [cut]"));
            o.add("Entries: " + std::to_string(count), listAt, a.at() - listAt);
            for (auto &e: entries) o.items.push_back(std::move(e));
            break;
        }
        case 18: {   // FSSTAT
            if (!v.postOpAttr("Attributes") || !ok) break;
            uint64_t total = 0, free = 0;
            if (!v.u64("Total Bytes", &total) || !v.u64("Free Bytes", &free)) break;
            more("total=" + std::to_string(total) + " free=" + std::to_string(free));
            v.u64("Available Bytes"); v.u64("Total Files"); v.u64("Free Files"); v.u64("Available Files"); v.u32("Invariant Seconds");
            break;
        }
        case 19: {   // FSINFO
            if (!v.postOpAttr("Attributes") || !ok) break;
            uint32_t rtmax = 0, wtmax = 0;
            if (!v.u32("Max Read Size", &rtmax) || !v.u32("Preferred Read Size") || !v.u32("Read Multiple") || !v.u32("Max Write Size", &wtmax)) break;
            more("rtmax=" + std::to_string(rtmax) + " wtmax=" + std::to_string(wtmax));
            v.u32("Preferred Write Size"); v.u32("Write Multiple"); v.u32("Preferred Directory Read Size"); v.u64("Max File Size");
            break;
        }
        case 20: {   // PATHCONF
            if (!v.postOpAttr("Attributes") || !ok) break;
            uint32_t linkMax = 0, nameMax = 0;
            if (!v.u32("Link Max", &linkMax) || !v.u32("Name Max", &nameMax)) break;
            more("link_max=" + std::to_string(linkMax) + " name_max=" + std::to_string(nameMax));
            break;
        }
        case 21:   // COMMIT: wcc_data, write verifier
            if (v.wcc("File") && ok) v.verifier("Write Verifier");
            break;
        default: break;   // NULL: void
    }
}

} // namespace dissect::rpcdec
