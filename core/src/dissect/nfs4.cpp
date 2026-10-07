// NFS version 4 (RFC 7530), 4.1 (RFC 5661) and the operation numbers of 4.2 (RFC 7862): the COMPOUND procedure with the arguments of
// every operation of 4.0 and 4.1 and, in a reply, the status and the common results of each operation.
//
// A COMPOUND call is "tag, minorversion, argarray<>" and each operation "opnum, its arguments"; the reply "status, tag, resarray<>" and each
// result "opnum, nfsstat4 status, its result (when the status is NFS4_OK; a few operations also answer something on an error)". The
// results stop at the first operation that failed. There is no length in front of an operation, so the list can only be followed as far
// as every operation's arguments are known: the operations of NFSv4.2 and the layout operations that carry opaque layout bodies of
// unknown size end the list ("N more operations not decoded"), the Info column says so with "...".
//
// fattr4 is "bitmap4 attrmask, opaque attr_vals<>": the values are listed in the order of the bits (RFC 7530 section 5); the common
// attributes are decoded, the first one that is not stops that list (the values are one opaque, so the operation after it is intact).
#include <algorithm>
#include <cstdio>
#include <ctime>

#include "nfs_decode.h"

namespace dissect::rpcdec {

namespace {

constexpr size_t kMaxOps = 128;        // operations of one COMPOUND that are decoded
constexpr size_t kMaxListed = 512;     // entries of a directory listing that are decoded
constexpr size_t kMaxShown = 64;       // entries that get a line in the tree

const char *nfsstat4Name(uint32_t s) {
    switch (s) {
        case 0: return "NFS4_OK";
        case 1: return "NFS4ERR_PERM";
        case 2: return "NFS4ERR_NOENT";
        case 5: return "NFS4ERR_IO";
        case 6: return "NFS4ERR_NXIO";
        case 13: return "NFS4ERR_ACCESS";
        case 17: return "NFS4ERR_EXIST";
        case 18: return "NFS4ERR_XDEV";
        case 20: return "NFS4ERR_NOTDIR";
        case 21: return "NFS4ERR_ISDIR";
        case 22: return "NFS4ERR_INVAL";
        case 27: return "NFS4ERR_FBIG";
        case 28: return "NFS4ERR_NOSPC";
        case 30: return "NFS4ERR_ROFS";
        case 31: return "NFS4ERR_MLINK";
        case 63: return "NFS4ERR_NAMETOOLONG";
        case 66: return "NFS4ERR_NOTEMPTY";
        case 69: return "NFS4ERR_DQUOT";
        case 70: return "NFS4ERR_STALE";
        case 10001: return "NFS4ERR_BADHANDLE";
        case 10003: return "NFS4ERR_BAD_COOKIE";
        case 10004: return "NFS4ERR_NOTSUPP";
        case 10005: return "NFS4ERR_TOOSMALL";
        case 10006: return "NFS4ERR_SERVERFAULT";
        case 10007: return "NFS4ERR_BADTYPE";
        case 10008: return "NFS4ERR_DELAY";
        case 10009: return "NFS4ERR_SAME";
        case 10010: return "NFS4ERR_DENIED";
        case 10011: return "NFS4ERR_EXPIRED";
        case 10012: return "NFS4ERR_LOCKED";
        case 10013: return "NFS4ERR_GRACE";
        case 10014: return "NFS4ERR_FHEXPIRED";
        case 10015: return "NFS4ERR_SHARE_DENIED";
        case 10016: return "NFS4ERR_WRONGSEC";
        case 10017: return "NFS4ERR_CLID_INUSE";
        case 10018: return "NFS4ERR_RESOURCE";
        case 10019: return "NFS4ERR_MOVED";
        case 10020: return "NFS4ERR_NOFILEHANDLE";
        case 10021: return "NFS4ERR_MINOR_VERS_MISMATCH";
        case 10022: return "NFS4ERR_STALE_CLIENTID";
        case 10023: return "NFS4ERR_STALE_STATEID";
        case 10024: return "NFS4ERR_OLD_STATEID";
        case 10025: return "NFS4ERR_BAD_STATEID";
        case 10026: return "NFS4ERR_BAD_SEQID";
        case 10027: return "NFS4ERR_NOT_SAME";
        case 10028: return "NFS4ERR_LOCK_RANGE";
        case 10029: return "NFS4ERR_SYMLINK";
        case 10030: return "NFS4ERR_RESTOREFH";
        case 10031: return "NFS4ERR_LEASE_MOVED";
        case 10032: return "NFS4ERR_ATTRNOTSUPP";
        case 10033: return "NFS4ERR_NO_GRACE";
        case 10034: return "NFS4ERR_RECLAIM_BAD";
        case 10035: return "NFS4ERR_RECLAIM_CONFLICT";
        case 10036: return "NFS4ERR_BADXDR";
        case 10037: return "NFS4ERR_LOCKS_HELD";
        case 10038: return "NFS4ERR_OPENMODE";
        case 10039: return "NFS4ERR_BADOWNER";
        case 10040: return "NFS4ERR_BADCHAR";
        case 10041: return "NFS4ERR_BADNAME";
        case 10042: return "NFS4ERR_BAD_RANGE";
        case 10043: return "NFS4ERR_LOCK_NOTSUPP";
        case 10044: return "NFS4ERR_OP_ILLEGAL";
        case 10045: return "NFS4ERR_DEADLOCK";
        case 10046: return "NFS4ERR_FILE_OPEN";
        case 10047: return "NFS4ERR_ADMIN_REVOKED";
        case 10048: return "NFS4ERR_CB_PATH_DOWN";
        case 10049: return "NFS4ERR_BADIOMODE";
        case 10050: return "NFS4ERR_BADLAYOUT";
        case 10051: return "NFS4ERR_BAD_SESSION_DIGEST";
        case 10052: return "NFS4ERR_BADSESSION";
        case 10053: return "NFS4ERR_BADSLOT";
        case 10054: return "NFS4ERR_COMPLETE_ALREADY";
        case 10055: return "NFS4ERR_CONN_NOT_BOUND_TO_SESSION";
        case 10056: return "NFS4ERR_DELEG_ALREADY_WANTED";
        case 10057: return "NFS4ERR_BACK_CHAN_BUSY";
        case 10058: return "NFS4ERR_LAYOUTTRYLATER";
        case 10059: return "NFS4ERR_LAYOUTUNAVAILABLE";
        case 10060: return "NFS4ERR_NOMATCHING_LAYOUT";
        case 10061: return "NFS4ERR_RECALLCONFLICT";
        case 10062: return "NFS4ERR_UNKNOWN_LAYOUTTYPE";
        case 10063: return "NFS4ERR_SEQ_MISORDERED";
        case 10064: return "NFS4ERR_SEQUENCE_POS";
        case 10065: return "NFS4ERR_REQ_TOO_BIG";
        case 10066: return "NFS4ERR_REP_TOO_BIG";
        case 10067: return "NFS4ERR_REP_TOO_BIG_TO_CACHE";
        case 10068: return "NFS4ERR_RETRY_UNCACHED_REP";
        case 10069: return "NFS4ERR_UNSAFE_COMPOUND";
        case 10070: return "NFS4ERR_TOO_MANY_OPS";
        case 10071: return "NFS4ERR_OP_NOT_IN_SESSION";
        case 10072: return "NFS4ERR_HASH_ALG_UNSUPP";
        case 10074: return "NFS4ERR_CLIENTID_BUSY";
        case 10075: return "NFS4ERR_PNFS_IO_HOLE";
        case 10076: return "NFS4ERR_SEQ_FALSE_RETRY";
        case 10077: return "NFS4ERR_BAD_HIGH_SLOT";
        case 10078: return "NFS4ERR_DEADSESSION";
        case 10079: return "NFS4ERR_ENCR_ALG_UNSUPP";
        case 10080: return "NFS4ERR_PNFS_NO_LAYOUT";
        case 10081: return "NFS4ERR_NOT_ONLY_OP";
        case 10082: return "NFS4ERR_WRONG_CRED";
        case 10083: return "NFS4ERR_WRONG_TYPE";
        case 10084: return "NFS4ERR_DIRDELEG_UNAVAIL";
        case 10085: return "NFS4ERR_REJECT_DELEG";
        case 10086: return "NFS4ERR_RETURNCONFLICT";
        case 10087: return "NFS4ERR_DELEG_REVOKED";
        default: return nullptr;
    }
}

const char *ftype4Name(uint32_t t) {
    switch (t) {
        case 1: return "NF4REG";
        case 2: return "NF4DIR";
        case 3: return "NF4BLK";
        case 4: return "NF4CHR";
        case 5: return "NF4LNK";
        case 6: return "NF4SOCK";
        case 7: return "NF4FIFO";
        case 8: return "NF4ATTRDIR";
        case 9: return "NF4NAMEDATTR";
        default: return "?";
    }
}

const char *stableName(uint32_t s) {
    switch (s) {
        case 0: return "UNSTABLE4";
        case 1: return "DATA_SYNC4";
        case 2: return "FILE_SYNC4";
        default: return "?";
    }
}

std::string hex(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%llx", static_cast<unsigned long long>(v));
    return b;
}

std::string timeText(int64_t sec, uint32_t nsec) {
    const time_t t = static_cast<time_t>(sec);
    struct tm tmv {};
    char b[96];
#ifdef _WIN32
    const bool converted = gmtime_s(&tmv, &t) == 0;
#else
    const bool converted = gmtime_r(&t, &tmv) != nullptr;
#endif
    if (!converted) return std::to_string(sec) + "." + std::to_string(nsec);
    std::snprintf(b, sizeof b, "%04lld-%02d-%02d %02d:%02d:%02d.%09u UTC", static_cast<long long>(tmv.tm_year) + 1900, tmv.tm_mon + 1, tmv.tm_mday, tmv.tm_hour, tmv.tm_min, tmv.tm_sec, nsec);
    return b;
}

// the attributes of RFC 7530 section 5 (bits 0..55) and the simple ones of RFC 5661 section 5 (bits 56..76)
const char *attrName(unsigned bit) {
    static const char *const names[] = {
        "supported_attrs", "type", "fh_expire_type", "change", "size", "link_support", "symlink_support", "named_attr", "fsid", "unique_handles",
        "lease_time", "rdattr_error", "filehandle", "acl", "aclsupport", "archive", "cansettime", "case_insensitive", "case_preserving",
        "chown_restricted", "fileid", "files_avail", "files_free", "files_total", "fs_locations", "hidden", "homogeneous", "maxfilesize",
        "maxlink", "maxname", "maxread", "maxwrite", "mimetype", "mode", "no_trunc", "numlinks", "owner", "owner_group", "quota_avail_hard",
        "quota_avail_soft", "quota_used", "rawdev", "space_avail", "space_free", "space_total", "space_used", "system", "time_access",
        "time_access_set", "time_backup", "time_create", "time_delta", "time_metadata", "time_modify", "time_modify_set", "mounted_on_fileid",
        "dir_notif_delay", "dirent_notif_delay", "dacl", "sacl", "change_policy", "fs_status", "fs_layout_types", "layout_hint", "layout_types",
        "layout_alignment", "layout_blksize", "mdsthreshold", "retention_get", "retention_set", "retentevt_get", "retentevt_set",
        "retention_hold", "mode_set_masked", "suppattr_exclcreat", "fs_charset_cap"};
    return bit < sizeof(names) / sizeof(names[0]) ? names[bit] : nullptr;
}

std::string attrText(unsigned bit) {
    const char *n = attrName(bit);
    return n ? std::string(n) : "attr " + std::to_string(bit);
}

// reads and shows the XDR structures of NFSv4; every function returns false when the bytes end early
struct V4 {
    Cursor &a;
    Out &o;
    XdrReader &r;
    int depth;
    V4(Cursor &c, Out &out, int d) : a(c), o(out), r(c.r), depth(d) {}

    size_t at() const { return a.at(); }
    void line(const std::string &t, size_t p, size_t len, int d = -1) { o.add(t, p, len, d < 0 ? depth : d); }

    bool u32(const char *label, uint32_t *out = nullptr, const char *(*names)(uint32_t) = nullptr) {
        const size_t p = at();
        const uint32_t v = r.readUnsignedInt();
        if (!r.ok()) return false;
        const char *n = names ? names(v) : nullptr;
        line(std::string(label) + ": " + (n ? std::string(n) + " (" + std::to_string(v) + ")" : std::to_string(v)), p, 4);
        if (out) *out = v;
        return true;
    }
    bool flags(const char *label, uint32_t *out = nullptr) {
        const size_t p = at();
        const uint32_t v = r.readUnsignedInt();
        if (!r.ok()) return false;
        line(std::string(label) + ": " + hex(v), p, 4);
        if (out) *out = v;
        return true;
    }
    bool u64(const char *label, uint64_t *out = nullptr) {
        const size_t p = at();
        const uint64_t v = r.readUnsignedHyper();
        if (!r.ok()) return false;
        line(std::string(label) + ": " + std::to_string(v), p, 8);
        if (out) *out = v;
        return true;
    }
    bool boolean(const char *label, bool *out = nullptr) {
        const size_t p = at();
        const bool v = r.readBool();
        if (!r.ok()) return false;
        line(std::string(label) + ": " + (v ? "True" : "False"), p, 4);
        if (out) *out = v;
        return true;
    }
    bool string(const char *label, std::string *out = nullptr, size_t max = 1024) {
        const size_t p = at();
        const std::string s = r.readString(max);
        if (!r.ok()) return false;
        const std::string t = text(s, 100);
        line(std::string(label) + ": " + t, p, 4 + s.size());
        if (out) *out = t;
        return true;
    }
    bool opaque(const char *label, size_t max = 0xFFFFFFFFu) {
        const size_t p = at();
        const auto b = r.readOpaque(max);
        if (!r.ok()) return false;
        line(std::string(label) + ": " + std::to_string(b.size()) + " bytes " + hexPreview(b.data(), b.size(), 12), p, 4 + b.size());
        return true;
    }
    // opaque data whose bytes are not needed: only the length (it may run past the captured bytes)
    bool data(const char *label, bool &cut) {
        const size_t p = at();
        const uint32_t len = r.readUnsignedInt();
        if (!r.ok()) return false;
        line(std::string(label) + ": " + std::to_string(len) + " bytes", p, 4);
        if (len > r.remaining()) { cut = true; return false; }
        r.readFixedOpaque(len);
        return true;
    }
    bool fixed(const char *label, size_t n) {
        const size_t p = at();
        const auto b = r.readFixedOpaque(n);
        if (!r.ok()) return false;
        line(std::string(label) + ": " + hexPreview(b.data(), b.size(), 16), p, n);
        return true;
    }
    bool fh(const char *label, std::string *brief = nullptr) {
        const size_t p = at();
        const auto f = r.readOpaque(128);
        if (!r.ok()) return false;
        const std::string t = hexPreview(f.data(), f.size());
        line(std::string(label) + ": " + t + " (" + std::to_string(f.size()) + " bytes)", p, 4 + f.size());
        if (brief) *brief = t;
        return true;
    }
    bool stateid(const char *label) {
        const size_t p = at();
        const uint32_t seq = r.readUnsignedInt();
        const auto other = r.readFixedOpaque(12);
        if (!r.ok()) return false;
        line(std::string(label) + ": seqid " + std::to_string(seq) + " other " + hexPreview(other.data(), other.size(), 12), p, 16);
        return true;
    }
    bool bitmap(const char *label, std::vector<uint32_t> *out = nullptr) {
        const size_t p = at();
        const uint32_t n = r.readUnsignedInt();
        if (!r.ok() || n > 16 || n * 4 > r.remaining()) { r.readFixedOpaque(0x7FFFFFFF); return false; }
        std::vector<uint32_t> words(n);
        for (auto &w: words) w = r.readUnsignedInt();
        if (!r.ok()) return false;
        std::string names;
        size_t shown = 0;
        for (uint32_t i = 0; i < n * 32; ++i) {
            if (!(words[i / 32] & (1u << (i % 32)))) continue;
            if (shown++ < 12) names += (names.empty() ? "" : ",") + attrText(i);
        }
        if (shown > 12) names += ",...";
        line(std::string(label) + ": " + (names.empty() ? std::string("(none)") : names), p, 4 + 4 * static_cast<size_t>(n));
        if (out) *out = words;
        return true;
    }
    bool changeInfo(const char *label) {
        const size_t p = at();
        const bool atomic = r.readBool();
        const uint64_t before = r.readUnsignedHyper(), after = r.readUnsignedHyper();
        if (!r.ok()) return false;
        line(std::string(label) + ": " + (atomic ? "atomic " : "") + "before " + std::to_string(before) + " after " + std::to_string(after), p, 20);
        return true;
    }
    bool nfstime(const char *label) {
        const size_t p = at();
        const int64_t s = r.readHyper();
        const uint32_t n = r.readUnsignedInt();
        if (!r.ok()) return false;
        line(std::string(label) + ": " + timeText(s, n), p, 12);
        return true;
    }
    bool lockOwner(const char *label) {
        const size_t p = at();
        const uint64_t clientid = r.readUnsignedHyper();
        const auto owner = r.readOpaque(1024);
        if (!r.ok()) return false;
        line(std::string(label) + ": clientid " + hex(clientid) + " owner " + hexPreview(owner.data(), owner.size(), 12), p, 12 + owner.size());
        return true;
    }
    bool nfsace(const char *label) {
        const size_t p = at();
        const uint32_t type = r.readUnsignedInt(), flag = r.readUnsignedInt(), mask = r.readUnsignedInt();
        const std::string who = r.readString(255);
        if (!r.ok()) return false;
        line(std::string(label) + ": type " + std::to_string(type) + " flag " + hex(flag) + " mask " + hex(mask) + " who " + text(who, 63), p, 16 + who.size());
        return true;
    }
    bool channelAttrs(const char *label) {
        const size_t p = at();
        const uint32_t pad = r.readUnsignedInt(), maxReq = r.readUnsignedInt(), maxResp = r.readUnsignedInt(), maxCached = r.readUnsignedInt(), maxOps = r.readUnsignedInt(), maxReqs = r.readUnsignedInt();
        const uint32_t ird = r.readUnsignedInt();
        if (!r.ok() || ird > 1) return false;
        if (ird) r.readUnsignedInt();
        if (!r.ok()) return false;
        line(std::string(label) + ": headerpad " + std::to_string(pad) + " maxrequest " + std::to_string(maxReq) + " maxresponse " + std::to_string(maxResp) + " maxcached " +
                 std::to_string(maxCached) + " maxops " + std::to_string(maxOps) + " maxrequests " + std::to_string(maxReqs), p, at() - p);
        return true;
    }
    // callback_sec_parms4<>
    bool callbackSecParms(const char *label) {
        const size_t p = at();
        const uint32_t n = r.readUnsignedInt();
        if (!r.ok() || n > 8) return false;
        std::string flavors;
        for (uint32_t i = 0; i < n; ++i) {
            const uint32_t flavor = r.readUnsignedInt();
            if (!r.ok()) return false;
            if (flavor == 0) {
                flavors += (flavors.empty() ? "" : ",") + std::string("AUTH_NONE");
            } else if (flavor == 1) {   // authsys_parms: stamp, machinename, uid, gid, gids<>
                r.readUnsignedInt();
                const std::string machine = r.readString(255);
                const uint32_t uid = r.readUnsignedInt(), gid = r.readUnsignedInt(), ngids = r.readUnsignedInt();
                if (!r.ok() || ngids > 16) return false;
                for (uint32_t g = 0; g < ngids; ++g) r.readUnsignedInt();
                if (!r.ok()) return false;
                flavors += (flavors.empty() ? "" : ",") + ("AUTH_SYS machine=" + text(machine, 63) + " uid=" + std::to_string(uid) + " gid=" + std::to_string(gid));
            } else if (flavor == 6) {   // gss_cb_handles4: service, server handle, client handle
                r.readUnsignedInt();
                r.readOpaque(1024);
                r.readOpaque(1024);
                if (!r.ok()) return false;
                flavors += (flavors.empty() ? "" : ",") + std::string("RPCSEC_GSS");
            } else {
                return false;
            }
        }
        line(std::string(label) + ": " + (flavors.empty() ? std::string("none") : flavors), p, at() - p);
        return true;
    }

    // fattr4: bitmap4 and opaque attr_vals<>; the values are decoded in bit order as far as they are understood
    bool fattr(const char *label) {
        const size_t p = at();
        std::vector<uint32_t> words;
        const size_t bmAt = at();
        const uint32_t n = r.readUnsignedInt();
        if (!r.ok() || n > 16 || n * 4 > r.remaining()) { r.readFixedOpaque(0x7FFFFFFF); return false; }
        words.resize(n);
        for (auto &w: words) w = r.readUnsignedInt();
        const size_t valsAt = at();
        const uint32_t len = r.readUnsignedInt();
        if (!r.ok() || len > r.remaining()) { r.readFixedOpaque(0x7FFFFFFF); return false; }
        const auto vals = r.readFixedOpaque(len);
        if (!r.ok()) return false;
        std::string names;
        size_t shown = 0;
        for (uint32_t i = 0; i < n * 32; ++i) {
            if (!(words[i / 32] & (1u << (i % 32)))) continue;
            if (shown++ < 12) names += (names.empty() ? "" : ",") + attrText(i);
        }
        if (shown > 12) names += ",...";
        line(std::string(label) + ": " + (names.empty() ? std::string("(none)") : names), p, at() - p);
        line("Attribute Mask: " + std::to_string(shown) + " attributes", bmAt, 4 + 4 * static_cast<size_t>(n), depth + 1);
        decodeValues(words, vals.data(), vals.size(), valsAt + 4);
        return true;
    }

    void decodeValues(const std::vector<uint32_t> &words, const uint8_t *vals, size_t len, size_t base) {
        XdrReader v(vals, len);
        const int d = depth + 1;
        const auto add = [&](const std::string &t, size_t from) { o.add(t, base + from, base + v.pos() > base + from ? v.pos() - from : 0, d); };
        for (uint32_t bit = 0; bit < words.size() * 32; ++bit) {
            if (!(words[bit / 32] & (1u << (bit % 32)))) continue;
            const size_t from = v.pos();
            const std::string n = attrText(bit);
            bool known = true;
            switch (bit) {
                case 0: case 75: {   // bitmap4
                    const uint32_t c = v.readUnsignedInt();
                    if (!v.ok() || c > 16) { known = false; break; }
                    for (uint32_t i = 0; i < c; ++i) v.readUnsignedInt();
                    add(n + ": " + std::to_string(c) + " words", from);
                    break;
                }
                case 1: { const uint32_t t = v.readUnsignedInt(); if (v.ok()) add(n + ": " + ftype4Name(t) + " (" + std::to_string(t) + ")", from); break; }
                case 2: case 10: case 11: case 14: case 28: case 29: case 35: case 65: case 66: case 76: case 33: {   // unsigned int
                    const uint32_t x = v.readUnsignedInt();
                    if (!v.ok()) break;
                    add(n + ": " + (bit == 33 ? [&] { char b[16]; std::snprintf(b, sizeof b, "%04o", x & 07777); return std::string(b); }() : std::to_string(x)), from);
                    break;
                }
                case 3: case 4: case 20: case 21: case 22: case 23: case 27: case 30: case 31: case 38: case 39: case 40: case 42: case 43: case 44: case 45: case 55: case 73: {   // unsigned hyper
                    const uint64_t x = v.readUnsignedHyper();
                    if (v.ok()) add(n + ": " + std::to_string(x), from);
                    break;
                }
                case 5: case 6: case 7: case 9: case 15: case 16: case 17: case 18: case 19: case 25: case 26: case 34: case 46: {   // bool
                    const bool x = v.readBool();
                    if (v.ok()) add(n + ": " + (x ? "True" : "False"), from);
                    break;
                }
                case 8: case 60: {   // fsid4 {major, minor} / change_policy {major, minor}
                    const uint64_t x = v.readUnsignedHyper(), y = v.readUnsignedHyper();
                    if (v.ok()) add(n + ": " + std::to_string(x) + "." + std::to_string(y), from);
                    break;
                }
                case 12: {
                    const auto f = v.readOpaque(128);
                    if (v.ok()) add(n + ": " + hexPreview(f.data(), f.size()) + " (" + std::to_string(f.size()) + " bytes)", from);
                    break;
                }
                case 13: case 58: case 59: {   // nfsace4<> (dacl / sacl have a flag word in front)
                    if (bit != 13) v.readUnsignedInt();
                    const uint32_t c = v.readUnsignedInt();
                    if (!v.ok() || c > 64) { known = false; break; }
                    for (uint32_t i = 0; i < c && v.ok(); ++i) { v.readUnsignedInt(); v.readUnsignedInt(); v.readUnsignedInt(); v.readString(255); }
                    if (v.ok()) add(n + ": " + std::to_string(c) + " entries", from);
                    break;
                }
                case 32: case 36: case 37: {   // utf8str
                    const std::string s = v.readString(255);
                    if (v.ok()) add(n + ": " + text(s, 63), from);
                    break;
                }
                case 41: {   // specdata4
                    const uint32_t x = v.readUnsignedInt(), y = v.readUnsignedInt();
                    if (v.ok()) add(n + ": " + std::to_string(x) + "," + std::to_string(y), from);
                    break;
                }
                case 47: case 49: case 50: case 51: case 52: case 53: case 56: case 57: {   // nfstime4
                    const int64_t s = v.readHyper();
                    const uint32_t ns = v.readUnsignedInt();
                    if (v.ok()) add(n + ": " + timeText(s, ns), from);
                    break;
                }
                case 62: case 64: {   // layouttype4<>
                    const uint32_t c = v.readUnsignedInt();
                    if (!v.ok() || c > 16) { known = false; break; }
                    for (uint32_t i = 0; i < c; ++i) v.readUnsignedInt();
                    if (v.ok()) add(n + ": " + std::to_string(c) + " layout types", from);
                    break;
                }
                default: known = false;   // fs_locations, the settime4 forms, mdsthreshold ...: not decoded
            }
            if (!known || !v.ok()) {
                o.add("Remaining attributes not decoded (from " + n + ")", base + from, 0, d);
                return;
            }
        }
    }
};

// ---- the arguments of one operation -------------------------------------------------------------------------------------------

std::string shareAccess(uint32_t v) {
    std::string s;
    const auto add = [&](const char *t) { s += (s.empty() ? "" : "|") + std::string(t); };
    switch (v & 3) { case 1: add("READ"); break; case 2: add("WRITE"); break; case 3: add("BOTH"); break; default: break; }
    if (v & 0x100) add("WANT_DELEG");
    return s.empty() ? hex(v) : s;
}

// the delegation part of an OPEN result / WANT_DELEGATION result
bool openDelegation(V4 &v) {
    uint32_t type = 0;
    if (!v.u32("Delegation Type", &type)) return false;
    auto &r = v.r;
    if (type == 0) return true;
    if (type == 1 || type == 2) {
        if (!v.stateid("Delegation Stateid")) return false;
        if (!v.boolean("Recall")) return false;
        if (type == 2) {
            uint32_t limitby = 0;
            if (!v.u32("Space Limit By", &limitby)) return false;
            if (limitby == 1) { if (!v.u64("Space Limit Size")) return false; }
            else if (limitby == 2) { if (!v.u32("Number of Blocks") || !v.u32("Bytes per Block")) return false; }
            else return false;
        }
        return v.nfsace("Permissions");
    }
    if (type == 3) {   // OPEN_DELEGATE_NONE_EXT (4.1): why not
        uint32_t why = 0;
        if (!v.u32("Why No Delegation", &why)) return false;
        if (why == 3 || why == 4) return v.boolean("Server Will Push");
        return true;
    }
    (void)r;
    return false;
}

struct OpResult {
    bool ok = true;          // the arguments / results were understood and consumed: the next operation can be read
    std::string note;        // a short key argument for the Info column
};

OpResult opArgs(V4 &v, uint32_t op) {
    OpResult res;
    auto &r = v.r;
    bool ok = true;
    bool cut = false;
    std::string s;
    switch (op) {
        case 3: ok = v.flags("Access Request"); break;
        case 4: ok = v.u32("Sequence ID") && v.stateid("Stateid"); break;
        case 5: ok = v.u64("Offset") && v.u32("Count"); break;
        case 6: {   // CREATE: createtype4, name, createattrs
            uint32_t type = 0;
            ok = v.u32("Type", &type, [](uint32_t t) -> const char * { return ftype4Name(t); });
            if (ok && type == 5) ok = v.string("Link Data");
            else if (ok && (type == 3 || type == 4)) ok = v.u32("Major") && v.u32("Minor");
            ok = ok && v.string("Name", &s) && v.fattr("Attributes");
            res.note = s;
            break;
        }
        case 7: ok = v.u64("Client ID"); break;
        case 8: ok = v.stateid("Stateid"); break;
        case 9: ok = v.bitmap("Attribute Request"); break;
        case 10: case 16: case 23: case 24: case 27: case 31: case 32: break;   // no arguments
        case 11: ok = v.string("New Name", &s); res.note = s; break;
        case 12: {   // LOCK
            bool newOwner = false;
            ok = v.u32("Lock Type") && v.boolean("Reclaim") && v.u64("Offset") && v.u64("Length") && v.boolean("New Lock Owner", &newOwner);
            if (ok && newOwner) ok = v.u32("Open Sequence ID") && v.stateid("Open Stateid") && v.u32("Lock Sequence ID") && v.lockOwner("Lock Owner");
            else if (ok) ok = v.stateid("Lock Stateid") && v.u32("Lock Sequence ID");
            break;
        }
        case 13: ok = v.u32("Lock Type") && v.u64("Offset") && v.u64("Length") && v.lockOwner("Lock Owner"); break;
        case 14: ok = v.u32("Lock Type") && v.u32("Sequence ID") && v.stateid("Lock Stateid") && v.u64("Offset") && v.u64("Length"); break;
        case 15: ok = v.string("Name", &s); res.note = s; break;
        case 17: case 37: ok = v.fattr("Attributes"); break;
        case 18: {   // OPEN: seqid, share_access, share_deny, owner, openhow, claim
            uint32_t access = 0, deny = 0;
            const size_t p = v.at() + 4;
            ok = v.u32("Sequence ID") && v.flags("Share Access", &access) && v.u32("Share Deny", &deny) && v.lockOwner("Owner");
            if (ok) v.o.items.push_back(Item{"Share Access (decoded): " + shareAccess(access), p, 4, v.depth + 1});
            uint32_t opentype = 0;
            if (ok) ok = v.u32("Open Type", &opentype, [](uint32_t t) -> const char * { return t == 0 ? "OPEN4_NOCREATE" : t == 1 ? "OPEN4_CREATE" : nullptr; });
            if (ok && opentype == 1) {
                uint32_t mode = 0;
                ok = v.u32("Create Mode", &mode, [](uint32_t m) -> const char * { return m == 0 ? "UNCHECKED4" : m == 1 ? "GUARDED4" : m == 2 ? "EXCLUSIVE4" : m == 3 ? "EXCLUSIVE4_1" : nullptr; });
                if (ok && (mode == 0 || mode == 1)) ok = v.fattr("Create Attributes");
                else if (ok && mode == 2) ok = v.fixed("Verifier", 8);
                else if (ok && mode == 3) ok = v.fixed("Verifier", 8) && v.fattr("Create Attributes");
                else ok = false;
            }
            uint32_t claim = 0;
            if (ok) ok = v.u32("Claim Type", &claim, [](uint32_t c) -> const char * {
                static const char *const n[] = {"CLAIM_NULL", "CLAIM_PREVIOUS", "CLAIM_DELEGATE_CUR", "CLAIM_DELEGATE_PREV", "CLAIM_FH", "CLAIM_DELEG_CUR_FH", "CLAIM_DELEG_PREV_FH"};
                return c < 7 ? n[c] : nullptr; });
            if (ok) {
                switch (claim) {
                    case 0: ok = v.string("Name", &s); res.note = s; break;
                    case 1: ok = v.u32("Delegate Type"); break;
                    case 2: ok = v.stateid("Delegate Stateid") && v.string("Name", &s); res.note = s; break;
                    case 3: ok = v.string("Name", &s); res.note = s; break;
                    case 4: case 6: break;
                    case 5: ok = v.stateid("Delegate Stateid"); break;
                    default: ok = false;
                }
            }
            break;
        }
        case 19: ok = v.boolean("Create Directory"); break;
        case 20: ok = v.stateid("Open Stateid") && v.u32("Sequence ID"); break;
        case 21: ok = v.stateid("Open Stateid") && v.u32("Sequence ID") && v.flags("Share Access") && v.u32("Share Deny"); break;
        case 22: ok = v.fh("File Handle", &s); res.note = s; break;
        case 25: ok = v.stateid("Stateid") && v.u64("Offset") && v.u32("Count"); break;
        case 26: ok = v.u64("Cookie") && v.fixed("Cookie Verifier", 8) && v.u32("Directory Count") && v.u32("Max Count") && v.bitmap("Attribute Request"); break;
        case 28: ok = v.string("Name", &s); res.note = s; break;
        case 29: {
            std::string to;
            ok = v.string("Old Name", &s) && v.string("New Name", &to);
            res.note = s + "->" + to;
            break;
        }
        case 30: ok = v.u64("Client ID"); break;
        case 33: ok = v.string("Name", &s); res.note = s; break;
        case 34: ok = v.stateid("Stateid") && v.fattr("Attributes"); break;
        case 35: ok = v.fixed("Verifier", 8) && v.opaque("Client ID String", 1024) && v.u32("Callback Program") && v.string("Callback Netid", nullptr, 32) && v.string("Callback Address", nullptr, 255) && v.u32("Callback Ident"); break;
        case 36: ok = v.u64("Client ID") && v.fixed("Confirm Verifier", 8); break;
        case 38: {   // WRITE: stateid, offset, stable, data
            uint32_t stable = 0;
            ok = v.stateid("Stateid") && v.u64("Offset") && v.u32("Stable", &stable, [](uint32_t t) -> const char * { return stableName(t); }) && v.data("Data", cut);
            break;
        }
        case 39: ok = v.lockOwner("Lock Owner"); break;
        // ---- NFSv4.1
        case 40: ok = v.u32("Callback Program") && v.callbackSecParms("Security Parameters"); break;
        case 41: ok = v.fixed("Session ID", 16) && v.u32("Direction") && v.boolean("Use RDMA"); break;
        case 42: {   // EXCHANGE_ID
            uint32_t how = 0;
            ok = v.fixed("Verifier", 8) && v.opaque("Client Owner ID", 1024) && v.flags("Flags") && v.u32("State Protection", &how);
            if (ok && how == 1) ok = v.bitmap("Must Enforce") && v.bitmap("Must Allow");
            else if (ok && how == 2) {
                ok = v.bitmap("Must Enforce") && v.bitmap("Must Allow");
                for (int i = 0; ok && i < 2; ++i) {   // hash algorithms, encryption algorithms: oid<>
                    const uint32_t n = r.readUnsignedInt();
                    if (!r.ok() || n > 16) { ok = false; break; }
                    for (uint32_t k = 0; k < n && r.ok(); ++k) r.readOpaque(64);
                    ok = r.ok();
                }
                ok = ok && v.u32("SSV Window") && v.u32("SSV GSS Handles");
            } else if (ok && how != 0) ok = false;
            if (ok) {
                const uint32_t n = r.readUnsignedInt();
                if (!r.ok() || n > 1) { ok = false; break; }
                if (n) { ok = v.string("Implementation Domain", nullptr, 255) && v.string("Implementation Name", nullptr, 255) && v.nfstime("Implementation Date"); }
            }
            break;
        }
        case 43: ok = v.u64("Client ID") && v.u32("Sequence ID") && v.flags("Flags") && v.channelAttrs("Fore Channel Attributes") && v.channelAttrs("Back Channel Attributes") && v.u32("Callback Program") && v.callbackSecParms("Security Parameters"); break;
        case 44: ok = v.fixed("Session ID", 16); break;
        case 45: ok = v.stateid("Stateid"); break;
        case 46: ok = v.boolean("Signal Delegation Available") && v.bitmap("Notification Types") && v.nfstime("Child Attribute Delay") && v.nfstime("Directory Attribute Delay") && v.bitmap("Child Attributes") && v.bitmap("Directory Attributes"); break;
        case 47: ok = v.fixed("Device ID", 16) && v.u32("Layout Type") && v.u32("Max Count") && v.bitmap("Notification Types"); break;
        case 48: ok = v.u32("Layout Type") && v.u32("Max Devices") && v.u64("Cookie") && v.fixed("Cookie Verifier", 8); break;
        case 49: {
            bool newOffset = false, newTime = false;
            ok = v.u64("Offset") && v.u64("Length") && v.boolean("Reclaim") && v.stateid("Stateid") && v.boolean("New Offset Present", &newOffset);
            if (ok && newOffset) ok = v.u64("Last Write Offset");
            ok = ok && v.boolean("New Time Present", &newTime);
            if (ok && newTime) ok = v.nfstime("Time Modify");
            ok = ok && v.u32("Layout Type") && v.opaque("Layout Update");
            break;
        }
        case 50: ok = v.boolean("Signal Layout Available") && v.u32("Layout Type") && v.u32("IO Mode") && v.u64("Offset") && v.u64("Length") && v.u64("Minimum Length") && v.stateid("Stateid") && v.u32("Max Count"); break;
        case 51: {
            uint32_t type = 0;
            ok = v.boolean("Reclaim") && v.u32("Layout Type") && v.u32("IO Mode") && v.u32("Return Type", &type);
            if (ok && type == 1) ok = v.u64("Offset") && v.u64("Length") && v.stateid("Stateid") && v.opaque("Layout Return");
            else if (ok && type != 2 && type != 3) ok = false;
            break;
        }
        case 52: ok = v.u32("Security Info Style"); break;
        case 53: ok = v.fixed("Session ID", 16) && v.u32("Sequence ID") && v.u32("Slot ID") && v.u32("Highest Slot ID") && v.boolean("Cache This"); break;
        case 54: ok = v.opaque("SSV") && v.opaque("Digest"); break;
        case 55: {
            const uint32_t n = r.readUnsignedInt();
            if (!r.ok() || n > 64) { ok = false; break; }
            v.line("Stateids: " + std::to_string(n), v.at() - 4, 4);
            for (uint32_t i = 0; ok && i < n; ++i) ok = v.stateid("Stateid");
            break;
        }
        case 56: {
            uint32_t claim = 0;
            ok = v.flags("Want") && v.u32("Claim Type", &claim);
            if (ok && claim == 1) ok = v.u32("Delegate Type");
            else if (ok && claim != 4 && claim != 6) ok = false;
            break;
        }
        case 57: ok = v.u64("Client ID"); break;
        case 58: ok = v.boolean("One File System"); break;
        case 10044: break;
        default: ok = false;
    }
    res.ok = ok && !cut && r.ok();
    if (cut) v.line("[the data goes on past the captured bytes]", v.at(), 0);
    return res;
}

// ---- the result of one operation ----------------------------------------------------------------------------------------------

bool lockDenied(V4 &v) {
    return v.u64("Offset") && v.u64("Length") && v.u32("Lock Type") && v.lockOwner("Owner");
}

// secinfo4<>
bool secInfo(V4 &v) {
    auto &r = v.r;
    const uint32_t n = r.readUnsignedInt();
    if (!r.ok() || n > 16) return false;
    v.line("Security Mechanisms: " + std::to_string(n), v.at() - 4, 4);
    for (uint32_t i = 0; i < n; ++i) {
        uint32_t flavor = 0;
        if (!v.u32("Flavor", &flavor, [](uint32_t f) -> const char * { return f == 0 ? "AUTH_NONE" : f == 1 ? "AUTH_SYS" : f == 6 ? "RPCSEC_GSS" : nullptr; })) return false;
        if (flavor == 6 && !(v.opaque("OID", 64) && v.u32("QOP") && v.u32("Service"))) return false;
    }
    return true;
}

// the result of operation `op` whose status was `status` (the status itself is already shown); `note` goes to the Info column
OpResult opResult(V4 &v, uint32_t op, uint32_t status) {
    OpResult res;
    auto &r = v.r;
    bool ok = true;
    bool cut = false;
    std::string s;
    if (status != 0) {
        // the few operations that answer more than the status on an error; the compound ends here
        if ((op == 12 || op == 13) && status == 10010) lockDenied(v);
        else if (op == 34) v.bitmap("Attributes Set");
        else if (op == 35 && status == 10017) { v.string("Callback Netid", nullptr, 32); v.string("Callback Address", nullptr, 255); }
        res.ok = false;
        return res;
    }
    switch (op) {
        case 3: ok = v.flags("Supported") && v.flags("Access"); break;
        case 4: case 12: case 14: case 20: case 21: ok = v.stateid("Stateid"); break;
        case 5: ok = v.fixed("Write Verifier", 8); break;
        case 6: ok = v.changeInfo("Change Info") && v.bitmap("Attributes Set"); break;
        case 9: ok = v.fattr("Attributes"); break;
        case 10: ok = v.fh("File Handle", &s); res.note = s; break;
        case 11: case 28: ok = v.changeInfo("Change Info"); break;
        case 18: {   // OPEN: stateid, change_info, rflags, attrset, delegation
            ok = v.stateid("Stateid") && v.changeInfo("Change Info") && v.flags("Result Flags") && v.bitmap("Attributes Set") && openDelegation(v);
            break;
        }
        case 25: {   // READ: eof, data
            bool eof = false;
            ok = v.boolean("EOF", &eof) && v.data("Data", cut);
            if (eof) res.note = "eof";
            break;
        }
        case 26: {   // READDIR: cookie verifier, entries, eof
            ok = v.fixed("Cookie Verifier", 8);
            if (!ok) break;
            const size_t listAt = v.at();
            size_t count = 0;
            std::vector<Item> entries;
            bool complete = true;
            while (count < kMaxListed) {
                const size_t at = v.at();
                if (!r.readBool()) break;
                const uint64_t cookie = r.readUnsignedHyper();
                const std::string name = r.readString(1024);
                if (!r.ok()) { complete = false; break; }
                // the attributes of the entry: bitmap and one opaque
                const uint32_t n = r.readUnsignedInt();
                if (!r.ok() || n > 16 || n * 4 > r.remaining()) { complete = false; break; }
                for (uint32_t i = 0; i < n; ++i) r.readUnsignedInt();
                const uint32_t len = r.readUnsignedInt();
                if (!r.ok() || len > r.remaining()) { complete = false; break; }
                r.readFixedOpaque(len);
                ++count;
                if (entries.size() < kMaxShown) entries.push_back(Item{text(name, 100) + " (cookie " + std::to_string(cookie) + ")", at, v.at() - at, v.depth + 1});
            }
            bool eof = false;
            if (complete) { eof = r.readBool(); complete = r.ok(); }
            res.note = std::to_string(count) + (count == 1 ? " entry" : " entries") + (complete ? (eof ? " eof" : "") : " [cut]");
            v.line("Entries: " + std::to_string(count) + (complete ? "" : " (cut)"), listAt, v.at() - listAt);
            for (auto &e: entries) v.o.items.push_back(std::move(e));
            ok = complete;
            break;
        }
        case 27: ok = v.string("Link Text", &s); res.note = s; break;
        case 29: ok = v.changeInfo("Source Change Info") && v.changeInfo("Target Change Info"); break;
        case 33: case 52: ok = secInfo(v); break;
        case 34: ok = v.bitmap("Attributes Set"); break;
        case 35: {
            uint64_t id = 0;
            ok = v.u64("Client ID", &id) && v.fixed("Confirm Verifier", 8);
            res.note = "clientid " + hex(id);
            break;
        }
        case 38: {
            uint32_t count = 0;
            ok = v.u32("Count", &count) && v.u32("Committed", nullptr, [](uint32_t t) -> const char * { return stableName(t); }) && v.fixed("Write Verifier", 8);
            res.note = "count=" + std::to_string(count);
            break;
        }
        // results that are void when the operation succeeded
        case 7: case 8: case 13: case 15: case 16: case 17: case 19: case 22: case 23: case 24: case 30: case 31: case 32: case 36: case 37: case 39:
        case 40: case 44: case 45: case 57: case 58: break;
        // ---- NFSv4.1
        case 41: ok = v.fixed("Session ID", 16) && v.u32("Direction") && v.boolean("Use RDMA"); break;
        case 42: {   // EXCHANGE_ID
            uint64_t id = 0;
            uint32_t how = 0;
            ok = v.u64("Client ID", &id) && v.u32("Sequence ID") && v.flags("Flags") && v.u32("State Protection", &how);
            res.note = "clientid " + hex(id);
            if (ok && how == 1) ok = v.bitmap("Must Enforce") && v.bitmap("Must Allow");
            else if (ok && how == 2) {
                ok = v.bitmap("Must Enforce") && v.bitmap("Must Allow") && v.u32("Hash Algorithm") && v.u32("Encryption Algorithm") && v.u32("SSV Length") && v.u32("Window");
                if (ok) {
                    const uint32_t n = r.readUnsignedInt();
                    if (!r.ok() || n > 16) { ok = false; break; }
                    for (uint32_t i = 0; i < n && r.ok(); ++i) { r.readOpaque(1024); }
                    ok = r.ok();
                }
            } else if (ok && how != 0) ok = false;
            ok = ok && v.u64("Server Owner Minor ID") && v.opaque("Server Owner Major ID", 1024) && v.opaque("Server Scope", 1024);
            if (ok) {
                const uint32_t n = r.readUnsignedInt();
                if (!r.ok() || n > 1) { ok = false; break; }
                if (n) ok = v.string("Implementation Domain", nullptr, 255) && v.string("Implementation Name", nullptr, 255) && v.nfstime("Implementation Date");
            }
            break;
        }
        case 43: ok = v.fixed("Session ID", 16) && v.u32("Sequence ID") && v.flags("Flags") && v.channelAttrs("Fore Channel Attributes") && v.channelAttrs("Back Channel Attributes"); break;
        case 49: {
            bool present = false;
            ok = v.boolean("New Size Present", &present);
            if (ok && present) ok = v.u64("New Size");
            break;
        }
        case 51: {
            bool present = false;
            ok = v.boolean("Layout Stateid Present", &present);
            if (ok && present) ok = v.stateid("Layout Stateid");
            break;
        }
        case 53: {
            uint32_t seq = 0, slot = 0;
            ok = v.fixed("Session ID", 16) && v.u32("Sequence ID", &seq) && v.u32("Slot ID", &slot) && v.u32("Highest Slot ID") && v.u32("Target Highest Slot ID") && v.flags("Status Flags");
            res.note = "slot " + std::to_string(slot) + " seq " + std::to_string(seq);
            break;
        }
        case 54: ok = v.opaque("Digest"); break;
        case 55: {
            const uint32_t n = r.readUnsignedInt();
            if (!r.ok() || n > 64) { ok = false; break; }
            v.line("Statuses: " + std::to_string(n), v.at() - 4, 4);
            for (uint32_t i = 0; ok && i < n; ++i) ok = v.u32("Status", nullptr, [](uint32_t t) -> const char * { return nfsstat4Name(t); });
            break;
        }
        case 56: ok = openDelegation(v); break;
        case 10044: break;
        default: ok = false;   // layout operations, GET_DIR_DELEGATION, GETDEVICE*, the operations of 4.2: not decoded
    }
    res.ok = ok && !cut && r.ok();
    return res;
}

std::string opLabel(uint32_t op) {
    if (const char *n = nfs4OpName(op)) return n;
    if (op == 10044) return "ILLEGAL";
    static const char *const v42[] = {"ALLOCATE", "COPY", "COPY_NOTIFY", "DEALLOCATE", "IO_ADVISE", "LAYOUTERROR", "LAYOUTSTATS", "OFFLOAD_CANCEL", "OFFLOAD_STATUS",
                                      "READ_PLUS", "SEEK", "WRITE_SAME", "CLONE"};
    if (op >= 59 && op <= 71) return v42[op - 59];
    return "op " + std::to_string(op);
}

// the operation names, comma separated, for the nfs.operations filter field (the first 16)
std::string opsCsv(const std::vector<uint32_t> &ops) {
    std::string s;
    for (size_t i = 0; i < ops.size() && i < 16; ++i) s += (s.empty() ? "" : ",") + opLabel(ops[i]);
    return s;
}

} // namespace

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
    o.add("Tag: " + text(tag, 63), argsAt, 4 + tag.size());
    o.add("Minor Version: " + std::to_string(minor), argsAt + 4 + ((tag.size() + 3) & ~size_t(3)), 4);
    o.add("Operations: " + std::to_string(nops), a.at() - 4, 4);
    std::vector<uint32_t> ops;
    std::string list;
    size_t decoded = 0;
    bool complete = true;
    for (uint32_t i = 0; i < nops && i < kMaxOps; ++i) {
        const size_t opAt = a.at();
        if (r.remaining() < 4) { complete = false; break; }
        const uint32_t op = r.readUnsignedInt();
        const std::string name = opLabel(op);
        const size_t idx = o.items.size();
        o.add("Operation " + std::to_string(i + 1) + ": " + name + " (" + std::to_string(op) + ")", opAt, 4, 1);
        ops.push_back(op);
        V4 v(a, o, 2);
        const OpResult res = opArgs(v, op);
        o.items[idx].len = a.at() - opAt;
        ++decoded;
        if (decoded <= 12) list += (list.empty() ? "" : ", ") + name + (res.note.empty() ? std::string() : " " + text(res.note, 40));
        if (!res.ok) { complete = false; break; }
    }
    if (decoded < nops) complete = false;
    if (nops > kMaxOps) complete = false;
    if (!complete && decoded < nops) {
        o.add(std::to_string(nops - decoded) + " more operation" + (nops - decoded == 1 ? "" : "s") + " not decoded", a.at(), 0, 1);
    }
    o.info = "minor=" + std::to_string(minor) + " ops=" + std::to_string(nops);
    if (!list.empty()) o.info += " [" + list + (decoded > 12 || (!complete && decoded < nops) ? ", ..." : "") + "]";
    o.ops = opsCsv(ops);
}

void nfs4Reply(uint32_t proc, Cursor &a, Out &o) {
    if (proc != 1) return;
    auto &r = a.r;
    const size_t startAt = a.at();
    const uint32_t status = r.readUnsignedInt();
    if (!r.ok()) return;
    const std::string tag = r.readString(255);
    const uint32_t nres = r.readUnsignedInt();
    if (!r.ok()) return;
    const char *sn = nfsstat4Name(status);
    const std::string statusText = sn ? sn : "NFS4 status " + std::to_string(status);
    o.hasResult = true;
    o.result = status;
    o.add("Status: " + (sn ? std::string(sn) : std::string("unknown")) + " (" + std::to_string(status) + ")", startAt, 4);
    o.add("Tag: " + text(tag, 63), startAt + 4, 4 + tag.size());
    o.add("Results: " + std::to_string(nres), a.at() - 4, 4);
    std::vector<uint32_t> ops;
    std::string list;
    size_t decoded = 0;
    bool complete = true;
    for (uint32_t i = 0; i < nres && i < kMaxOps; ++i) {
        const size_t opAt = a.at();
        if (r.remaining() < 8) { complete = false; break; }
        const uint32_t op = r.readUnsignedInt();
        const uint32_t st = r.readUnsignedInt();
        const std::string name = opLabel(op);
        const char *stn = nfsstat4Name(st);
        const size_t idx = o.items.size();
        o.add("Result " + std::to_string(i + 1) + ": " + name + " (" + std::to_string(op) + "), " + (stn ? stn : "status " + std::to_string(st)), opAt, 8, 1);
        ops.push_back(op);
        V4 v(a, o, 2);
        const OpResult res = opResult(v, op, st);
        o.items[idx].len = a.at() - opAt;
        ++decoded;
        if (decoded <= 12) list += (list.empty() ? "" : ", ") + name + (st != 0 ? std::string(" ") + (stn ? stn : std::to_string(st)) : std::string()) + (res.note.empty() ? std::string() : " " + text(res.note, 40));
        if (!res.ok) { if (st == 0) complete = false; break; }
    }
    if (decoded < nres && complete == true && status == 0) complete = false;
    if (!complete && decoded < nres) o.add(std::to_string(nres - decoded) + " more result" + (nres - decoded == 1 ? "" : "s") + " not decoded", a.at(), 0, 1);
    o.info = statusText;
    if (!list.empty()) o.info += " [" + list + (decoded > 12 || (!complete && decoded < nres) ? ", ..." : "") + "]";
    o.ops = opsCsv(ops);
}

} // namespace dissect::rpcdec
