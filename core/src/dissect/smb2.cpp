// SMB2 / SMB3 ([MS-SMB2]) over Direct TCP (port 445: a zero byte and a 24 bit length in front) or NetBIOS (port 139: the NBSS
// session service header with its message types). Decoded: the 64 byte header of every command of a compound message (sync and
// async form, credits, NextCommand, related operations), the SMB3 Transform header (encrypted messages are named, not decrypted),
// and the bodies of Negotiate (dialects, contexts), Session Setup (NTLMSSP message type, user and domain of the authenticate
// message), Tree Connect, Create (with its create contexts), Close, Flush, Read, Write, IOCTL, Query Directory, Change Notify,
// Query Info and Set Info (common [MS-FSCC] information classes), Lock, Oplock Break and the Error response.
#include "smb2.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "reader.h"
#include "smb2_session.h"
#include "spnego.h"
#include "util.h"

using packet::Field;

namespace dissect {

namespace {

constexpr size_t kMaxMessage = 8u << 20;   // not more than the stream table buffers (a Direct TCP message can be 16 MB - 1)
constexpr size_t kHeader = 64;

// app_flags
constexpr uint16_t kFlagResponse = 1, kFlagSigned = 2, kFlagEncrypted = 4, kFlagCompressed = 8, kFlagDialect = 0x10, kFlagAsync = 0x20, kFlagCompound = 0x40, kFlagPipe = 0x80;

const char *commandName(uint16_t cmd) {
    switch (cmd) {
        case 0x0000: return "Negotiate";
        case 0x0001: return "Session Setup";
        case 0x0002: return "Logoff";
        case 0x0003: return "Tree Connect";
        case 0x0004: return "Tree Disconnect";
        case 0x0005: return "Create";
        case 0x0006: return "Close";
        case 0x0007: return "Flush";
        case 0x0008: return "Read";
        case 0x0009: return "Write";
        case 0x000A: return "Lock";
        case 0x000B: return "Ioctl";
        case 0x000C: return "Cancel";
        case 0x000D: return "Echo";
        case 0x000E: return "Query Directory";
        case 0x000F: return "Change Notify";
        case 0x0010: return "Query Info";
        case 0x0011: return "Set Info";
        case 0x0012: return "Oplock Break";
        default: return "Unknown";
    }
}

// [MS-ERREF] 2.3 NTSTATUS values that SMB2 servers answer with
const char *ntStatusName(uint32_t status) {
    switch (status) {
        case 0x00000000: return "STATUS_SUCCESS";
        case 0x00000103: return "STATUS_PENDING";
        case 0x0000010B: return "STATUS_NOTIFY_CLEANUP";
        case 0x0000010C: return "STATUS_NOTIFY_ENUM_DIR";
        case 0x80000005: return "STATUS_BUFFER_OVERFLOW";
        case 0x80000006: return "STATUS_NO_MORE_FILES";
        case 0xC0000001: return "STATUS_UNSUCCESSFUL";
        case 0xC0000002: return "STATUS_NOT_IMPLEMENTED";
        case 0xC0000008: return "STATUS_INVALID_HANDLE";
        case 0xC000000D: return "STATUS_INVALID_PARAMETER";
        case 0xC000000F: return "STATUS_NO_SUCH_FILE";
        case 0xC0000016: return "STATUS_MORE_PROCESSING_REQUIRED";
        case 0xC0000022: return "STATUS_ACCESS_DENIED";
        case 0xC0000023: return "STATUS_BUFFER_TOO_SMALL";
        case 0xC0000033: return "STATUS_OBJECT_NAME_INVALID";
        case 0xC0000034: return "STATUS_OBJECT_NAME_NOT_FOUND";
        case 0xC0000035: return "STATUS_OBJECT_NAME_COLLISION";
        case 0xC000003A: return "STATUS_OBJECT_PATH_NOT_FOUND";
        case 0xC0000043: return "STATUS_SHARING_VIOLATION";
        case 0xC0000056: return "STATUS_DELETE_PENDING";
        case 0xC000005E: return "STATUS_NO_LOGON_SERVERS";
        case 0xC000006D: return "STATUS_LOGON_FAILURE";
        case 0xC000006E: return "STATUS_ACCOUNT_RESTRICTION";
        case 0xC000006F: return "STATUS_INVALID_LOGON_HOURS";
        case 0xC0000070: return "STATUS_INVALID_WORKSTATION";
        case 0xC0000071: return "STATUS_PASSWORD_EXPIRED";
        case 0xC0000072: return "STATUS_ACCOUNT_DISABLED";
        case 0xC000009A: return "STATUS_INSUFFICIENT_RESOURCES";
        case 0xC00000BA: return "STATUS_FILE_IS_A_DIRECTORY";
        case 0xC00000BB: return "STATUS_NOT_SUPPORTED";
        case 0xC00000C9: return "STATUS_NETWORK_NAME_DELETED";
        case 0xC00000CC: return "STATUS_BAD_NETWORK_NAME";
        case 0xC0000101: return "STATUS_DIRECTORY_NOT_EMPTY";
        case 0xC0000103: return "STATUS_NOT_A_DIRECTORY";
        case 0xC0000120: return "STATUS_CANCELLED";
        case 0xC0000128: return "STATUS_FILE_CLOSED";
        case 0xC0000133: return "STATUS_TIME_DIFFERENCE_AT_DC";
        case 0xC0000203: return "STATUS_USER_SESSION_DELETED";
        case 0xC0000225: return "STATUS_NOT_FOUND";
        case 0xC0000234: return "STATUS_ACCOUNT_LOCKED_OUT";
        default: return nullptr;
    }
}

const char *dialectName(uint16_t d) {
    switch (d) {
        case 0x0202: return "SMB 2.0.2";
        case 0x0210: return "SMB 2.1";
        case 0x0300: return "SMB 3.0";
        case 0x0302: return "SMB 3.0.2";
        case 0x0311: return "SMB 3.1.1";
        case 0x02FF: return "SMB 2.???";
        default: return "unknown dialect";
    }
}

const char *nbssTypeName(uint8_t t) {
    switch (t) {
        case 0x00: return "Session Message";
        case 0x81: return "Session Request";
        case 0x82: return "Positive Session Response";
        case 0x83: return "Negative Session Response";
        case 0x84: return "Retarget Session Response";
        case 0x85: return "Session Keep Alive";
        default: return nullptr;
    }
}

bool smbMagic(const uint8_t *p, uint8_t first) { return p[0] == first && p[1] == 'S' && p[2] == 'M' && p[3] == 'B'; }

std::string utf16(const uint8_t *p, size_t bytes, size_t maxChars = 200) {
    std::string out;
    for (size_t i = 0; i + 1 < bytes && out.size() < maxChars; i += 2) {
        const uint16_t ch = static_cast<uint16_t>(p[i] | (p[i + 1] << 8));
        out += (ch >= 32 && ch < 127) ? static_cast<char>(ch) : '?';
    }
    if (bytes / 2 > maxChars) out += "...";
    return out;
}

std::string hex64(uint64_t v) {
    char b[24];
    std::snprintf(b, sizeof b, "0x%016llx", static_cast<unsigned long long>(v));
    return b;
}

std::string asciiHex(const uint8_t *p, size_t n) {
    std::string out;
    char b[4];
    for (size_t i = 0; i < n; ++i) { std::snprintf(b, sizeof b, "%02x", p[i]); out += b; }
    return out;
}

uint64_t le64(const uint8_t *p) { return static_cast<uint64_t>(le32(reinterpret_cast<const char *>(p))) | (static_cast<uint64_t>(le32(reinterpret_cast<const char *>(p) + 4)) << 32); }

// FILETIME (100 ns since 1601-01-01 UTC) as "YYYY-MM-DD HH:MM:SS UTC"; civil-from-days after H. Hinnant
std::string fileTime(uint64_t ft) {
    if (ft == 0) return "not set";
    if (ft >= 0x7FFFFFFFFFFFFFFFull) return "never";
    const int64_t secs = static_cast<int64_t>(ft / 10000000ull) - 11644473600ll;
    int64_t days = secs / 86400, rem = secs % 86400;
    if (rem < 0) { rem += 86400; --days; }
    days += 719468;
    const int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const int64_t doe = days - era * 146097;
    const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const int64_t mp = (5 * doy + 2) / 153;
    const int64_t d = doy - (153 * mp + 2) / 5 + 1;
    const int64_t m = mp < 10 ? mp + 3 : mp - 9;
    const int64_t y = yoe + era * 400 + (m <= 2);
    char b[48];
    std::snprintf(b, sizeof b, "%04lld-%02lld-%02lld %02lld:%02lld:%02lld UTC", static_cast<long long>(y), static_cast<long long>(m), static_cast<long long>(d),
                  static_cast<long long>(rem / 3600), static_cast<long long>(rem % 3600 / 60), static_cast<long long>(rem % 60));
    return b;
}

std::string bitNames(uint32_t v, const std::pair<uint32_t, const char *> *names, size_t count) {
    std::string out;
    for (size_t i = 0; i < count; ++i) if (v & names[i].first) out += (out.empty() ? "" : ", ") + std::string(names[i].second);
    return out;
}

// [MS-FSCC] 2.6 file attributes
std::string attributesText(uint32_t a) {
    static const std::pair<uint32_t, const char *> names[] = {{0x1, "READONLY"}, {0x2, "HIDDEN"}, {0x4, "SYSTEM"}, {0x10, "DIRECTORY"}, {0x20, "ARCHIVE"}, {0x80, "NORMAL"},
        {0x100, "TEMPORARY"}, {0x200, "SPARSE_FILE"}, {0x400, "REPARSE_POINT"}, {0x800, "COMPRESSED"}, {0x4000, "ENCRYPTED"}};
    const std::string n = bitNames(a, names, std::size(names));
    return hexString(a, 8) + (n.empty() ? "" : " (" + n + ")");
}

// [MS-FSCC] 2.4 FILE_INFORMATION_CLASS
const char *fileInfoClassName(uint8_t c) {
    switch (c) {
        case 1: return "FileDirectoryInformation";
        case 2: return "FileFullDirectoryInformation";
        case 3: return "FileBothDirectoryInformation";
        case 4: return "FileBasicInformation";
        case 5: return "FileStandardInformation";
        case 6: return "FileInternalInformation";
        case 7: return "FileEaInformation";
        case 8: return "FileAccessInformation";
        case 9: return "FileNameInformation";
        case 10: return "FileRenameInformation";
        case 11: return "FileLinkInformation";
        case 12: return "FileNamesInformation";
        case 13: return "FileDispositionInformation";
        case 14: return "FilePositionInformation";
        case 15: return "FileFullEaInformation";
        case 16: return "FileModeInformation";
        case 17: return "FileAlignmentInformation";
        case 18: return "FileAllInformation";
        case 19: return "FileAllocationInformation";
        case 20: return "FileEndOfFileInformation";
        case 21: return "FileAlternateNameInformation";
        case 22: return "FileStreamInformation";
        case 23: return "FilePipeInformation";
        case 24: return "FilePipeLocalInformation";
        case 25: return "FilePipeRemoteInformation";
        case 28: return "FileCompressionInformation";
        case 29: return "FileObjectIdInformation";
        case 32: return "FileQuotaInformation";
        case 33: return "FileReparsePointInformation";
        case 34: return "FileNetworkOpenInformation";
        case 35: return "FileAttributeTagInformation";
        case 37: return "FileIdBothDirectoryInformation";
        case 38: return "FileIdFullDirectoryInformation";
        case 39: return "FileValidDataLengthInformation";
        case 40: return "FileShortNameInformation";
        default: return nullptr;
    }
}

// [MS-FSCC] 2.5 FS_INFORMATION_CLASS
const char *fsInfoClassName(uint8_t c) {
    switch (c) {
        case 1: return "FileFsVolumeInformation";
        case 2: return "FileFsLabelInformation";
        case 3: return "FileFsSizeInformation";
        case 4: return "FileFsDeviceInformation";
        case 5: return "FileFsAttributeInformation";
        case 6: return "FileFsControlInformation";
        case 7: return "FileFsFullSizeInformation";
        case 8: return "FileFsObjectIdInformation";
        case 11: return "FileFsSectorSizeInformation";
        default: return nullptr;
    }
}

// FSCTL codes: CTL_CODE(DeviceType, Function, Method, Access) = (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
const char *ctlCodeName(uint32_t code) {
    switch (code) {
        case 0x00060194: return "FSCTL_DFS_GET_REFERRALS";
        case 0x000601B0: return "FSCTL_DFS_GET_REFERRALS_EX";
        case 0x0011400C: return "FSCTL_PIPE_PEEK";
        case 0x00110018: return "FSCTL_PIPE_WAIT";
        case 0x0011C017: return "FSCTL_PIPE_TRANSCEIVE";
        case 0x000900A4: return "FSCTL_SET_REPARSE_POINT";
        case 0x000900A8: return "FSCTL_GET_REPARSE_POINT";
        case 0x000900C4: return "FSCTL_SET_SPARSE";
        case 0x000940CF: return "FSCTL_QUERY_ALLOCATED_RANGES";
        case 0x000980C8: return "FSCTL_SET_ZERO_DATA";
        case 0x001401D4: return "FSCTL_LMR_REQUEST_RESILIENCY";
        case 0x001401FC: return "FSCTL_QUERY_NETWORK_INTERFACE_INFO";
        case 0x00140204: return "FSCTL_VALIDATE_NEGOTIATE_INFO";
        case 0x00140078: return "FSCTL_SRV_REQUEST_RESUME_KEY";
        case 0x00144064: return "FSCTL_SRV_ENUMERATE_SNAPSHOTS";
        case 0x001440F2: return "FSCTL_SRV_COPYCHUNK";
        case 0x001480F2: return "FSCTL_SRV_COPYCHUNK_WRITE";
        default: return nullptr;
    }
}

const char *shareTypeName(uint8_t t) { return t == 1 ? "Disk" : t == 2 ? "Pipe" : t == 3 ? "Print" : "unknown"; }

const char *dispositionName(uint32_t d) {
    switch (d) {
        case 0: return "FILE_SUPERSEDE";
        case 1: return "FILE_OPEN";
        case 2: return "FILE_CREATE";
        case 3: return "FILE_OPEN_IF";
        case 4: return "FILE_OVERWRITE";
        case 5: return "FILE_OVERWRITE_IF";
        default: return "unknown";
    }
}

const char *createActionName(uint32_t a) {
    switch (a) {
        case 0: return "FILE_SUPERSEDED";
        case 1: return "FILE_OPENED";
        case 2: return "FILE_CREATED";
        case 3: return "FILE_OVERWRITTEN";
        default: return "unknown";
    }
}

const char *createContextName(const std::string &tag) {
    if (tag == "ExtA") return "extended attributes";
    if (tag == "SecD") return "security descriptor";
    if (tag == "DHnQ") return "durable handle request";
    if (tag == "DHnC") return "durable handle reconnect";
    if (tag == "AlSi") return "allocation size";
    if (tag == "MxAc") return "query maximal access";
    if (tag == "TWrp") return "timewarp";
    if (tag == "QFid") return "query on disk id";
    if (tag == "RqLs") return "lease";
    if (tag == "DH2Q") return "durable handle request v2";
    if (tag == "DH2C") return "durable handle reconnect v2";
    if (tag == "AAPL") return "Apple extensions";
    return nullptr;
}

const char *negotiateContextName(uint16_t t) {
    switch (t) {
        case 1: return "SMB2_PREAUTH_INTEGRITY_CAPABILITIES";
        case 2: return "SMB2_ENCRYPTION_CAPABILITIES";
        case 3: return "SMB2_COMPRESSION_CAPABILITIES";
        case 5: return "SMB2_NETNAME_NEGOTIATE_CONTEXT_ID";
        case 6: return "SMB2_TRANSPORT_CAPABILITIES";
        case 7: return "SMB2_RDMA_TRANSFORM_CAPABILITIES";
        case 8: return "SMB2_SIGNING_CAPABILITIES";
        default: return "unknown";
    }
}

const char *cipherName(uint16_t c) {
    switch (c) {
        case 1: return "AES-128-CCM";
        case 2: return "AES-128-GCM";
        case 3: return "AES-256-CCM";
        case 4: return "AES-256-GCM";
        default: return "unknown";
    }
}

// One command of a message: the bytes, the fields read from them, and the line it adds to the Info column.
struct Cmd {
    Context &ctx;
    Field *layer = nullptr;               // the layer of this command (null when no tree is wanted)
    const uint8_t *b = nullptr;           // first byte of the body (after the 64 byte header)
    size_t bodyLen = 0;                   // bytes of this command after the header
    size_t abs = 0;                       // frame offset of the header
    uint16_t command = 0;
    bool response = false;
    uint32_t status = 0;
    uint16_t structSize = 0;
    std::string summary;                  // Info text of this command
    Smb2Command facts;                    // what the session table is told

    explicit Cmd(Context &c) : ctx(c) {}

    bool has(size_t at, size_t n) const { return at <= bodyLen && n <= bodyLen - at; }
    uint8_t u8(size_t at) const { return has(at, 1) ? b[at] : 0; }
    uint16_t u16(size_t at) const { return has(at, 2) ? le16(reinterpret_cast<const char *>(b) + at) : 0; }
    uint32_t u32(size_t at) const { return has(at, 4) ? le32(reinterpret_cast<const char *>(b) + at) : 0; }
    uint64_t u64(size_t at) const { return has(at, 8) ? le64(b + at) : 0; }

    /// A buffer the body points to with an offset counted from the start of the header; true when it lies inside this command.
    bool buffer(uint64_t headerOffset, uint64_t length, const uint8_t *&p) const {
        if (headerOffset < kHeader || headerOffset - kHeader > bodyLen || length > bodyLen - (headerOffset - kHeader)) return false;
        p = b + (headerOffset - kHeader);
        return true;
    }

    /// Adds a node under `under` (or the layer when null) for bytes counted from the start of the header; clipped to this command.
    Field *add(Field *under, const std::string &text, size_t headerOffset, size_t length) {
        Field *parent = under ? under : layer;
        if (!parent || !ctx.wantFields()) return nullptr;
        const size_t limit = kHeader + bodyLen;
        if (headerOffset > limit) { headerOffset = limit; length = 0; }
        length = std::min(length, limit - headerOffset);
        return &parent->add(text, abs + headerOffset, length);
    }
    /// Same for a field of the body at body offset `at`.
    Field *field(const std::string &text, size_t at, size_t length, Field *under = nullptr) { return add(under, text, kHeader + at, length); }
};

// Body offset of the FileId of a command (-1: the command has none there). [MS-SMB2] 2.2.x
int fileIdAt(const Cmd &c) {
    const uint16_t s = c.structSize;
    if (!c.response) {
        switch (c.command) {
            case 6: return s == 24 ? 8 : -1;      // Close
            case 7: return s == 24 ? 8 : -1;      // Flush
            case 8: return s == 49 ? 16 : -1;     // Read
            case 9: return s == 49 ? 16 : -1;     // Write
            case 0x0A: return s == 48 ? 8 : -1;   // Lock
            case 0x0B: return s == 57 ? 8 : -1;   // Ioctl
            case 0x0E: return s == 33 ? 8 : -1;   // Query Directory
            case 0x0F: return s == 32 ? 8 : -1;   // Change Notify
            case 0x10: return s == 41 ? 24 : -1;  // Query Info
            case 0x11: return s == 33 ? 16 : -1;  // Set Info
            case 0x12: return s == 24 ? 8 : -1;   // Oplock Break acknowledgment
            default: return -1;
        }
    }
    if (c.command == 5 && s == 89) return 64;    // Create response
    if (c.command == 0x12 && s == 24) return 8;  // Oplock Break notification / response
    if (c.command == 0x0B && s == 49) return 8;  // Ioctl response
    return -1;
}

std::string ntStatusText(uint32_t status) {
    if (const char *n = ntStatusName(status)) return n;
    char buf[32];
    std::snprintf(buf, sizeof buf, "NT_STATUS_0x%08X", status);
    return buf;
}

// Reads what the session table needs from the body (the same bytes the body decoders show).
void readFacts(Cmd &c) {
    Smb2Command &f = c.facts;
    if (const int at = fileIdAt(c); at >= 0 && c.has(static_cast<size_t>(at), 16)) {
        f.hasFileId = true;
        f.filePersistent = c.u64(static_cast<size_t>(at));
        f.fileVolatile = c.u64(static_cast<size_t>(at) + 8);
    }
    const uint8_t *p = nullptr;
    if (!c.response && c.command == 5 && c.structSize == 57) {
        if (c.buffer(c.u16(44), c.u16(46), p)) f.name = utf16(p, c.u16(46), 128);
    } else if (!c.response && c.command == 3 && c.structSize == 9) {
        if (c.buffer(c.u16(4), c.u16(6), p)) f.name = utf16(p, c.u16(6), 128);
    } else if (c.response && c.command == 3 && c.structSize == 16) {
        f.shareType = c.u8(2);
    } else if (!c.response && c.command == 0x10 && c.structSize == 41) {
        f.infoType = c.u8(2); f.infoClass = c.u8(3);
    } else if (!c.response && c.command == 0x11 && c.structSize == 33) {
        f.infoType = c.u8(2); f.infoClass = c.u8(3);
    } else if (!c.response && c.command == 0x0E && c.structSize == 33) {
        f.infoType = 1; f.infoClass = c.u8(2);
    } else if (!c.response && c.command == 0x0B && c.structSize == 57) {
        f.ctlCode = c.u32(4);
    }
}

void fileIdItem(Cmd &c) {
    const int at = fileIdAt(c);
    if (at < 0 || !c.has(static_cast<size_t>(at), 16)) return;
    c.field("File ID: persistent " + hex64(c.facts.filePersistent) + ", volatile " + hex64(c.facts.fileVolatile), static_cast<size_t>(at), 16);
}

void negotiateContexts(Cmd &c, size_t headerOffset, size_t count) {
    if (headerOffset < kHeader || count == 0) return;
    size_t at = headerOffset - kHeader;
    Field *list = c.field("Negotiate Contexts (" + std::to_string(count) + ")", at, c.bodyLen > at ? c.bodyLen - at : 0);
    for (size_t i = 0; i < count && i < 16 && c.has(at, 8); ++i) {
        const uint16_t type = c.u16(at), dl = c.u16(at + 2);
        if (!c.has(at + 8, dl)) break;
        const std::string name = negotiateContextName(type);
        Field *n = c.field(name + " (" + std::to_string(type) + ", " + std::to_string(dl) + " bytes)", at, 8 + dl, list);
        if (n && type == 2 && dl >= 2) {
            const uint16_t cc = c.u16(at + 8);
            std::string ciphers;
            for (uint16_t k = 0; k < cc && k < 8 && 2 + static_cast<size_t>(k) * 2 + 2 <= dl; ++k) ciphers += (ciphers.empty() ? "" : ", ") + std::string(cipherName(c.u16(at + 10 + k * 2)));
            c.field("Ciphers (" + std::to_string(cc) + "): " + ciphers, at + 8, 2 + std::min<size_t>(cc, 8) * 2, n);
        } else if (n && type == 1 && dl >= 4) {
            const uint16_t hc = c.u16(at + 8);
            c.field("Hash algorithms: " + std::to_string(hc) + (hc && dl >= 6 && c.u16(at + 12) == 1 ? " (SHA-512)" : ""), at + 8, 2, n);
        } else if (n && type == 8 && dl >= 2) {
            const uint16_t sc = c.u16(at + 8);
            std::string algs;
            for (uint16_t k = 0; k < sc && k < 8 && 2 + static_cast<size_t>(k) * 2 + 2 <= dl; ++k) {
                const uint16_t a = c.u16(at + 10 + k * 2);
                algs += (algs.empty() ? "" : ", ") + std::string(a == 0 ? "HMAC-SHA256" : a == 1 ? "AES-CMAC" : a == 2 ? "AES-GMAC" : "unknown");
            }
            c.field("Signing algorithms (" + std::to_string(sc) + "): " + algs, at + 8, 2 + std::min<size_t>(sc, 8) * 2, n);
        }
        at += (8 + static_cast<size_t>(dl) + 7) & ~static_cast<size_t>(7);
    }
}

// Create contexts: a chain of { Next(4), NameOffset(2), NameLength(2), Reserved(2), DataOffset(2), DataLength(4) } counted from each entry
std::string createContexts(Cmd &c, size_t headerOffset, size_t length) {
    if (length == 0 || headerOffset < kHeader || headerOffset - kHeader > c.bodyLen) return std::string();
    size_t at = headerOffset - kHeader;
    const size_t end = std::min<size_t>(c.bodyLen, at + length);
    Field *list = c.field("Create Contexts (" + std::to_string(length) + " bytes)", at, end - at);
    std::string names;
    for (int i = 0; i < 16 && at + 16 <= end; ++i) {
        const uint32_t next = c.u32(at);
        const uint16_t nameOff = c.u16(at + 4), nameLen = c.u16(at + 6);
        const uint32_t dataLen = c.u32(at + 12);
        std::string tag;
        if (nameOff >= 16 && at + nameOff + nameLen <= end) tag = printableText(c.b + at + nameOff, nameLen, 16);
        const char *desc = createContextName(tag);
        names += (names.empty() ? "" : ", ") + (tag.empty() ? std::string("?") : tag);
        c.field("Context " + (tag.empty() ? std::string("?") : tag) + (desc ? std::string(" (") + desc + ")" : "") + ", data " + std::to_string(dataLen) + " bytes", at,
                next ? std::min<size_t>(next, end - at) : end - at, list);
        if (next == 0 || next < 16 || at + next >= end) break;
        at += next;
    }
    return names;
}

std::string accessText(uint32_t share) {
    static const std::pair<uint32_t, const char *> names[] = {{1, "READ"}, {2, "WRITE"}, {4, "DELETE"}};
    const std::string n = bitNames(share, names, std::size(names));
    return hexString(share, 8) + (n.empty() ? "" : " (" + n + ")");
}

// The information structure of Query Info (response) / Set Info (request): the common classes of [MS-FSCC]
void infoBuffer(Cmd &c, Field *under, uint8_t type, uint8_t cls, size_t at, size_t length) {
    if (!c.ctx.wantFields() || length == 0 || !c.has(at, length)) return;
    auto time = [&](const char *label, size_t o) { c.field(std::string(label) + ": " + fileTime(c.u64(at + o)), at + o, 8, under); };
    auto num = [&](const char *label, size_t o, size_t n) {
        c.field(std::string(label) + ": " + std::to_string(n == 8 ? c.u64(at + o) : n == 4 ? c.u32(at + o) : c.u8(at + o)), at + o, n, under);
    };
    if (type == 1) {
        switch (cls) {
            case 4:   // FileBasicInformation: CreationTime, LastAccessTime, LastWriteTime, ChangeTime, FileAttributes, Reserved
                if (length >= 36) {
                    time("Creation Time", 0); time("Last Access Time", 8); time("Last Write Time", 16); time("Change Time", 24);
                    c.field("File Attributes: " + attributesText(c.u32(at + 32)), at + 32, 4, under);
                }
                break;
            case 5:   // FileStandardInformation: AllocationSize, EndOfFile, NumberOfLinks, DeletePending, Directory, Reserved
                if (length >= 22) {
                    num("Allocation Size", 0, 8); num("End Of File", 8, 8); num("Number Of Links", 16, 4);
                    c.field(std::string("Delete Pending: ") + (c.u8(at + 20) ? "yes" : "no"), at + 20, 1, under);
                    c.field(std::string("Directory: ") + (c.u8(at + 21) ? "yes" : "no"), at + 21, 1, under);
                }
                break;
            case 9: case 21: case 40:   // FileNameInformation and the like: FileNameLength(4), FileName
                if (length >= 4 && c.has(at + 4, c.u32(at))) c.field("File Name: " + utf16(c.b + at + 4, c.u32(at), 128), at + 4, c.u32(at), under);
                break;
            case 10: case 11:   // FileRenameInformation / FileLinkInformation: ReplaceIfExists(1), Reserved(7), RootDirectory(8), FileNameLength(4), FileName
                if (length >= 20) {
                    c.field(std::string("Replace If Exists: ") + (c.u8(at) ? "yes" : "no"), at, 1, under);
                    if (c.has(at + 20, c.u32(at + 16))) c.field("File Name: " + utf16(c.b + at + 20, c.u32(at + 16), 128), at + 20, c.u32(at + 16), under);
                }
                break;
            case 13:   // FileDispositionInformation: DeletePending(1)
                c.field(std::string("Delete Pending: ") + (c.u8(at) ? "yes" : "no"), at, 1, under);
                break;
            case 14: if (length >= 8) num("Current Byte Offset", 0, 8); break;
            case 19: if (length >= 8) num("Allocation Size", 0, 8); break;
            case 20: case 39: if (length >= 8) num("End Of File", 0, 8); break;
            case 34:   // FileNetworkOpenInformation: four times, AllocationSize, EndOfFile, FileAttributes, Reserved
                if (length >= 56) {
                    time("Creation Time", 0); time("Last Access Time", 8); time("Last Write Time", 16); time("Change Time", 24);
                    num("Allocation Size", 32, 8); num("End Of File", 40, 8);
                    c.field("File Attributes: " + attributesText(c.u32(at + 48)), at + 48, 4, under);
                }
                break;
            case 35:   // FileAttributeTagInformation: FileAttributes, ReparseTag
                if (length >= 8) {
                    c.field("File Attributes: " + attributesText(c.u32(at)), at, 4, under);
                    c.field("Reparse Tag: " + hexString(c.u32(at + 4), 8), at + 4, 4, under);
                }
                break;
            case 7: if (length >= 4) num("EA Size", 0, 4); break;
            case 6: if (length >= 8) num("Index Number", 0, 8); break;
            default: break;
        }
    } else if (type == 2) {
        switch (cls) {
            case 3:   // FileFsSizeInformation: TotalAllocationUnits, AvailableAllocationUnits, SectorsPerAllocationUnit, BytesPerSector
                if (length >= 24) { num("Total Allocation Units", 0, 8); num("Available Allocation Units", 8, 8); num("Sectors Per Allocation Unit", 16, 4); num("Bytes Per Sector", 20, 4); }
                break;
            case 7:   // FileFsFullSizeInformation: Total, CallerAvailable, ActualAvailable, SectorsPerAllocationUnit, BytesPerSector
                if (length >= 32) { num("Total Allocation Units", 0, 8); num("Caller Available Allocation Units", 8, 8); num("Actual Available Allocation Units", 16, 8); num("Sectors Per Allocation Unit", 24, 4); num("Bytes Per Sector", 28, 4); }
                break;
            case 5:   // FileFsAttributeInformation: FileSystemAttributes, MaximumComponentNameLength, FileSystemNameLength, FileSystemName
                if (length >= 12) {
                    c.field("File System Attributes: " + hexString(c.u32(at), 8), at, 4, under);
                    num("Maximum Component Name Length", 4, 4);
                    if (c.has(at + 12, c.u32(at + 8))) c.field("File System Name: " + utf16(c.b + at + 12, c.u32(at + 8), 64), at + 12, c.u32(at + 8), under);
                }
                break;
            case 1:   // FileFsVolumeInformation: VolumeCreationTime, VolumeSerialNumber, VolumeLabelLength, SupportsObjects, Reserved, VolumeLabel
                if (length >= 18) {
                    time("Volume Creation Time", 0);
                    c.field("Volume Serial Number: " + hexString(c.u32(at + 8), 8), at + 8, 4, under);
                    if (c.has(at + 18, c.u32(at + 12))) c.field("Volume Label: " + utf16(c.b + at + 18, c.u32(at + 12), 64), at + 18, c.u32(at + 12), under);
                }
                break;
            default: break;
        }
    } else if (type == 3 && length >= 4) {
        c.field("Security descriptor revision: " + std::to_string(c.u8(at)), at, 1, under);
    }
}

std::string infoClassText(uint8_t type, uint8_t cls) {
    const char *n = type == 1 ? fileInfoClassName(cls) : type == 2 ? fsInfoClassName(cls) : nullptr;
    return n ? n : "class " + std::to_string(cls);
}
const char *infoTypeName(uint8_t t) { return t == 1 ? "File" : t == 2 ? "File System" : t == 3 ? "Security" : t == 4 ? "Quota" : "unknown"; }

std::string securityInfoText(uint32_t flags) {
    static const std::pair<uint32_t, const char *> names[] = {{1, "OWNER"}, {2, "GROUP"}, {4, "DACL"}, {8, "SACL"}};
    const std::string n = bitNames(flags, names, std::size(names));
    return hexString(flags, 8) + (n.empty() ? "" : " (" + n + ")");
}

// the body of one command; `note` is what the load pass found out about it (may be null)
void decodeBody(Cmd &c, const Smb2Note *note, bool first, Context &ctx) {
    auto &pack = ctx.pack;
    const uint16_t s = c.structSize;
    if (!c.has(0, 2)) return;
    c.field("Structure Size: " + std::to_string(s), 0, 2);

    // an error response has its own body ([MS-SMB2] 2.2.2) whatever the command is
    const bool errorStatus = (c.status & 0xC0000000u) == 0xC0000000u && !(c.command == 1 && c.status == 0xC0000016u);
    if (c.response && errorStatus && s == 9) {
        const uint32_t byteCount = c.u32(4);
        c.field("Error Context Count: " + std::to_string(c.u8(2)), 2, 1);
        c.field("Byte Count: " + std::to_string(byteCount), 4, 4);
        if (byteCount) c.field("Error Data (" + std::to_string(std::min<size_t>(byteCount, c.bodyLen > 8 ? c.bodyLen - 8 : 0)) + " bytes)", 8, std::min<size_t>(byteCount, c.bodyLen > 8 ? c.bodyLen - 8 : 0));
        return;
    }

    fileIdItem(c);
    const uint8_t *p = nullptr;
    switch (c.command) {
        case 0:   // Negotiate
            if (!c.response && s == 36) { // DialectCount, SecurityMode, Reserved, Capabilities, ClientGuid, NegotiateContextOffset/ClientStartTime, NegotiateContextCount
                const uint16_t count = c.u16(2);
                c.field("Security Mode: " + hexString(c.u16(4), 4) + ((c.u16(4) & 2) ? " (signing required)" : (c.u16(4) & 1) ? " (signing enabled)" : ""), 4, 2);
                c.field("Capabilities: " + hexString(c.u32(8), 8), 8, 4);
                std::string list;
                bool has311 = false;
                for (uint16_t i = 0; i < count && i < 16 && c.has(36 + static_cast<size_t>(i) * 2, 2); ++i) {
                    const uint16_t d = c.u16(36 + static_cast<size_t>(i) * 2);
                    has311 |= d == 0x0311;
                    list += (list.empty() ? "" : ", ") + std::string(dialectName(d));
                }
                c.field("Dialects (" + std::to_string(count) + "): " + list, 36, std::min<size_t>(static_cast<size_t>(count) * 2, c.bodyLen > 36 ? c.bodyLen - 36 : 0));
                if (!list.empty()) c.summary += " [" + list + "]";
                if (has311) negotiateContexts(c, c.u32(28), c.u16(32));
            } else if (c.response && s == 65) { // SecurityMode, DialectRevision, NegotiateContextCount, ServerGuid, Capabilities, MaxTransact/Read/Write, times, SecurityBuffer
                const uint16_t dialect = c.u16(4);
                c.field("Security Mode: " + hexString(c.u16(2), 4) + ((c.u16(2) & 2) ? " (signing required)" : (c.u16(2) & 1) ? " (signing enabled)" : ""), 2, 2);
                c.field(std::string("Dialect: ") + dialectName(dialect) + " (" + hexString(dialect, 4) + ")", 4, 2);
                c.field("Capabilities: " + hexString(c.u32(24), 8), 24, 4);
                c.field("Max Transact Size: " + std::to_string(c.u32(28)), 28, 4);
                c.field("Max Read Size: " + std::to_string(c.u32(32)), 32, 4);
                c.field("Max Write Size: " + std::to_string(c.u32(36)), 36, 4);
                c.field("System Time: " + fileTime(c.u64(40)), 40, 8);
                c.summary += std::string(" [") + dialectName(dialect) + "]";
                if (first) { pack.app_code = dialect; pack.app_flags |= kFlagDialect; }
                if (dialect == 0x0311) negotiateContexts(c, c.u32(60), c.u16(6));
            }
            break;
        case 1: // Session Setup (the security buffer is decoded by sessionSetupBody)
            break;
        case 3: // Tree Connect
            if (!c.response && s == 9) { // Flags/Reserved, PathOffset, PathLength, Path
                if (c.buffer(c.u16(4), c.u16(6), p)) {
                    c.add(nullptr, "Path: " + c.facts.name, c.u16(4), c.u16(6));
                    c.summary += ", Path: " + c.facts.name;
                    if (first) pack.app_text = c.facts.name;
                }
            } else if (c.response && s == 16) { // ShareType, Reserved, ShareFlags, Capabilities, MaximalAccess
                c.field(std::string("Share Type: ") + shareTypeName(c.u8(2)) + " (" + std::to_string(c.u8(2)) + ")", 2, 1);
                c.field("Share Flags: " + hexString(c.u32(4), 8), 4, 4);
                c.field("Capabilities: " + hexString(c.u32(8), 8), 8, 4);
                c.field("Maximal Access: " + hexString(c.u32(12), 8), 12, 4);
            }
            break;
        case 5: // Create
            if (!c.response && s == 57) {
                c.field("Requested Oplock Level: " + std::to_string(c.u8(3)), 3, 1);
                c.field("Impersonation Level: " + std::to_string(c.u32(4)), 4, 4);
                c.field("Desired Access: " + hexString(c.u32(24), 8), 24, 4);
                c.field("File Attributes: " + attributesText(c.u32(28)), 28, 4);
                c.field("Share Access: " + accessText(c.u32(32)), 32, 4);
                c.field(std::string("Disposition: ") + dispositionName(c.u32(36)) + " (" + std::to_string(c.u32(36)) + ")", 36, 4);
                c.field("Create Options: " + hexString(c.u32(40), 8) + ((c.u32(40) & 1) ? " (directory)" : "") + ((c.u32(40) & 0x1000) ? " (delete on close)" : ""), 40, 4);
                if (c.buffer(c.u16(44), c.u16(46), p)) {
                    const std::string& name = c.facts.name;
                    c.add(nullptr, "File Name: " + (name.empty() ? std::string("<root>") : name), c.u16(44), c.u16(46));
                    c.summary += ", File: " + (name.empty() ? std::string("<root>") : name);
                    if (first) pack.app_text = name;
                }
                const std::string ctxNames = createContexts(c, c.u32(48), c.u32(52));
                if (!ctxNames.empty()) c.summary += " [" + ctxNames + "]";
            } else if (c.response && s == 89) { // OplockLevel, Flags, CreateAction, times, AllocationSize, EndofFile, FileAttributes, Reserved2, FileId, CreateContexts
                c.field("Oplock Level: " + std::to_string(c.u8(2)), 2, 1);
                c.field(std::string("Create Action: ") + createActionName(c.u32(4)) + " (" + std::to_string(c.u32(4)) + ")", 4, 4);
                c.field("Creation Time: " + fileTime(c.u64(8)), 8, 8);
                c.field("Last Write Time: " + fileTime(c.u64(24)), 24, 8);
                c.field("Allocation Size: " + std::to_string(c.u64(40)), 40, 8);
                c.field("End Of File: " + std::to_string(c.u64(48)), 48, 8);
                c.field("File Attributes: " + attributesText(c.u32(56)), 56, 4);
                if (c.has(48, 8)) c.summary += ", Size: " + std::to_string(c.u64(48));
                const std::string ctxNames = createContexts(c, c.u32(80), c.u32(84));
                if (!ctxNames.empty()) c.summary += " [" + ctxNames + "]";
            }
            break;
        case 6: // Close
            if (!c.response && s == 24) { // Flags, Reserved, FileId
                c.field("Flags: " + hexString(c.u16(2), 4) + ((c.u16(2) & 1) ? " (POSTQUERY_ATTRIB)" : ""), 2, 2);
            } else if (c.response && s == 60) { // Flags, Reserved, CreationTime, LastAccessTime, LastWriteTime, ChangeTime, AllocationSize, EndofFile, FileAttributes
                c.field("Flags: " + hexString(c.u16(2), 4), 2, 2);
                if (c.u16(2) & 1) {
                    c.field("Creation Time: " + fileTime(c.u64(8)), 8, 8);
                    c.field("Last Write Time: " + fileTime(c.u64(24)), 24, 8);
                    c.field("Allocation Size: " + std::to_string(c.u64(40)), 40, 8);
                    c.field("End Of File: " + std::to_string(c.u64(48)), 48, 8);
                    c.field("File Attributes: " + attributesText(c.u32(56)), 56, 4);
                }
            }
            break;
        case 8: // Read
            if (!c.response && s == 49) { // Padding, Flags, Length, Offset, FileId, MinimumCount, Channel, RemainingBytes
                c.field("Length: " + std::to_string(c.u32(4)), 4, 4);
                c.field("Offset: " + std::to_string(c.u64(8)), 8, 8);
                c.field("Minimum Count: " + std::to_string(c.u32(32)), 32, 4);
                c.summary += ", Len: " + std::to_string(c.u32(4)) + ", Off: " + std::to_string(c.u64(8));
            } else if (c.response && s == 17) { // DataOffset, Reserved, DataLength, DataRemaining
                c.field("Data Offset: " + std::to_string(c.u8(2)), 2, 1);
                c.field("Data Length: " + std::to_string(c.u32(4)), 4, 4);
                c.field("Data Remaining: " + std::to_string(c.u32(8)), 8, 4);
                c.summary += ", Len: " + std::to_string(c.u32(4));
            }
            break;
        case 9: // Write
            if (!c.response && s == 49) { // DataOffset, Length, Offset, FileId, Channel, RemainingBytes, ..., Flags
                c.field("Data Offset: " + std::to_string(c.u16(2)), 2, 2);
                c.field("Length: " + std::to_string(c.u32(4)), 4, 4);
                c.field("Offset: " + std::to_string(c.u64(8)), 8, 8);
                c.field("Flags: " + hexString(c.u32(44), 8), 44, 4);
                c.summary += ", Len: " + std::to_string(c.u32(4)) + ", Off: " + std::to_string(c.u64(8));
            } else if (c.response && s == 17) { // Reserved, Count, Remaining
                c.field("Count: " + std::to_string(c.u32(4)), 4, 4);
                c.summary += ", Len: " + std::to_string(c.u32(4));
            }
            break;
        case 0x0B: // IOCTL
            if (!c.response && s == 57) { // Reserved, CtlCode, FileId, InputOffset, InputCount, MaxInputResponse, OutputOffset, OutputCount, MaxOutputResponse, Flags
                const uint32_t code = c.u32(4);
                const char *name = ctlCodeName(code);
                c.field(std::string("Function: ") + (name ? name : "unknown") + " (" + hexString(code, 8) + ")", 4, 4);
                c.field("Input Count: " + std::to_string(c.u32(28)), 28, 4);
                c.field("Max Input Response: " + std::to_string(c.u32(32)), 32, 4);
                c.field("Output Count: " + std::to_string(c.u32(40)), 40, 4);
                c.field("Max Output Response: " + std::to_string(c.u32(44)), 44, 4);
                c.field(std::string("Flags: ") + hexString(c.u32(48), 8) + ((c.u32(48) & 1) ? " (IS_FSCTL)" : ""), 48, 4);
                c.summary += std::string(", ") + (name ? name : hexString(code, 8));
                if (c.u32(28)) c.summary += ", In: " + std::to_string(c.u32(28));
            } else if (c.response && s == 49) { // Reserved, CtlCode, FileId, InputOffset, InputCount, OutputOffset, OutputCount, Flags
                const uint32_t code = c.u32(4);
                const char *name = ctlCodeName(code);
                c.field(std::string("Function: ") + (name ? name : "unknown") + " (" + hexString(code, 8) + ")", 4, 4);
                c.field("Input Count: " + std::to_string(c.u32(28)), 28, 4);
                c.field("Output Count: " + std::to_string(c.u32(36)), 36, 4);
                c.summary += std::string(", ") + (name ? name : hexString(code, 8));
                if (c.u32(36)) c.summary += ", Out: " + std::to_string(c.u32(36));
            }
            break;
        case 0x0E: // Query Directory
            if (!c.response && s == 33) { // FileInformationClass, Flags, FileIndex, FileId, FileNameOffset, FileNameLength, OutputBufferLength
                const uint8_t cls = c.u8(2), flags = c.u8(3);
                c.field("File Information Class: " + infoClassText(1, cls) + " (" + std::to_string(cls) + ")", 2, 1);
                c.field("Flags: " + hexString(flags, 2) + ((flags & 1) ? " (RESTART_SCANS)" : "") + ((flags & 2) ? " (RETURN_SINGLE_ENTRY)" : ""), 3, 1);
                c.field("Output Buffer Length: " + std::to_string(c.u32(28)), 28, 4);
                if (c.buffer(c.u16(24), c.u16(26), p)) {
                    const std::string pattern = utf16(p, c.u16(26), 128);
                    c.add(nullptr, "Search Pattern: " + pattern, c.u16(24), c.u16(26));
                    c.summary += ", Pattern: " + pattern;
                }
                c.summary += ", " + infoClassText(1, cls);
            } else if (c.response && s == 9) { // OutputBufferOffset, OutputBufferLength
                c.field("Output Buffer Length: " + std::to_string(c.u32(4)), 4, 4);
                c.summary += ", Len: " + std::to_string(c.u32(4));
            }
            break;
        case 0x0F: // Change Notify
            if (!c.response && s == 32) { // Flags, OutputBufferLength, FileId, CompletionFilter
                c.field(std::string("Flags: ") + hexString(c.u16(2), 4) + ((c.u16(2) & 1) ? " (WATCH_TREE)" : ""), 2, 2);
                c.field("Completion Filter: " + hexString(c.u32(24), 8), 24, 4);
                c.summary += (c.u16(2) & 1) ? ", Watch tree" : "";
            } else if (c.response && s == 9) {
                c.field("Output Buffer Length: " + std::to_string(c.u32(4)), 4, 4);
            }
            break;
        case 0x10: // Query Info
            if (!c.response && s == 41) { // InfoType, FileInfoClass, OutputBufferLength, InputBufferOffset, Reserved, InputBufferLength, AdditionalInformation, Flags, FileId
                const uint8_t type = c.u8(2), cls = c.u8(3);
                c.field(std::string("Info Type: ") + infoTypeName(type) + " (" + std::to_string(type) + ")", 2, 1);
                if (type == 1 || type == 2) c.field("Info Class: " + infoClassText(type, cls) + " (" + std::to_string(cls) + ")", 3, 1);
                c.field("Output Buffer Length: " + std::to_string(c.u32(4)), 4, 4);
                if (type == 3) c.field("Additional Information: " + securityInfoText(c.u32(16)), 16, 4);
                c.summary += std::string(", ") + (type == 1 || type == 2 ? infoClassText(type, cls) : std::string(infoTypeName(type)) + " info");
            } else if (c.response && s == 9) { // OutputBufferOffset, OutputBufferLength
                const uint32_t len = c.u32(4);
                c.field("Output Buffer Length: " + std::to_string(len), 4, 4);
                if (note && (note->flags & Smb2Note::kMatched)) {
                    c.summary += std::string(", ") + (note->infoType == 1 || note->infoType == 2 ? infoClassText(note->infoType, note->infoClass) : std::string(infoTypeName(note->infoType)) + " info");
                    if (c.buffer(c.u16(2), len, p)) {
                        Field *info = c.add(nullptr, std::string(infoTypeName(note->infoType)) + " information: " + infoClassText(note->infoType, note->infoClass), c.u16(2), len);
                        infoBuffer(c, info, note->infoType, note->infoClass, c.u16(2) - kHeader, len);
                    }
                } else {
                    c.summary += ", Len: " + std::to_string(len);
                }
            }
            break;
        case 0x11: // Set Info
            if (!c.response && s == 33) { // InfoType, FileInfoClass, BufferLength, BufferOffset, Reserved, AdditionalInformation, FileId
                const uint8_t type = c.u8(2), cls = c.u8(3);
                const uint32_t len = c.u32(4);
                c.field(std::string("Info Type: ") + infoTypeName(type) + " (" + std::to_string(type) + ")", 2, 1);
                if (type == 1 || type == 2) c.field("Info Class: " + infoClassText(type, cls) + " (" + std::to_string(cls) + ")", 3, 1);
                c.field("Buffer Length: " + std::to_string(len), 4, 4);
                if (type == 3) c.field("Additional Information: " + securityInfoText(c.u32(12)), 12, 4);
                c.summary += std::string(", ") + (type == 1 || type == 2 ? infoClassText(type, cls) : std::string(infoTypeName(type)) + " info");
                if (c.buffer(c.u16(8), len, p)) {
                    Field *info = c.add(nullptr, std::string(infoTypeName(type)) + " information: " + infoClassText(type, cls), c.u16(8), len);
                    infoBuffer(c, info, type, cls, c.u16(8) - kHeader, len);
                    if (type == 1 && cls == 20 && len >= 8) c.summary += ", Size: " + std::to_string(c.u64(c.u16(8) - kHeader));
                    if (type == 1 && cls == 13 && len >= 1 && c.u8(c.u16(8) - kHeader)) c.summary += ", Delete";
                }
            }
            break;
        case 0x0A: // Lock
            if (!c.response && s == 48) c.field("Lock Count: " + std::to_string(c.u16(2)), 2, 2);
            break;
        case 0x12: // Oplock Break (notification, acknowledgment, response with the 24 byte structure; the lease forms are 44 / 36 bytes)
            if (s == 24) c.field("Oplock Level: " + std::to_string(c.u8(2)), 2, 1);
            else if (s == 44 || s == 36) c.field("Lease break", 0, 0);
            break;
        default: break;
    }
}

// [MS-NLMP] 2.2.2.5 NegotiateFlags
std::string ntlmFlagNames(uint32_t f) {
    static const std::pair<uint32_t, const char *> names[] = {{0x1, "UNICODE"}, {0x2, "OEM"}, {0x4, "REQUEST_TARGET"}, {0x10, "SIGN"}, {0x20, "SEAL"},
        {0x80, "LM_KEY"}, {0x200, "NTLM"}, {0x8000, "ALWAYS_SIGN"}, {0x80000, "EXTENDED_SESSIONSECURITY"}, {0x800000, "TARGET_INFO"}, {0x2000000, "VERSION"},
        {0x20000000, "128"}, {0x40000000, "KEY_EXCH"}, {0x80000000u, "56"}};
    return hexString(f, 8) + (bitNames(f, names, std::size(names)).empty() ? "" : " (" + bitNames(f, names, std::size(names)) + ")");
}

// An NTLMSSP message ([MS-NLMP] 2.2.1) found by the security blob decoder: its type, the fields of the three messages and, for
// the authenticate message, "DOMAIN\user" (returned in `user`). `under` may be null (no tree wanted).
void ntlmssp(Context &ctx, Field *under, const uint8_t *m, size_t n, std::string &user) {
    if (n < 12) return;
    const size_t base = ctx.offsetOf(reinterpret_cast<const char *>(m));
    auto u16le = [&](size_t at) { return at + 2 <= n ? static_cast<uint32_t>(m[at] | (m[at + 1] << 8)) : 0u; };
    auto u32le = [&](size_t at) { return at + 4 <= n ? le32(reinterpret_cast<const char *>(m) + at) : 0u; };
    const uint32_t type = u32le(8);
    const size_t flagsAt = type == 1 ? 12 : type == 2 ? 20 : type == 3 ? 60 : n;
    const uint32_t flags = flagsAt + 4 <= n ? u32le(flagsAt) : 1u;   // no flags field: assume Unicode
    const bool unicode = (flags & 1) != 0;
    auto note = [&](const std::string &text, size_t at, size_t len) { if (under) under->add(text, base + at, std::min(len, n > at ? n - at : 0)); };
    // a security buffer field: Len(2) MaxLen(2) BufferOffset(4); returns the text of a string buffer
    auto buffer = [&](size_t at, size_t &off, size_t &len) {
        len = u16le(at);
        off = u32le(at + 4);
        return at + 8 <= n && off <= n && len <= n - off;
    };
    auto text = [&](size_t at, size_t max, bool &ok) {
        size_t off = 0, len = 0;
        ok = buffer(at, off, len);
        if (!ok) return std::string();
        return unicode ? utf16(m + off, len, max) : printableText(m + off, len, max);
    };
    auto stringField = [&](const char *label, size_t at) {
        bool ok = false;
        const std::string v = text(at, 64, ok);
        size_t off = 0, len = 0;
        buffer(at, off, len);
        if (ok && len) note(std::string(label) + ": " + v, off, len);
        return v;
    };
    auto version = [&](size_t at) {
        if ((flags & 0x02000000) && at + 8 <= n) note("Version: " + std::to_string(m[at]) + "." + std::to_string(m[at + 1]) + " (build " + std::to_string(u16le(at + 2)) + ")", at, 8);
    };
    if (!under && type != 3) return;
    if (type == 1) {          // NEGOTIATE: NegotiateFlags, DomainNameFields, WorkstationFields, Version
        note("Negotiate Flags: " + ntlmFlagNames(flags), 12, 4);
        stringField("Calling workstation domain", 16);
        stringField("Calling workstation name", 24);
        version(32);
    } else if (type == 2) {   // CHALLENGE: TargetNameFields, NegotiateFlags, ServerChallenge, Reserved, TargetInfoFields, Version
        stringField("Target Name", 12);
        note("Negotiate Flags: " + ntlmFlagNames(flags), 20, 4);
        if (n >= 32) note("NTLM Server Challenge: " + asciiHex(m + 24, 8), 24, 8);
        size_t off = 0, len = 0;
        if (n >= 48 && buffer(40, off, len) && len) {
            note("Target Info (" + std::to_string(len) + " bytes)", off, len);
            for (size_t at = off, count = 0; at + 4 <= off + len && count < 16; ++count) {
                const uint16_t id = static_cast<uint16_t>(u16le(at)), vl = static_cast<uint16_t>(u16le(at + 2));
                if (id == 0 || at + 4 + vl > off + len) break;
                static const char *names[] = {"EOL", "NetBIOS computer name", "NetBIOS domain name", "DNS computer name", "DNS domain name", "DNS tree name", "Flags", "Timestamp", "Single host", "Target name", "Channel bindings"};
                const std::string label = id < std::size(names) ? names[id] : "AV pair " + std::to_string(id);
                if (id >= 1 && id <= 5 && id != 6) note(label + ": " + utf16(m + at + 4, vl, 64), at, 4 + vl);
                else if (id == 7 && vl == 8) note(label + ": " + fileTime(le64(m + at + 4)), at, 12);
                else note(label + " (" + std::to_string(vl) + " bytes)", at, 4 + vl);
                at += 4 + static_cast<size_t>(vl);
            }
        }
        version(48);
    } else if (type == 3) {   // AUTHENTICATE: LmChallengeResponse, NtChallengeResponse, Domain, User, Workstation, EncryptedRandomSessionKey, NegotiateFlags, Version
        size_t off = 0, len = 0;
        if (under && n >= 20) {
            if (buffer(12, off, len)) note("LM Response (" + std::to_string(len) + " bytes)", off, len);
            if (buffer(20, off, len)) note("NT Response (" + std::to_string(len) + " bytes" + (len > 24 ? ", NTLMv2" : "") + ")", off, len);
        }
        bool okD = false, okU = false;
        const std::string dom = n >= 36 ? text(28, 64, okD) : std::string();
        const std::string usr = n >= 44 ? text(36, 64, okU) : std::string();
        if (under) {
            stringField("Domain", 28);
            stringField("User", 36);
            stringField("Workstation", 44);
            if (n >= 64) note("Negotiate Flags: " + ntlmFlagNames(flags), 60, 4);
            version(64);
        }
        if (okU && !usr.empty()) user = dom.empty() ? usr : dom + "\\" + usr;
    }
}

// Session Setup: the security buffer is SPNEGO (with NTLMSSP or Kerberos inside), a bare Kerberos token or a bare NTLMSSP message
void sessionSetup(Cmd &c, bool first, Context &ctx) {
    const uint16_t s = c.structSize;
    if (!((!c.response && s == 25) || (c.response && s == 9))) return;
    const size_t offAt = c.response ? 4 : 12, lenAt = c.response ? 6 : 14;
    const uint16_t off = c.u16(offAt), len = c.u16(lenAt);
    if (!c.response) {
        c.field("Security Mode: " + hexString(c.u8(3), 2) + ((c.u8(3) & 2) ? " (signing required)" : (c.u8(3) & 1) ? " (signing enabled)" : ""), 3, 1);
        c.field("Capabilities: " + hexString(c.u32(4), 8), 4, 4);
    } else {
        c.field(std::string("Session Flags: ") + hexString(c.u16(2), 4) + ((c.u16(2) & 1) ? " (guest)" : "") + ((c.u16(2) & 2) ? " (null session)" : "") + ((c.u16(2) & 4) ? " (encrypt data)" : ""), 2, 2);
    }
    const uint8_t *sec = nullptr;
    if (len == 0 || !c.buffer(off, len, sec)) return;
    Field *node = c.add(nullptr, "Security Buffer (" + std::to_string(len) + " bytes)", off, len);
    SecurityBlob blob = decodeSecurityBlob(ctx, sec, len, node);
    if (!blob.ok) {   // something in front of an NTLMSSP message that is not a GSS-API token: look for the signature
        for (size_t i = 0; i + 12 <= len; ++i) {
            if (std::memcmp(sec + i, "NTLMSSP\0", 8) == 0) {
                blob.ok = blob.hasNtlmssp = true;
                blob.ntlmssp = sec + i;
                blob.ntlmsspLength = len - i;
                const uint32_t type = le32(reinterpret_cast<const char *>(sec) + i + 8);
                blob.summary = type == 1 ? "NTLMSSP_NEGOTIATE" : type == 2 ? "NTLMSSP_CHALLENGE" : type == 3 ? "NTLMSSP_AUTH" : "NTLMSSP";
                break;
            }
        }
    }
    if (!blob.ok) return;
    c.summary += " [" + blob.summary + "]";
    if (blob.hasNtlmssp) {
        std::string user;
        Field *n = ctx.wantFields() && node ? &node->add("NTLM Secure Service Provider", ctx.offsetOf(reinterpret_cast<const char *>(blob.ntlmssp)), blob.ntlmsspLength) : nullptr;
        ntlmssp(ctx, n, blob.ntlmssp, blob.ntlmsspLength, user);
        if (!user.empty()) {
            c.summary += " user=" + user;
            if (first) ctx.pack.app_text = user;
        }
    }
}

// ---- SMB1: recognised only ---------------------------------------------------------------------------------------------------
const char *smb1CommandName(uint8_t cmd) {
    switch (cmd) {
        case 0x00: return "Create Directory";
        case 0x01: return "Delete Directory";
        case 0x02: return "Open";
        case 0x03: return "Create";
        case 0x04: return "Close";
        case 0x05: return "Flush";
        case 0x06: return "Delete";
        case 0x07: return "Rename";
        case 0x08: return "Query Information";
        case 0x0A: return "Read";
        case 0x0B: return "Write";
        case 0x24: return "Locking AndX";
        case 0x25: return "Transaction";
        case 0x2B: return "Echo";
        case 0x2D: return "Open AndX";
        case 0x2E: return "Read AndX";
        case 0x2F: return "Write AndX";
        case 0x32: return "Transaction2";
        case 0x71: return "Tree Disconnect";
        case 0x72: return "Negotiate";
        case 0x73: return "Session Setup AndX";
        case 0x74: return "Logoff AndX";
        case 0x75: return "Tree Connect AndX";
        case 0xA0: return "NT Transact";
        case 0xA2: return "NT Create AndX";
        case 0xA4: return "NT Cancel";
        default: return nullptr;
    }
}

// The 32 byte SMB1 header and, for Negotiate, the dialect strings (request) / the chosen dialect index (response): the part that
// tells a client how a connection moves on to SMB2 (the "SMB 2.002" / "SMB 2.???" dialects of a multi-protocol negotiate).
void dissectSmb1(Context &ctx, const uint8_t *m, size_t n, size_t abs) {
    auto &pack = ctx.pack;
    pack.protocol = "SMB";
    if (n < 33) {
        pack.info = "SMB1 [Truncated header]";
        if (ctx.wantFields()) ctx.addLayer("Server Message Block (SMB1)", abs, n);
        return;
    }
    const uint8_t cmd = m[4];
    const uint32_t status = le32(reinterpret_cast<const char *>(m) + 5);
    const uint8_t flags = m[9];
    const uint16_t flags2 = le16(reinterpret_cast<const char *>(m) + 10);
    const bool reply = (flags & 0x80) != 0;
    const char *known = smb1CommandName(cmd);
    const std::string name = known ? known : "Command " + hexString(cmd, 2);
    std::string info = "SMB1 " + name + (reply ? " Response" : " Request");
    if (reply && (flags2 & 0x4000)) info += ", " + ntStatusText(status);   // SMB_FLAGS2_NT_STATUS: the status is an NTSTATUS
    const uint8_t words = m[32];
    std::vector<std::string> dialects;
    Field *layer = ctx.wantFields() ? &ctx.addLayer("Server Message Block (SMB1)", abs, n) : nullptr;
    auto item = [&](const std::string &t, size_t at, size_t len) { if (layer) layer->add(t, abs + at, std::min(len, n > at ? n - at : 0)); };
    item("Command: " + name + " (" + hexString(cmd, 2) + ")", 4, 1);
    item("NT Status: " + hexString(status, 8), 5, 4);
    item("Flags: " + hexString(flags, 2) + (reply ? " (Reply)" : ""), 9, 1);
    item("Flags2: " + hexString(flags2, 4), 10, 2);
    item("Tree ID: " + hexString(le16(reinterpret_cast<const char *>(m) + 24), 4), 24, 2);
    item("Process ID: " + hexString(le16(reinterpret_cast<const char *>(m) + 26), 4), 26, 2);
    item("User ID: " + hexString(le16(reinterpret_cast<const char *>(m) + 28), 4), 28, 2);
    item("Multiplex ID: " + hexString(le16(reinterpret_cast<const char *>(m) + 30), 4), 30, 2);
    item("Word Count: " + std::to_string(words), 32, 1);
    if (cmd == 0x72) {
        if (!reply && words == 0 && n >= 35) {   // ByteCount, then BufferFormat 0x02 + a NUL terminated dialect string each
            const size_t byteCount = le16(reinterpret_cast<const char *>(m) + 33);
            size_t at = 35;
            const size_t end = std::min(n, 35 + byteCount);
            while (at < end && dialects.size() < 16 && m[at] == 0x02) {
                size_t e = at + 1;
                while (e < end && m[e] != 0) ++e;
                dialects.push_back(printableText(m + at + 1, e - at - 1, 40));
                at = e + 1;
            }
            std::string list;
            for (const auto &d: dialects) list += (list.empty() ? "" : ", ") + d;
            if (layer) {
                Field &l = layer->add("Requested Dialects (" + std::to_string(dialects.size()) + "): " + list, abs + 35, end > 35 ? end - 35 : 0);
                for (const auto &d: dialects) l.add(d + (d == "SMB 2.002" || d == "SMB 2.???" ? " (SMB2)" : ""), abs + 35, 0);
            }
            if (!list.empty()) info += " [" + list + "]";
        } else if (reply && words >= 1 && n >= 35) {   // DialectIndex is the first word
            const uint16_t index = le16(reinterpret_cast<const char *>(m) + 33);
            item(index == 0xFFFF ? "Dialect Index: 0xFFFF (no dialect chosen)" : "Dialect Index: " + std::to_string(index), 33, 2);
            info += index == 0xFFFF ? ", no dialect chosen" : ", Dialect index " + std::to_string(index);
        }
    }
    pack.info = info;
}

} // namespace

StreamFrame frameSmb2(const char *data, size_t length) {
    if (length == 0) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    // NetBIOS session service header: 1 byte type, then a 24 bit length (Direct TCP: type 0 and 24 bits as well)
    if (!nbssTypeName(bytes[0])) return StreamFrame{StreamFrame::Kind::Reject, 0};
    if (length < 4) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const size_t len = (static_cast<size_t>(bytes[1]) << 16) | (static_cast<size_t>(bytes[2]) << 8) | bytes[3];
    const size_t total = 4 + len;
    if (total > kMaxMessage) return StreamFrame{StreamFrame::Kind::Reject, 0};
    // a session message carries an SMB message (or a Transform / Compression header): its magic is checked once it is there
    if (bytes[0] == 0x00 && len >= 4 && length >= 8) {
        if (!(smbMagic(bytes + 4, 0xfe) || smbMagic(bytes + 4, 0xff) || smbMagic(bytes + 4, 0xfd) || smbMagic(bytes + 4, 0xfc))) return StreamFrame{StreamFrame::Kind::Reject, 0};
    }
    return StreamFrame{length < total ? StreamFrame::Kind::NeedMore : StreamFrame::Kind::Complete, total};
}

void dissectSmb2(Context &ctx, const char *data, size_t length) {
    if (!data || length < 4) return;
    auto &pack = ctx.pack;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    const size_t o = ctx.offsetOf(data);

    // NBSS / Direct TCP header
    size_t base = 0;
    if (nbssTypeName(bytes[0]) && !(length >= 4 && (bytes[0] == 0xfe || bytes[0] == 0xff || bytes[0] == 0xfd || bytes[0] == 0xfc))) base = 4;
    if (base == 4 && bytes[0] != 0x00) { // NetBIOS session request / response / keep-alive on port 139
        pack.protocol = "NBSS";
        const std::string name = nbssTypeName(bytes[0]);
        pack.info = "NBSS " + name;
        if (ctx.wantFields()) {
            Field &l = ctx.addLayer("NetBIOS Session Service (" + name + ")", o, length);
            l.add("Message Type: " + name + " (" + hexString(bytes[0], 2) + ")", o, 1);
            l.add("Length: " + std::to_string((static_cast<size_t>(bytes[1]) << 16) | (static_cast<size_t>(bytes[2]) << 8) | bytes[3]), o + 1, 3);
        }
        return;
    }
    if (length < base + 4) return;

    const uint8_t *msg = bytes + base;
    const size_t msgLen = length - base;
    if (smbMagic(msg, 0xff)) {
        dissectSmb1(ctx, msg, msgLen, o + base);
        return;
    }
    if (smbMagic(msg, 0xfd)) { // SMB3 Transform header ([MS-SMB2] 2.2.41): the message is encrypted
        pack.protocol = "SMB2";
        pack.app_flags |= kFlagEncrypted;
        uint64_t sessionId = 0;
        if (msgLen >= 52) std::memcpy(&sessionId, msg + 44, 8);
        std::string sid;
        if (msgLen >= 52) { char b[24]; std::snprintf(b, sizeof b, "0x%016llx", static_cast<unsigned long long>(sessionId)); sid = b; }
        pack.info = "Encrypted SMB3 (" + std::to_string(msgLen) + " bytes)" + (sid.empty() ? "" : ", Session: " + sid);
        if (ctx.wantFields()) {
            Field &l = ctx.addLayer("SMB2 Transform Header (encrypted)", o + base, msgLen);
            if (msgLen >= 52) {
                l.add("Original Message Size: " + std::to_string(le32(reinterpret_cast<const char *>(msg) + 36)), o + base + 36, 4);
                l.add("Session ID: " + sid, o + base + 44, 8);
            }
            l.add("[the message is encrypted: the content is not shown]");
        }
        return;
    }
    if (smbMagic(msg, 0xfc)) { // compression transform header
        pack.protocol = "SMB2";
        pack.app_flags |= kFlagCompressed;
        pack.info = "Compressed SMB3 (" + std::to_string(msgLen) + " bytes)";
        if (ctx.wantFields()) ctx.addLayer("SMB2 Compression Transform Header", o + base, msgLen).add("[the message is compressed: the content is not shown]");
        return;
    }
    if (!smbMagic(msg, 0xfe)) return;

    pack.protocol = "SMB2";
    std::string infoAll;
    const char *malformed = nullptr;
    // trees, files and request/response matching (rule 4): the load pass hands every command to the session table, Replay reads
    // the note the load pass stored for it
    SessionTables *sessions = ctx.sessions;
    const bool loadPass = ctx.mode != ParseMode::Replay && sessions && !sessions->isFrozen();
    const std::string connection = sessions ? smb2ConnectionKey(pack.source, pack.src_port, pack.destination, pack.dst_port) : std::string();
    const uint32_t number = static_cast<uint32_t>(pack.number);
    size_t pos = 0;   // offset of the current command inside msg
    int commands = 0;

    while (pos < msgLen && commands < 16) {
        const size_t avail = msgLen - pos;
        if (avail < kHeader || !smbMagic(msg + pos, 0xfe)) {
            if (commands == 0) { // the first header is cut: name it
                infoAll = "SMB2 [Truncated header]";
                // a session message whose NBSS length promises more bytes is the first segment of a longer message
                const bool segmentOfLonger = base == 4 && bytes[0] == 0x00 && ((static_cast<size_t>(bytes[1]) << 16) | (static_cast<size_t>(bytes[2]) << 8) | bytes[3]) > msgLen;
                if (!segmentOfLonger) malformed = "SMB2 header truncated";
            } else {
                malformed = "NextCommand does not lead to an SMB2 header";
            }
            break;
        }
        const char *h = reinterpret_cast<const char *>(msg + pos);
        const uint16_t command = le16(h + 12);
        const uint32_t status = le32(h + 8);
        const uint32_t flags = le32(h + 16);
        const uint32_t nextCommand = le32(h + 20);
        const uint64_t messageId = le64(msg + pos + 24);
        const bool response = (flags & 1) != 0, async = (flags & 2) != 0, related = (flags & 4) != 0, isSigned = (flags & 8) != 0;
        const uint32_t treeId = async ? 0 : le32(h + 36);
        const uint64_t asyncId = async ? le64(msg + pos + 32) : 0;
        const uint64_t sessionId = le64(msg + pos + 40);
        const size_t end = (nextCommand != 0 && nextCommand >= kHeader && nextCommand <= avail) ? pos + nextCommand : msgLen;   // this command's bytes
        const size_t body = pos + kHeader;
        const bool first = commands == 0;

        Cmd c(ctx);
        c.b = msg + body;
        c.bodyLen = end > body ? end - body : 0;
        c.abs = o + base + pos;
        c.command = command;
        c.response = response;
        c.status = status;
        c.structSize = c.u16(0);
        const std::string cmdName = commandName(command);
        c.summary = cmdName + (response ? " Response" : " Request");
        if (response) c.summary += ", " + ntStatusText(status);
        if (ctx.wantFields()) c.layer = &ctx.addLayer("SMB2 (" + cmdName + (response ? " Response" : " Request") + ")", c.abs, std::min<size_t>(end - pos, kHeader + c.bodyLen));

        c.facts.command = command;
        c.facts.response = response;
        c.facts.async = async;
        c.facts.related = related;
        c.facts.status = status;
        c.facts.messageId = messageId;
        c.facts.sessionId = sessionId;
        c.facts.treeId = treeId;
        readFacts(c);

        if (first) {
            pack.app_type = command;
            if (response) pack.app_flags |= kFlagResponse;
            if (isSigned) pack.app_flags |= kFlagSigned;
            if (async) pack.app_flags |= kFlagAsync;
            if (response) pack.app_stream = status;
        }

        // ---- header ---------------------------------------------------------------------------------------------------
        c.add(nullptr, "Credit Charge: " + std::to_string(le16(h + 6)), 6, 2);
        c.add(nullptr, "Command: " + cmdName + " (" + std::to_string(command) + ")", 12, 2);
        c.add(nullptr, std::string(response ? "Credits granted: " : "Credits requested: ") + std::to_string(le16(h + 14)), 14, 2);
        c.add(nullptr, std::string("Flags: ") + hexString(flags, 8) + (response ? " (Response)" : " (Request)") + (async ? " (Async)" : "") + (related ? " (Related operations)" : "") + (isSigned ? " (Signed)" : ""), 16, 4);
        if (nextCommand != 0) c.add(nullptr, "Next Command: " + std::to_string(nextCommand), 20, 4);
        c.add(nullptr, "Message ID: " + std::to_string(messageId), 24, 8);
        if (async) c.add(nullptr, "Async ID: " + hex64(asyncId), 32, 8);
        else c.add(nullptr, "Tree ID: " + hexString(treeId, 8), 36, 4);
        c.add(nullptr, "Session ID: " + hex64(sessionId), 40, 8);
        if (isSigned) c.add(nullptr, "Signature: " + asciiHex(msg + pos + 48, 16), 48, 16);
        if (response) {
            const char *stName = ntStatusName(status);
            c.add(nullptr, "NT Status: " + hexString(status, 8) + (stName ? " (" + std::string(stName) + ")" : ""), 8, 4);
        }

        const Smb2Note *note = nullptr;
        if (sessions) note = loadPass ? sessions->observeSmb2(connection, number, ctx.tcpStreamSeq, static_cast<uint8_t>(commands), c.facts)
                                      : sessions->smb2Note(number, ctx.tcpStreamSeq, static_cast<uint8_t>(commands));
        if (c.layer) {   // what the session table found out about this command
            if (note) {
                if (note->flags & Smb2Note::kMatched) c.add(nullptr, "[Request in frame " + std::to_string(note->requestPacket) + "]", 0, 0);
                if (note->flags & Smb2Note::kAnswered) c.add(nullptr, "[Response in frame " + std::to_string(note->responsePacket) + "]", 0, 0);
                if (note->flags & Smb2Note::kInterim) c.add(nullptr, "[Interim response: the final response follows]", 0, 0);
                if (note->flags & Smb2Note::kUnmatched) c.add(nullptr, "[No request with this Message ID was seen]", 0, 0);
                if (note->flags & Smb2Note::kRelated) c.add(nullptr, "[Related operation: the ids of the command before are used]", 0, 0);
                if (!note->share.empty()) c.add(nullptr, "[Share: " + note->share + "]", 0, 0);
                if (!note->file.empty()) c.add(nullptr, std::string("[") + ((note->flags & Smb2Note::kPipe) ? "Named pipe: " : "File: ") + note->file + "]", 0, 0);
            } else if (sessions && sessions->isTableStateLost("smb2")) {
                c.add(nullptr, "[SMB2 session state lost: the share and file of this command are not known]", 0, 0);
            }
        }

        // ---- body -----------------------------------------------------------------------------------------------------
        if (command == 1) sessionSetup(c, first, ctx);
        decodeBody(c, note, first, ctx);
        if (nextCommand != 0 && !(nextCommand >= kHeader && nextCommand <= avail)) malformed = "SMB2 NextCommand outside the message";
        // the file the command works on (from its FileId or its request), else the share, else the raw tree id
        if (note && !note->file.empty() && !(command == 5 && !response)) c.summary += ", File: " + note->file;
        else if (note && !note->share.empty() && !(command == 3 && !response)) c.summary += ", Share: " + note->share;
        else if (treeId != 0 && !async) c.summary += ", TreeID: " + hexString(treeId, 4);
        if (first && note) {
            pack.app_text2 = note->file;
            if (note->flags & Smb2Note::kPipe) pack.app_flags |= kFlagPipe;
        }

        infoAll += (commands ? ", " : "") + c.summary;
        ++commands;
        if (nextCommand == 0 || malformed) break;
        pos += nextCommand;
    }
    if (commands > 1) pack.app_flags |= kFlagCompound;
    pack.info = infoAll;
    if (commands == 0 && ctx.wantFields()) ctx.addLayer("SMB2", o + base, msgLen);
    if (malformed) ctx.markMalformed(malformed);
}

} // namespace dissect
