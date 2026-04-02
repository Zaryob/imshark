// SMB2 / SMB3 ([MS-SMB2]) over Direct TCP (port 445: a zero byte and a 24 bit length in front) or NetBIOS (port 139: the NBSS
// session service header with its message types). Decoded: the 64 byte header of every command of a compound message (sync and
// async form, NextCommand), the SMB3 Transform header (encrypted messages are named, not decrypted), and the bodies of Negotiate
// (dialects / chosen dialect), Session Setup (NTLMSSP message type, user and domain of the authenticate message), Tree Connect (share
// path), Create (file name), Read and Write (length and offset). Not decoded: file ids to names, trees to shares (no session tables).
#include "smb2.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "reader.h"
#include "util.h"

using packet::Field;

namespace dissect {

namespace {

constexpr size_t kMaxMessage = 8u << 20;   // not more than the stream table buffers (a Direct TCP message can be 16 MB - 1)
constexpr size_t kHeader = 64;

// app_flags
constexpr uint16_t kFlagResponse = 1, kFlagSigned = 2, kFlagEncrypted = 4, kFlagCompressed = 8, kFlagDialect = 0x10, kFlagAsync = 0x20, kFlagCompound = 0x40;

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
        pack.protocol = "SMB";
        pack.info = "SMB (Legacy SMB1)";
        if (ctx.wantFields()) ctx.addLayer("Server Message Block (SMB1)", o + base, msgLen);
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
    std::vector<std::pair<std::string, std::pair<size_t, size_t>>> layers;   // layer text, offset, length (one per command)
    std::vector<std::vector<std::pair<std::string, std::pair<size_t, size_t>>>> layerItems;
    const char *malformed = nullptr;
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
        const uint64_t messageId = static_cast<uint64_t>(le32(h + 24)) | (static_cast<uint64_t>(le32(h + 28)) << 32);
        const bool response = (flags & 1) != 0, async = (flags & 2) != 0, isSigned = (flags & 8) != 0;
        const uint32_t treeId = async ? 0 : le32(h + 36);
        const uint64_t asyncId = async ? (static_cast<uint64_t>(le32(h + 32)) | (static_cast<uint64_t>(le32(h + 36)) << 32)) : 0;
        const uint64_t sessionId = static_cast<uint64_t>(le32(h + 40)) | (static_cast<uint64_t>(le32(h + 44)) << 32);
        const size_t end = (nextCommand != 0 && nextCommand >= kHeader && nextCommand <= avail) ? pos + nextCommand : msgLen;   // this command's bytes
        const size_t body = pos + kHeader;
        const size_t bodyLen = end > body ? end - body : 0;
        const uint8_t *b = msg + body;
        const size_t abs = o + base + pos;   // frame offset of this command

        const std::string cmdName = commandName(command);
        std::string summary = cmdName + (response ? " Response" : " Request");
        if (response) {
            const char *stName = ntStatusName(status);
            if (stName) {
                summary += ", " + std::string(stName);
            } else {
                char buf[32];
                std::snprintf(buf, sizeof buf, ", NT_STATUS_0x%08X", status);
                summary += buf;
            }
        }
        std::vector<std::pair<std::string, std::pair<size_t, size_t>>> items;
        auto add = [&](const std::string &text, size_t off, size_t len) { items.push_back({text, {abs + off, len}}); };
        auto rd16 = [&](size_t at, uint16_t &v) { if (at + 2 > bodyLen) return false; v = le16(reinterpret_cast<const char *>(b) + at); return true; };
        auto rd32 = [&](size_t at, uint32_t &v) { if (at + 4 > bodyLen) return false; v = le32(reinterpret_cast<const char *>(b) + at); return true; };

        if (commands == 0) {
            pack.app_type = command;
            if (response) pack.app_flags |= kFlagResponse;
            if (isSigned) pack.app_flags |= kFlagSigned;
            if (async) pack.app_flags |= kFlagAsync;
            if (response) pack.app_stream = status;
        }

        add("Command: " + cmdName + " (" + std::to_string(command) + ")", 12, 2);
        add(std::string("Flags: ") + hexString(flags, 8) + (response ? " (Response)" : " (Request)") + (async ? " (Async)" : "") + (isSigned ? " (Signed)" : ""), 16, 4);
        if (nextCommand != 0) add("Next Command: " + std::to_string(nextCommand), 20, 4);
        add("Message ID: " + std::to_string(messageId), 24, 8);
        if (async) add("Async ID: " + hexString(static_cast<uint32_t>(asyncId), 8), 32, 8);
        else add("Tree ID: " + hexString(treeId, 8), 36, 4);
        add("Session ID: " + hexString(static_cast<uint32_t>(sessionId), 8), 40, 8);
        if (response) {
            const char *stName = ntStatusName(status);
            add("NT Status: " + hexString(status, 8) + (stName ? " (" + std::string(stName) + ")" : ""), 8, 4);
        }

        // ---- bodies ------------------------------------------------------------------------------------------------
        uint16_t structSize = 0;
        if (rd16(0, structSize)) {
            if (command == 0 && !response && structSize == 36) { // Negotiate Request: DialectCount, SecurityMode, Reserved, Capabilities, ClientGuid, ..., Dialects
                uint16_t count = 0;
                if (rd16(2, count)) {
                    std::string list;
                    for (uint16_t i = 0; i < count && i < 16 && 36 + static_cast<size_t>(i) * 2 + 2 <= bodyLen; ++i) {
                        uint16_t d = 0;
                        rd16(36 + static_cast<size_t>(i) * 2, d);
                        list += (list.empty() ? "" : ", ") + std::string(dialectName(d));
                    }
                    add("Dialects (" + std::to_string(count) + "): " + list, kHeader + 36, std::min<size_t>(static_cast<size_t>(count) * 2, bodyLen > 36 ? bodyLen - 36 : 0));
                    if (!list.empty()) summary += " [" + list + "]";
                }
            } else if (command == 0 && response && structSize == 65) { // Negotiate Response: SecurityMode, DialectRevision, ...
                uint16_t dialect = 0;
                if (rd16(4, dialect)) {
                    add(std::string("Dialect: ") + dialectName(dialect) + " (" + hexString(dialect, 4) + ")", kHeader + 4, 2);
                    summary += std::string(" [") + dialectName(dialect) + "]";
                    if (commands == 0) { pack.app_code = dialect; pack.app_flags |= kFlagDialect; }
                }
            } else if (command == 1 && ((!response && structSize == 25) || (response && structSize == 9))) { // Session Setup
                uint16_t off = 0, len = 0;
                const size_t offAt = response ? 4 : 12, lenAt = response ? 6 : 14;
                if (rd16(offAt, off) && rd16(lenAt, len) && off >= kHeader && off - kHeader + len <= bodyLen && len > 0) {
                    const uint8_t *sec = b + (off - kHeader);
                    // the security buffer is NTLMSSP or SPNEGO that wraps it: find the signature
                    size_t at = std::string::npos;
                    for (size_t i = 0; i + 12 <= len; ++i) if (std::memcmp(sec + i, "NTLMSSP\0", 8) == 0) { at = i; break; }
                    if (at != std::string::npos) {
                        const uint32_t type = le32(reinterpret_cast<const char *>(sec) + at + 8);
                        const char *tn = type == 1 ? "NTLMSSP_NEGOTIATE" : type == 2 ? "NTLMSSP_CHALLENGE" : type == 3 ? "NTLMSSP_AUTH" : "NTLMSSP";
                        add(std::string("Security Blob: ") + tn, off + at, len - at);
                        summary += std::string(" [") + tn + "]";
                        if (type == 3 && len - at >= 52) { // domain (28), user (36): length (2), max (2), offset (4) relative to the signature
                            auto sec16 = [&](size_t p) { return static_cast<size_t>(sec[at + p] | (sec[at + p + 1] << 8)); };
                            auto sec32 = [&](size_t p) { return static_cast<size_t>(le32(reinterpret_cast<const char *>(sec) + at + p)); };
                            const size_t dl = sec16(28), dO = sec32(32), ul = sec16(36), uO = sec32(40);
                            const std::string dom = dO + dl <= len - at ? utf16(sec + at + dO, dl, 64) : std::string();
                            const std::string usr = uO + ul <= len - at ? utf16(sec + at + uO, ul, 64) : std::string();
                            if (!usr.empty()) {
                                add("NTLMSSP User: " + (dom.empty() ? usr : dom + "\\" + usr), off + at + uO, ul);
                                summary += " user=" + (dom.empty() ? usr : dom + "\\" + usr);
                                if (commands == 0) pack.app_text = (dom.empty() ? usr : dom + "\\" + usr);
                            }
                        }
                    } else {
                        add("Security Blob (" + std::to_string(len) + " bytes)", off, len);
                    }
                }
            } else if (command == 3 && !response && structSize == 9) { // Tree Connect Request: Reserved(2), PathOffset(2), PathLength(2), Path
                uint16_t off = 0, len = 0;
                if (rd16(4, off) && rd16(6, len) && off >= kHeader && off - kHeader + len <= bodyLen) {
                    const std::string path = utf16(b + (off - kHeader), len, 128);
                    add("Path: " + path, off, len);
                    summary += ", Path: " + path;
                    if (commands == 0) pack.app_text = path;
                }
            } else if (command == 5 && !response && structSize == 57) { // Create Request: ..., NameOffset(2) @44, NameLength(2) @46
                uint16_t off = 0, len = 0;
                if (rd16(44, off) && rd16(46, len) && off >= kHeader && off - kHeader + len <= bodyLen) {
                    const std::string name = utf16(b + (off - kHeader), len, 128);
                    add("File Name: " + (name.empty() ? std::string("<root>") : name), off, len);
                    summary += ", File: " + (name.empty() ? std::string("<root>") : name);
                    if (commands == 0) pack.app_text = name;
                }
            } else if ((command == 8 || command == 9) && !response && structSize == 49) { // Read / Write Request: Length(4) @4, Offset(8) @8
                uint32_t len = 0, offLo = 0;
                if (rd32(4, len) && rd32(8, offLo)) {
                    add("Length: " + std::to_string(len), kHeader + 4, 4);
                    add("Offset: " + std::to_string(offLo), kHeader + 8, 4);
                    summary += ", Len: " + std::to_string(len) + ", Off: " + std::to_string(offLo);
                }
            }
        }
        if (nextCommand != 0 && !(nextCommand >= kHeader && nextCommand <= avail)) malformed = "SMB2 NextCommand outside the message";
        if (treeId != 0 && !async) summary += ", TreeID: " + hexString(treeId, 4);

        infoAll += (commands ? ", " : "") + summary;
        layers.push_back({"SMB2 (" + cmdName + (response ? " Response" : " Request") + ")", {abs, std::min<size_t>(end - pos, kHeader + bodyLen)}});
        layerItems.push_back(std::move(items));
        ++commands;
        if (nextCommand == 0 || malformed) break;
        pos += nextCommand;
    }
    if (commands > 1) pack.app_flags |= kFlagCompound;
    pack.info = infoAll;

    if (ctx.wantFields()) {
        for (size_t i = 0; i < layers.size(); ++i) {
            Field &l = ctx.addLayer(layers[i].first, layers[i].second.first, layers[i].second.second);
            for (const auto &it: layerItems[i]) { // only what lies inside the captured bytes
                if (it.second.first <= o + length) l.add(it.first, it.second.first, std::min(it.second.second, o + length - it.second.first));
            }
        }
        if (layers.empty()) ctx.addLayer("SMB2", o + base, msgLen);
    }
    if (malformed) ctx.markMalformed(malformed);
}

} // namespace dissect
