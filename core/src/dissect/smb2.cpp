#include "smb2.h"
#include "reader.h"
#include "util.h"
#include <cstdio>
#include <string>

namespace dissect {

namespace {

const char *smb2CommandName(uint16_t cmd) {
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

const char *ntStatusName(uint32_t status) {
    switch (status) {
        case 0x00000000: return "STATUS_SUCCESS";
        case 0x00000103: return "STATUS_NOT_A_DIRECTORY";
        case 0x0000010B: return "STATUS_NOTIFY_CLEANUP";
        case 0x0000010C: return "STATUS_NOTIFY_ENUM_DIR";
        case 0x00000107: return "STATUS_DIRECTORY_NOT_EMPTY";
        case 0xC0000001: return "STATUS_UNSUCCESSFUL";
        case 0xC0000008: return "STATUS_INVALID_HANDLE";
        case 0xC000000F: return "STATUS_NO_SUCH_FILE";
        case 0xC0000022: return "STATUS_ACCESS_DENIED";
        case 0xC0000034: return "STATUS_OBJECT_NAME_NOT_FOUND";
        case 0xC0000035: return "STATUS_OBJECT_NAME_COLLISION";
        case 0xC000003A: return "STATUS_OBJECT_PATH_NOT_FOUND";
        case 0xC0000043: return "STATUS_SHARING_VIOLATION";
        case 0xC000005E: return "STATUS_NO_LOGON_SERVERS";
        case 0xC000006D: return "STATUS_LOGON_FAILURE";
        case 0xC000006E: return "STATUS_ACCOUNT_RESTRICTION";
        case 0xC000006F: return "STATUS_INVALID_LOGON_HOURS";
        case 0xC0000070: return "STATUS_INVALID_WORKSTATION";
        case 0xC0000071: return "STATUS_PASSWORD_EXPIRED";
        case 0xC0000072: return "STATUS_ACCOUNT_DISABLED";
        case 0xC000009A: return "STATUS_INSUFFICIENT_RESOURCES";
        case 0xC00000CC: return "STATUS_BAD_NETWORK_NAME";
        case 0xC00000BA: return "STATUS_FILE_IS_A_DIRECTORY";
        case 0xC00000BB: return "STATUS_NOT_SUPPORTED";
        case 0xC0000101: return "STATUS_ALL_SIDS_FOUND";
        case 0xC0000120: return "STATUS_CANCELLED";
        case 0xC0000133: return "STATUS_TIME_DIFFERENCE_AT_ISSUE";
        case 0xC0000203: return "STATUS_USER_SESSION_DELETED";
        case 0xC0000225: return "STATUS_NOT_FOUND";
        default: return nullptr;
    }
}

} // namespace

StreamFrame frameSmb2(const char *data, size_t length) {
    if (length < 4) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    // NetBIOS session header: 1 byte type (0x00 = session message), 3 bytes length
    uint32_t len = (static_cast<uint32_t>(bytes[1]) << 16) |
                   (static_cast<uint32_t>(bytes[2]) << 8) |
                   static_cast<uint32_t>(bytes[3]);

    if (len > 16 * 1024 * 1024) { // 16 MB limit
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }

    size_t total = 4 + static_cast<size_t>(len);
    if (length < total) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    return StreamFrame{StreamFrame::Kind::Complete, total};
}

void dissectSmb2(Context &ctx, const char *data, size_t length) {
    if (!data || length < 4) return;

    size_t offset = 0;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);

    // If starts with NetBIOS session service header (first byte 0x00 and remaining >= 4)
    // Check if byte 4..7 has SMB2 magic (\xfeSMB) or SMB1 magic (\xffSMB)
    if (length >= 8 && bytes[0] == 0x00 && bytes[4] == 0xfe && bytes[5] == 'S' && bytes[6] == 'M' && bytes[7] == 'B') {
        offset = 4;
    } else if (length >= 8 && bytes[0] == 0x00 && bytes[4] == 0xff && bytes[5] == 'S' && bytes[6] == 'M' && bytes[7] == 'B') {
        offset = 4;
    }

    if (offset + 4 > length) return;

    // Check Magic
    bool isSmb2 = (bytes[offset] == 0xfe && bytes[offset + 1] == 'S' && bytes[offset + 2] == 'M' && bytes[offset + 3] == 'B');
    bool isSmb1 = (bytes[offset] == 0xff && bytes[offset + 1] == 'S' && bytes[offset + 2] == 'M' && bytes[offset + 3] == 'B');

    if (!isSmb2 && !isSmb1) {
        return;
    }

    if (isSmb1) {
        ctx.pack.protocol = "SMB";
        ctx.pack.info = "SMB (Legacy SMB1)";
        if (ctx.wantFields()) {
            const size_t o = ctx.offsetOf(data) + offset;
            ctx.addLayer("Server Message Block (SMB1)", o, length - offset);
        }
        return;
    }

    // SMB2 / SMB3
    // Header is 64 bytes:
    // 0..3: ProtocolId (\xFESMB)
    // 4..5: StructureSize (must be 64)
    // 6..7: CreditCharge
    // 8..11: Status (in responses) / ChannelSequence / Reserved
    // 12..13: Command (uint16)
    // 14..15: Credits
    // 16..19: Flags (uint32)
    // 20..23: NextCommand (uint32)
    // 24..31: MessageId (uint64)
    // 32..35: Reserved / AsyncId
    // 36..39: TreeId (uint32)
    // 40..47: SessionId (uint64)
    // 48..63: Signature (16 bytes)
    if (length - offset < 64) {
        ctx.markMalformed("SMB2 truncated header");
        ctx.pack.protocol = "SMB2";
        ctx.pack.info = "SMB2 [Truncated]";
        return;
    }

    ByteReader r(bytes + offset, length - offset);
    r.skip(8); // Magic (4), StructureSize (2), CreditCharge (2)
    uint32_t status = r.u32_le();
    uint16_t command = r.u16_le();
    r.skip(2); // Credits
    uint32_t flags = r.u32_le();
    uint32_t nextCommand = r.u32_le();
    uint64_t messageId = r.u64_le();
    r.skip(4); // Reserved/AsyncId
    uint32_t treeId = r.u32_le();
    uint64_t sessionId = r.u64_le();
    r.skip(16); // Signature

    bool isResponse = (flags & 0x00000001) != 0;
    bool isSigned = (flags & 0x00000008) != 0;

    std::string cmdName = smb2CommandName(command);
    std::string protoName = "SMB2";

    ctx.pack.protocol = protoName;
    ctx.pack.app_type = command;

    std::string summary = cmdName + (isResponse ? " Response" : " Request");
    if (isResponse) {
        const char *stName = ntStatusName(status);
        if (stName) {
            summary += ", " + std::string(stName);
        } else if (status != 0) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), ", NT_STATUS_0x%08X", status);
            summary += buf;
        }
    }
    if (treeId != 0) {
        summary += ", TreeID: 0x" + hexString(treeId, 4);
    }

    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data) + offset;
        auto &root = ctx.addLayer("SMB2 (" + cmdName + (isResponse ? " Response" : " Request") + ")", o, 64);
        root.add("Command: " + cmdName + " (" + std::to_string(command) + ")");
        root.add("Flags: 0x" + hexString(flags, 8) + (isResponse ? " (Response)" : " (Request)"));
        if (nextCommand != 0) root.add("Next Command: " + std::to_string(nextCommand));
        if (isSigned) root.add("Signed: Yes");
        root.add("Message ID: " + std::to_string(messageId));
        if (isResponse) {
            const char *stName = ntStatusName(status);
            root.add("NT Status: 0x" + hexString(status, 8) + (stName ? " (" + std::string(stName) + ")" : ""));
        }
        root.add("Tree ID: 0x" + hexString(treeId, 4));
        root.add("Session ID: 0x" + hexString(sessionId, 8));
    }
}

} // namespace dissect
