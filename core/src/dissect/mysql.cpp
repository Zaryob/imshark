#include "mysql.h"
#include "reader.h"
#include "util.h"
#include <cstdio>
#include <string>

namespace dissect {

namespace {

const char *mySqlCommandName(uint8_t cmd) {
    switch (cmd) {
        case 0x00: return "COM_SLEEP";
        case 0x01: return "COM_QUIT";
        case 0x02: return "COM_INIT_DB";
        case 0x03: return "COM_QUERY";
        case 0x04: return "COM_FIELD_LIST";
        case 0x05: return "COM_CREATE_DB";
        case 0x06: return "COM_DROP_DB";
        case 0x07: return "COM_REFRESH";
        case 0x08: return "COM_SHUTDOWN";
        case 0x09: return "COM_STATISTICS";
        case 0x0A: return "COM_PROCESS_INFO";
        case 0x0B: return "COM_CONNECT";
        case 0x0C: return "COM_PROCESS_KILL";
        case 0x0D: return "COM_DEBUG";
        case 0x0E: return "COM_PING";
        case 0x0F: return "COM_TIME";
        case 0x10: return "COM_DELAYED_INSERT";
        case 0x11: return "COM_CHANGE_USER";
        case 0x12: return "COM_BINLOG_DUMP";
        case 0x13: return "COM_TABLE_DUMP";
        case 0x14: return "COM_CONNECT_OUT";
        case 0x15: return "COM_REGISTER_SLAVE";
        case 0x16: return "COM_STMT_PREPARE";
        case 0x17: return "COM_STMT_EXECUTE";
        case 0x18: return "COM_STMT_SEND_LONG_DATA";
        case 0x19: return "COM_STMT_CLOSE";
        case 0x1A: return "COM_STMT_RESET";
        case 0x1B: return "COM_SET_OPTION";
        case 0x1C: return "COM_STMT_FETCH";
        case 0x1D: return "COM_DAEMON";
        case 0x1E: return "COM_BINLOG_DUMP_GTID";
        case 0x1F: return "COM_RESET_CONNECTION";
        default: return nullptr;
    }
}

} // namespace

StreamFrame frameMySql(const char *data, size_t length) {
    if (length < 4) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    // 3 bytes little-endian packet length
    uint32_t payloadLen = static_cast<uint32_t>(bytes[0]) |
                          (static_cast<uint32_t>(bytes[1]) << 8) |
                          (static_cast<uint32_t>(bytes[2]) << 16);

    if (payloadLen > 16 * 1024 * 1024) { // 16 MB max packet size
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }

    size_t total = 4 + static_cast<size_t>(payloadLen);
    if (length < total) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    return StreamFrame{StreamFrame::Kind::Complete, total};
}

void dissectMySql(Context &ctx, const char *data, size_t length) {
    if (!data || length < 4) return;

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    uint32_t payloadLen = r.u24_le();
    uint8_t seqId = r.u8();

    ctx.pack.protocol = "MySQL";

    if (payloadLen == 0) {
        ctx.pack.info = "Empty Packet (Seq " + std::to_string(seqId) + ")";
        return;
    }

    if (r.remaining() == 0) return;

    // Check packet type
    // If seqId == 0, could be Initial Handshake (server -> client) or Command (client -> server)
    uint8_t firstByte = r.peek_u8();

    std::string summary;
    std::string typeName;

    // Initial Handshake packet (protocol version 10 = 0x0A)
    if (seqId == 0 && firstByte == 0x0A && r.remaining() >= 5) {
        r.skip(1); // skip protocol version 10
        std::string serverVersion;
        while (r.remaining() > 0 && r.peek_u8() != 0) {
            serverVersion.push_back(static_cast<char>(r.u8()));
        }
        if (r.remaining() > 0) r.skip(1); // null terminator

        typeName = "Server Greeting";
        summary = "Server Greeting proto=10 version=" + serverVersion;
    }
    // OK packet: 0x00 header, EOF packet: 0xFE, ERR packet: 0xFF
    else if (firstByte == 0x00 && r.remaining() >= 3) {
        typeName = "OK";
        summary = "Response OK (Seq " + std::to_string(seqId) + ")";
    } else if (firstByte == 0xFF && r.remaining() >= 3) {
        typeName = "ERR";
        r.skip(1);
        uint16_t errCode = r.u16_le();
        summary = "Response ERR " + std::to_string(errCode);
        ctx.pack.app_code = errCode;
    } else if (firstByte == 0xFE && r.remaining() <= 9) {
        typeName = "EOF";
        summary = "Response EOF (Seq " + std::to_string(seqId) + ")";
    } else {
        // Assume client command packet
        const char *cmd = mySqlCommandName(firstByte);
        if (cmd) {
            typeName = cmd;
            ctx.pack.app_type = firstByte;
            if (firstByte == 0x03 && r.remaining() > 1) { // COM_QUERY
                r.skip(1);
                std::string q;
                while (r.remaining() > 0) {
                    q.push_back(static_cast<char>(r.u8()));
                }
                summary = "Query: " + q;
                ctx.pack.app_text = q;
            } else if (firstByte == 0x02 && r.remaining() > 1) { // COM_INIT_DB
                r.skip(1);
                std::string db;
                while (r.remaining() > 0) {
                    db.push_back(static_cast<char>(r.u8()));
                }
                summary = "Init DB: " + db;
                ctx.pack.app_text = db;
            } else {
                summary = std::string("Command: ") + cmd;
            }
        } else {
            typeName = "Payload";
            summary = "Packet (Seq " + std::to_string(seqId) + ", Len " + std::to_string(payloadLen) + ")";
        }
    }

    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("MySQL Protocol (" + typeName + ")", o, 4 + payloadLen <= length ? 4 + payloadLen : length);
        root.add("Payload Length: " + std::to_string(payloadLen));
        root.add("Sequence ID: " + std::to_string(seqId));
        if (!ctx.pack.app_text.empty()) {
            root.add("Content: " + ctx.pack.app_text);
        }
    }
}

} // namespace dissect
