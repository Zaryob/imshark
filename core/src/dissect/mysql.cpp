// MySQL client/server protocol (https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basics.html).
// A packet is a 3 byte little-endian payload length, a 1 byte sequence id and the payload. The server speaks first (Initial
// Handshake, protocol 10, sequence 0); the client answers with a HandshakeResponse41 or, to go on with TLS, a 32 byte SSLRequest
// (sequence 1, CLIENT_SSL set) that is followed by the TLS handshake. After the handshake the client sends commands (sequence 0,
// first payload byte is the command) and the server answers with OK / ERR / a result set. Which side a packet comes from decides
// what its first byte means, so the direction is decided first: the default port, else the endpoint that sent a greeting.
#include "mysql.h"

#include <string>
#include <vector>

#include "reader.h"
#include "util.h"

using packet::Field;

namespace dissect {

namespace {

constexpr size_t kMaxPacket = 8u << 20;   // not more than the stream table buffers (a MySQL payload can be 16 MB - 1)
constexpr uint32_t kClientSsl = 0x0800;   // CLIENT_SSL capability flag

// app_flags bits
constexpr uint16_t kFlagServer = 1, kFlagError = 2, kFlagGreeting = 4, kFlagResponse = 8, kFlagSslRequest = 16, kFlagCommand = 32;

const char *commandName(uint8_t cmd) {
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

// Length-encoded integer; returns false if it does not fit
bool lenenc(ByteReader &r, uint64_t &v) {
    if (r.remaining() < 1) return false;
    const uint8_t first = r.u8();
    if (first < 0xfb) { v = first; return true; }
    if (first == 0xfc) { if (r.remaining() < 2) return false; v = r.u16_le(); return true; }
    if (first == 0xfd) { if (r.remaining() < 3) return false; v = r.u24_le(); return true; }
    if (first == 0xfe) { if (r.remaining() < 8) return false; v = r.u64_le(); return true; }
    return false;   // 0xfb is NULL, 0xff is ERR
}

bool lenencString(ByteReader &r, std::string &s) {
    uint64_t n = 0;
    if (!lenenc(r, n) || n > r.remaining()) return false;
    s = r.readString(static_cast<size_t>(n));
    return true;
}

} // namespace

StreamFrame frameMySql(const char *data, size_t length) {
    if (length < 4) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    const size_t payloadLen = static_cast<size_t>(bytes[0]) | (static_cast<size_t>(bytes[1]) << 8) | (static_cast<size_t>(bytes[2]) << 16);
    const size_t total = 4 + payloadLen;
    if (total > kMaxPacket) return StreamFrame{StreamFrame::Kind::Reject, 0};   // a payload of 8 MB or more is not buffered
    return StreamFrame{length < total ? StreamFrame::Kind::NeedMore : StreamFrame::Kind::Complete, total};
}

void dissectMySql(Context &ctx, const char *data, size_t length) {
    if (!data || length < 4) return;
    auto &pack = ctx.pack;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader hdr(bytes, length);
    const uint32_t payloadLen = hdr.u24_le();
    const uint8_t seq = hdr.u8();
    pack.protocol = "MySQL";
    pack.app_stream = seq;
    const size_t o = ctx.offsetOf(data);
    const size_t have = std::min<size_t>(payloadLen, length - 4);   // payload bytes captured
    ByteReader p(bytes + 4, have);
    const bool cut = payloadLen > length - 4;

    // who sent it: the default port, else an endpoint that was seen sending a greeting
    bool server = pack.src_port == 3306;
    if (!server && pack.dst_port != 3306 && ctx.sessions) server = ctx.sessions->isServerEndpoint(pack.source, pack.src_port);
    const bool looksLikeGreeting = seq == 0 && have >= 6 && bytes[4] == 0x0a && bytes[5] >= '0' && bytes[5] <= '9';
    if (!server && pack.src_port != 3306 && pack.dst_port != 3306 && looksLikeGreeting) server = true;

    std::string typeName, info;
    std::vector<std::pair<std::string, std::pair<size_t, size_t>>> items;   // detail-tree children: text, offset, length
    items.push_back({"Packet Length: " + std::to_string(payloadLen), {o, 3}});
    items.push_back({"Packet Number: " + std::to_string(seq), {o + 3, 1}});
    const size_t po = o + 4;   // payload offset

    if (server) pack.app_flags |= kFlagServer;

    if (payloadLen == 0) {
        typeName = "Empty Packet";
        info = "Empty Packet (Seq " + std::to_string(seq) + ")";
    } else if (have == 0) {
        typeName = "Packet";
        info = "Packet (Seq " + std::to_string(seq) + ", Len " + std::to_string(payloadLen) + ") [cut]";
    } else if (server) {
        const uint8_t first = p.peek_u8();
        if (looksLikeGreeting) {
            typeName = "Server Greeting";
            pack.app_flags |= kFlagGreeting;
            p.skip(1);
            const std::string version = p.stringZ();
            std::string greeting = "Server Greeting proto=10 version=" + printableText(version.data(), version.size(), 63);
            items.push_back({"Protocol: 10", {po, 1}});
            items.push_back({"Version: " + printableText(version.data(), version.size(), 63), {po + 1, version.size() + 1}});
            pack.app_text2 = printableText(version.data(), version.size(), 63);
            if (p.remaining() >= 4) {
                const uint32_t tid = p.u32_le();
                items.push_back({"Connection ID: " + std::to_string(tid), {po + 2 + version.size(), 4}});
                greeting += " conn=" + std::to_string(tid);
            }
            // auth-plugin-data part 1 (8) + filler (1) + capabilities low (2) [+ charset (1) + status (2) + capabilities high (2)
            // + auth data length (1) + reserved (10) + auth data part 2 + plugin name]
            uint32_t caps = 0;
            if (p.remaining() >= 11) {
                p.skip(9);
                caps = p.u16_le();
                if (p.remaining() >= 5) {
                    p.skip(3);
                    caps |= static_cast<uint32_t>(p.u16_le()) << 16;
                    const size_t authLen = p.remaining() >= 1 ? p.u8() : 0;
                    if (p.remaining() >= 10) p.skip(10);
                    const size_t part2 = std::max<size_t>(13, authLen > 8 ? authLen - 8 : 0);
                    if (p.remaining() >= part2) p.skip(part2);
                    if (caps & 0x80000) { // CLIENT_PLUGIN_AUTH
                        const std::string plugin = p.stringZ();
                        if (!plugin.empty()) { greeting += " auth=" + printableText(plugin.data(), plugin.size(), 40); items.push_back({"Authentication Plugin: " + printableText(plugin.data(), plugin.size(), 40), {po, have}}); }
                    }
                }
                items.push_back({"Server Capabilities: " + hexString(caps, 8) + ((caps & kClientSsl) ? " (SSL supported)" : ""), {po, have}});
                if (caps & kClientSsl) greeting += " (SSL)";
            }
            info = greeting;
            if (ctx.sessions) ctx.sessions->markServerEndpoint(pack.source, pack.src_port);
        } else if (first == 0xff) {
            typeName = "ERR";
            pack.app_flags |= kFlagError;
            p.skip(1);
            const uint16_t code = p.remaining() >= 2 ? p.u16_le() : 0;
            std::string state;
            if (p.remaining() >= 6 && p.peek_u8() == '#') { p.skip(1); state = p.readString(5); }
            const std::string msg = p.remainingString();
            pack.app_code = code;
            info = "Response ERR " + std::to_string(code) + (state.empty() ? "" : " " + printableText(state.data(), state.size(), 5)) + (msg.empty() ? "" : ": " + printableText(msg.data(), msg.size(), 120));
            items.push_back({"Error Code: " + std::to_string(code), {po + 1, 2}});
            if (!state.empty()) items.push_back({"SQL State: " + printableText(state.data(), state.size(), 5), {po + 3, 6}});
            items.push_back({"Error Message: " + printableText(msg.data(), msg.size(), 200), {po + 1, have - 1}});
        } else if (first == 0xfe && payloadLen < 9) {
            typeName = "EOF";
            info = "Response EOF (Seq " + std::to_string(seq) + ")";
            if (have >= 5) items.push_back({"Warnings: " + std::to_string(le16(data + 5)), {po + 1, 2}});
        } else if (first == 0xfe && seq == 2) {
            typeName = "Authentication Switch Request";
            p.skip(1);
            const std::string plugin = p.stringZ();
            info = "Authentication Switch Request plugin=" + printableText(plugin.data(), plugin.size(), 40);
            items.push_back({"Authentication Plugin: " + printableText(plugin.data(), plugin.size(), 40), {po + 1, plugin.size() + 1}});
        } else if (first == 0x01 && seq >= 2 && payloadLen <= 4) {
            typeName = "Authentication More Data";
            info = "Authentication More Data (Seq " + std::to_string(seq) + ")";
        } else if (first == 0x00 || first == 0xfe) {
            // OK: affected rows, last insert id (length-encoded), status flags, warnings; 0xfe is the OK of CLIENT_DEPRECATE_EOF.
            // A text row whose first value is empty also starts with 0x00: it is an OK only early in the exchange and if its fields add up.
            ByteReader ok(bytes + 5, have - 1);
            uint64_t affected = 0, lastId = 0;
            const bool parsed = lenenc(ok, affected) && lenenc(ok, lastId) && ok.remaining() >= 4;
            if (parsed && (first == 0xfe || seq <= 3)) {
                typeName = first == 0xfe ? "OK (EOF)" : "OK";
                const uint16_t status = ok.u16_le(), warnings = ok.u16_le();
                info = "Response " + typeName + " (Seq " + std::to_string(seq) + ", affected rows " + std::to_string(affected) + ")";
                items.push_back({"Affected Rows: " + std::to_string(affected), {po, 0}});
                items.push_back({"Server Status: " + hexString(status, 4), {po, 0}});
                items.push_back({"Warnings: " + std::to_string(warnings), {po, 0}});
            } else {
                typeName = "Result Row";
                info = "Result Row (Seq " + std::to_string(seq) + ")";
            }
        } else if (payloadLen == 1 && seq == 1 && first < 0xfb) {
            typeName = "Column Count";
            info = "Result Set: " + std::to_string(first) + " column" + (first == 1 ? "" : "s");
            items.push_back({"Column Count: " + std::to_string(first), {po, 1}});
        } else if (have >= 5 && first == 3 && bytes[5] == 'd' && bytes[6] == 'e' && bytes[7] == 'f') {
            // Column Definition: catalog "def", schema, table, org_table, name, org_name (length-encoded strings)
            typeName = "Column Definition";
            std::string cat, schema, table, orgTable, name;
            const bool ok = lenencString(p, cat) && lenencString(p, schema) && lenencString(p, table) && lenencString(p, orgTable) && lenencString(p, name);
            info = "Column Definition" + (ok ? ": " + printableText(table.data(), table.size(), 40) + "." + printableText(name.data(), name.size(), 40) : std::string());
            if (ok) items.push_back({"Column: " + printableText(table.data(), table.size(), 40) + "." + printableText(name.data(), name.size(), 40), {po, have}});
        } else {
            typeName = "Result Row";
            std::string firstValue;
            ByteReader row(bytes + 4, have);
            lenencString(row, firstValue);
            info = "Result Row (Seq " + std::to_string(seq) + ")" + (firstValue.empty() ? "" : ": " + printableText(firstValue.data(), firstValue.size(), 60));
        }
    } else { // client
        const uint8_t first = p.peek_u8();
        if (seq == 1 && payloadLen >= 32 && have >= 4 && (le32(data + 4) & kClientSsl) && payloadLen == 32) {
            typeName = "SSL Request";
            pack.app_flags |= kFlagSslRequest;
            info = "SSLRequest - TLS follows";
            items.push_back({"Client Capabilities: " + hexString(le32(data + 4), 8) + " (SSL)", {po, 4}});
            // the server accepts by waiting for the TLS handshake: both directions carry TLS from here (load pass; Replay reads)
            if (ctx.sessions && ctx.tcpStreamSeq >= 0 && pack.tcp_relative_ack >= 0) {
                ctx.sessions->markTlsUpgrade(pack.source, pack.src_port, pack.destination, pack.dst_port, static_cast<uint32_t>(ctx.tcpStreamSeq) + 4 + payloadLen);
                ctx.sessions->markTlsUpgrade(pack.destination, pack.dst_port, pack.source, pack.src_port, static_cast<uint32_t>(pack.tcp_relative_ack));
            }
            if (ctx.sessions) ctx.sessions->markServerEndpoint(pack.destination, pack.dst_port);
        } else if (seq == 1 && payloadLen >= 33) {
            // HandshakeResponse41: capabilities (4), max packet (4), charset (1), reserved (23), username NUL, auth response ...
            typeName = "Login Request";
            pack.app_flags |= kFlagResponse;
            std::string user;
            if (have > 32) {
                ByteReader u(bytes + 4 + 32, have - 32);
                user = u.stringZ();
            }
            pack.app_text2 = printableText(user.data(), user.size(), 63);
            info = "Login Request user=" + printableText(user.data(), user.size(), 63);
            items.push_back({"Client Capabilities: " + hexString(have >= 4 ? le32(data + 4) : 0, 8), {po, std::min<size_t>(have, 4)}});
            items.push_back({"Username: " + printableText(user.data(), user.size(), 63), {po + 32, user.size()}});
            items.push_back({"Authentication Response: (not shown)", {po + 32 + user.size() + 1, 0}});
            if (ctx.sessions) ctx.sessions->markServerEndpoint(pack.destination, pack.dst_port);
        } else if (seq >= 1) {
            typeName = "Authentication Response";
            info = "Authentication Response (Seq " + std::to_string(seq) + ", Len " + std::to_string(payloadLen) + ")";
        } else {
            // a command: the first payload byte
            const char *cmd = commandName(first);
            typeName = cmd ? cmd : "Command " + std::to_string(first);
            pack.app_type = first;
            pack.app_flags |= kFlagCommand;
            p.skip(1);
            info = typeName;
            items.push_back({"Command: " + typeName + " (" + std::to_string(first) + ")", {po, 1}});
            if (first == 0x03 || first == 0x16) { // COM_QUERY, COM_STMT_PREPARE: the SQL text to the end of the packet
                const std::string q = p.remainingString();
                pack.app_text = printableText(q.data(), q.size(), 512);
                info = std::string(first == 0x03 ? "Query: " : "Prepare: ") + printableText(q.data(), q.size(), 200);
                items.push_back({"Statement: " + pack.app_text, {po + 1, have - 1}});
            } else if (first == 0x02) { // COM_INIT_DB
                const std::string db = p.remainingString();
                pack.app_text = printableText(db.data(), db.size(), 128);
                info = "Init DB: " + pack.app_text;
                items.push_back({"Schema: " + pack.app_text, {po + 1, have - 1}});
            } else if (first == 0x17 && p.remaining() >= 4) { // COM_STMT_EXECUTE: statement id
                const uint32_t id = p.u32_le();
                info = "Execute: statement " + std::to_string(id);
                items.push_back({"Statement ID: " + std::to_string(id), {po + 1, 4}});
            } else if (first == 0x19 && p.remaining() >= 4) { // COM_STMT_CLOSE
                info = "Close: statement " + std::to_string(p.u32_le());
            }
        }
    }

    pack.info = info + (cut ? " [cut]" : "");
    if (ctx.wantFields()) {
        Field &l = ctx.addLayer("MySQL Protocol (" + typeName + ")", o, std::min<size_t>(4 + payloadLen, length));
        for (const auto &it: items) {
            const size_t rel = it.second.first - o;
            if (rel <= length) l.add(it.first, it.second.first, std::min(it.second.second, length - rel));
        }
    }
}

} // namespace dissect
