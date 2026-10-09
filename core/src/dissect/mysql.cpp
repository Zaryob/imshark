// MySQL client/server protocol (https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basics.html).
// A packet is a 3 byte little-endian payload length, a 1 byte sequence id and the payload. The server speaks first (Initial
// Handshake, protocol 10, sequence 0); the client answers with a HandshakeResponse41 or, to go on with TLS, a 32 byte SSLRequest
// (sequence 1, CLIENT_SSL set) that is followed by the TLS handshake. After the handshake the client sends commands (sequence 0,
// first payload byte is the command) and the server answers with OK / ERR / a result set. Which side a packet comes from decides
// what its first byte means, so the direction is decided first: the default port, else the endpoint that sent a greeting.
#include "mysql.h"

#include <cstring>
#include <string>
#include <vector>

#include "db_session.h"
#include "db_values.h"
#include "reader.h"
#include "util.h"

using packet::Field;

namespace dissect {

namespace {

constexpr size_t kMaxPacket = 8u << 20;   // not more than the stream table buffers (a MySQL payload can be 16 MB - 1)
constexpr uint32_t kClientSsl = 0x0800;   // CLIENT_SSL capability flag

// app_flags bits
constexpr uint16_t kFlagServer = 1, kFlagError = 2, kFlagGreeting = 4, kFlagResponse = 8, kFlagSslRequest = 16, kFlagCommand = 32, kFlagPrepareOk = 64, kFlagRow = 128;

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
bool lenenc(ByteReader &r, uint64_t &v) { return myLengthEncoded(r, v); }

bool lenencString(ByteReader &r, std::string &s) {
    uint64_t n = 0;
    if (!lenenc(r, n) || n > r.remaining()) return false;
    s = r.readString(static_cast<size_t>(n));
    return true;
}

// ---- values (the caps keep Info, the tree and the stored state bounded) -------------------------------------------------------
// A value shows at most kValueChars characters (then "..." and its length), a packet at most kTreeValues values in the tree and
// kInfoValues in Info (the rest is counted), and app_text keeps the first kFilterValues of a row.
constexpr size_t kValueChars = 64, kTreeValues = 32, kInfoValues = 4, kFilterValues = 8;
constexpr uint16_t kUnsignedFlag = 0x20;   // column flags: UNSIGNED_FLAG
constexpr uint16_t kBinaryCharset = 63;

const char *typeLabel(uint8_t t) {
    switch (t) {
        case 0x00: return "DECIMAL";
        case 0x01: return "TINY";
        case 0x02: return "SHORT";
        case 0x03: return "LONG";
        case 0x04: return "FLOAT";
        case 0x05: return "DOUBLE";
        case 0x06: return "NULL";
        case 0x07: return "TIMESTAMP";
        case 0x08: return "LONGLONG";
        case 0x09: return "INT24";
        case 0x0a: return "DATE";
        case 0x0b: return "TIME";
        case 0x0c: return "DATETIME";
        case 0x0d: return "YEAR";
        case 0x0f: return "VARCHAR";
        case 0x10: return "BIT";
        case 0xf5: return "JSON";
        case 0xf6: return "NEWDECIMAL";
        case 0xf7: return "ENUM";
        case 0xf8: return "SET";
        case 0xf9: return "TINY_BLOB";
        case 0xfa: return "MEDIUM_BLOB";
        case 0xfb: return "LONG_BLOB";
        case 0xfc: return "BLOB";
        case 0xfd: return "VAR_STRING";
        case 0xfe: return "STRING";
        case 0xff: return "GEOMETRY";
        default: return nullptr;
    }
}

std::string typeText(uint8_t t) {
    const char *n = typeLabel(t);
    return n ? std::string(n) : "type " + std::to_string(t);
}

std::string withLength(std::string shown, size_t n, size_t shownMax) { return n > shownMax ? shown + " (" + std::to_string(n) + " bytes)" : shown; }

// a string value: text, or for the binary character set (BLOB, BINARY, VARBINARY) hexadecimal
std::string stringValue(const uint8_t *v, size_t n, bool binary) {
    if (!binary) return withLength(printableText(v, n, kValueChars), n, kValueChars);
    static const char digits[] = "0123456789abcdef";
    std::string out = "0x";
    for (size_t i = 0; i < n && i < kValueChars / 2; ++i) { out += digits[v[i] >> 4]; out += digits[v[i] & 15]; }
    if (n > kValueChars / 2) out += "...";
    return withLength(out, n * 2, kValueChars);
}

bool isStringType(uint8_t t) {
    switch (t) {
        case 0x00: case 0x0f: case 0x10: case 0xf5: case 0xf6: case 0xf7: case 0xf8: case 0xf9: case 0xfa: case 0xfb: case 0xfc: case 0xfd: case 0xfe: case 0xff: return true;
        default: return false;
    }
}

std::string pad(uint64_t v, int width) { char b[24]; std::snprintf(b, sizeof b, "%0*llu", width, static_cast<unsigned long long>(v)); return b; }

// One value of the binary protocol (rows of COM_STMT_EXECUTE, parameters of COM_STMT_EXECUTE): the type says how many bytes it takes.
// False if the bytes run out (the packet is cut or the type is unknown).
bool binaryValue(ByteReader &r, uint8_t type, bool isUnsigned, bool binaryCharset, std::string &out) {
    switch (type) {
        case 0x01: { if (r.remaining() < 1) return false; const uint8_t v = r.u8(); out = isUnsigned ? std::to_string(v) : std::to_string(static_cast<int8_t>(v)); return true; }
        case 0x02: case 0x0d: { if (r.remaining() < 2) return false; const uint16_t v = r.u16_le(); out = isUnsigned || type == 0x0d ? std::to_string(v) : std::to_string(static_cast<int16_t>(v)); return true; }
        case 0x03: case 0x09: { if (r.remaining() < 4) return false; const uint32_t v = r.u32_le(); out = isUnsigned ? std::to_string(v) : std::to_string(static_cast<int32_t>(v)); return true; }
        case 0x08: { if (r.remaining() < 8) return false; const uint64_t v = r.u64_le(); out = isUnsigned ? std::to_string(v) : std::to_string(static_cast<int64_t>(v)); return true; }
        case 0x04: { if (r.remaining() < 4) return false; const uint32_t u = r.u32_le(); float f; std::memcpy(&f, &u, 4); out = dbFloatText(f, true); return true; }
        case 0x05: { if (r.remaining() < 8) return false; const uint64_t u = r.u64_le(); double d; std::memcpy(&d, &u, 8); out = dbFloatText(d, false); return true; }
        case 0x06: out = "NULL"; return true;
        case 0x07: case 0x0a: case 0x0c: {   // length (0, 4, 7 or 11), year (2), month, day, hour, minute, second, microseconds (4)
            if (r.remaining() < 1) return false;
            const uint8_t len = r.u8();
            if ((len != 0 && len != 4 && len != 7 && len != 11) || r.remaining() < len) return false;
            uint32_t year = 0, month = 0, day = 0, hour = 0, minute = 0, second = 0, micro = 0;
            if (len >= 4) { year = r.u16_le(); month = r.u8(); day = r.u8(); }
            if (len >= 7) { hour = r.u8(); minute = r.u8(); second = r.u8(); }
            if (len == 11) micro = r.u32_le();
            out = pad(year, 4) + "-" + pad(month, 2) + "-" + pad(day, 2);
            if (type != 0x0a) {
                out += " " + pad(hour, 2) + ":" + pad(minute, 2) + ":" + pad(second, 2);
                if (micro) out += "." + pad(micro, 6);
            }
            return true;
        }
        case 0x0b: {   // length (0, 8 or 12), negative flag, days (4), hour, minute, second, microseconds (4)
            if (r.remaining() < 1) return false;
            const uint8_t len = r.u8();
            if ((len != 0 && len != 8 && len != 12) || r.remaining() < len) return false;
            uint32_t negative = 0, days = 0, hour = 0, minute = 0, second = 0, micro = 0;
            if (len >= 8) { negative = r.u8(); days = r.u32_le(); hour = r.u8(); minute = r.u8(); second = r.u8(); }
            if (len == 12) micro = r.u32_le();
            out = std::string(negative ? "-" : "") + pad(static_cast<uint64_t>(days) * 24 + hour, 2) + ":" + pad(minute, 2) + ":" + pad(second, 2);
            if (micro) out += "." + pad(micro, 6);
            return true;
        }
        default:
            if (!isStringType(type)) return false;
            uint64_t n = 0;
            if (!lenenc(r, n) || n > r.remaining()) return false;
            out = stringValue(r.current(), static_cast<size_t>(n), binaryCharset);
            r.skip(static_cast<size_t>(n));
            return true;
    }
}

struct RowValue {
    std::string name, type, text;
    size_t offset = 0, length = 0;   // inside the packet payload
};

// A text protocol row: one length-encoded string (0xfb = NULL) per column.
size_t textRow(const uint8_t *payload, size_t size, const DbColumnSet *columns, std::vector<RowValue> &out) {
    ByteReader r(payload, size);
    const size_t total = columns ? columns->total : 0;
    size_t seen = 0;
    while (r.remaining() > 0 && (total == 0 || seen < total)) {
        RowValue v;
        v.offset = r.offset();
        const MyColumn *col = columns && seen < columns->my.size() ? &columns->my[seen] : nullptr;
        if (r.peek_u8() == 0xfb) {
            r.skip(1);
            v.text = "NULL";
        } else {
            uint64_t n = 0;
            if (!lenenc(r, n) || n > r.remaining()) break;
            v.text = stringValue(r.current(), static_cast<size_t>(n), col && col->charset == kBinaryCharset && isStringType(col->type) && col->type != 0x00 && col->type != 0xf6);
            r.skip(static_cast<size_t>(n));
        }
        v.length = r.offset() - v.offset;
        if (col) { v.name = col->name; v.type = typeText(col->type); }
        if (out.size() < 256) out.push_back(std::move(v));
        ++seen;
    }
    return seen;
}

// A binary protocol row: 0x00, a NULL bitmap of (columns + 7 + 2) / 8 bytes (the first two bits are reserved), then the values of the
// columns that are not NULL. Only the columns the description kept can be read (their types are needed to know each value's size).
size_t binaryRow(const uint8_t *payload, size_t size, const DbColumnSet *columns, std::vector<RowValue> &out) {
    if (!columns || size < 1 || payload[0] != 0x00) return 0;
    const size_t total = columns->total, bitmap = (total + 7 + 2) / 8;
    if (size < 1 + bitmap) return 0;
    ByteReader r(payload + 1 + bitmap, size - 1 - bitmap);
    size_t seen = 0;
    for (size_t i = 0; i < total && i < columns->my.size(); ++i) {
        const MyColumn &col = columns->my[i];
        RowValue v;
        v.name = col.name;
        v.type = typeText(col.type);
        v.offset = 1 + bitmap + r.offset();
        if (payload[1 + (i + 2) / 8] & (1u << ((i + 2) % 8))) {
            v.text = "NULL";
        } else if (!binaryValue(r, col.type, (col.flags & kUnsignedFlag) != 0, col.charset == kBinaryCharset, v.text)) {
            break;
        }
        v.length = 1 + bitmap + r.offset() - v.offset;
        if (out.size() < 256) out.push_back(std::move(v));
        ++seen;
    }
    return seen;
}

std::string joinInfo(const std::vector<RowValue> &v, size_t n) {
    std::string out;
    for (size_t i = 0; i < v.size() && i < n; ++i) out += (i ? ", " : "") + (v[i].name.empty() ? std::string() : printableText(v[i].name.data(), v[i].name.size(), 40) + "=") + v[i].text;
    if (v.size() > n) out += ", ...";
    return out;
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
    const char *malformed = nullptr;   // set when the packet is complete (not cut) but its body does not decode

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

    // session state: decided while the capture loads (only for a packet that was captured whole), Replay reads it
    SessionTables *sessions = ctx.sessions;
    const bool loadPass = ctx.mode != ParseMode::Replay && sessions && !sessions->isFrozen() && !cut;
    const uint32_t number = static_cast<uint32_t>(pack.number);
    const int32_t streamSeq = static_cast<int32_t>(ctx.tcpStreamSeq);
    const std::string conn = sessions ? dbConnectionKey(pack.source, pack.src_port, pack.destination, pack.dst_port) : std::string();
    const auto observe = [&](auto &&f) { return sessions->dbObserve(f); };
    const auto queryAside = [](const DbStatement *st, size_t cap) { return st && st->query && !st->query->empty() ? " (" + printableText(st->query->data(), st->query->size(), cap) + ")" : std::string(); };
    const auto setQuery = [&](const DbStatement *st) { if (st && st->query) pack.app_text = printableText(st->query->data(), st->query->size(), 512); };

    if (payloadLen == 0) {
        typeName = "Empty Packet";
        info = "Empty Packet (Seq " + std::to_string(seq) + ")";
    } else if (have == 0) {
        typeName = "Packet";
        info = "Packet (Seq " + std::to_string(seq) + ", Len " + std::to_string(payloadLen) + ") [cut]";
    } else if (server) {
        const uint8_t first = p.peek_u8();
        // what the session table knows about this packet (the phase of the response in flight)
        MyPacket mp;
        if (sessions && !looksLikeGreeting && !cut) {
            if (loadPass) mp = observe([&](DbTable &t, size_t max, bool &lost) { return t.myServerPacket(conn, number, streamSeq, std::string_view(reinterpret_cast<const char *>(bytes + 4), have), max, lost); });
            else mp = sessions->dbTable().myPacketAt(conn, number, streamSeq, sessions->isTableStateLost("db"));
        }
        if (looksLikeGreeting) {
            typeName = "Server Greeting";
            pack.app_flags |= kFlagGreeting;
            p.skip(1);
            const std::string version = p.stringZ();
            if (!cut && 5 + version.size() >= 4 + have) malformed = "MySQL greeting: server version is not terminated";
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
            if (loadPass) observe([&](DbTable &t, size_t max, bool &lost) { t.myGreeting(conn, caps, max, lost); });
        } else if (first == 0xff) {
            typeName = "ERR";
            pack.app_flags |= kFlagError;
            if (!cut && payloadLen < 3) malformed = "MySQL ERR packet without an error code";
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
        } else if (mp.kind != MyPacket::Unknown) {
            // the phase of the response says what this packet is (no guessing between an OK, a row and a column definition)
            const auto showColumn = [&](const char *what) {
                MyColumn col;
                if (!parseMyColumn(std::string_view(reinterpret_cast<const char *>(bytes + 4), have), col)) { info = std::string(what) + " (Seq " + std::to_string(seq) + ")"; return; }
                const std::string full = printableText(col.table.data(), col.table.size(), 40) + (col.table.empty() ? "" : ".") + printableText(col.name.data(), col.name.size(), 40);
                info = std::string(what) + ": " + full;
                items.push_back({"Column: " + full + " (type " + typeText(col.type) + (col.flags & kUnsignedFlag ? ", unsigned" : "") + ", charset " + std::to_string(col.charset) + ")", {po, have}});
            };
            const auto showOk = [&]() {
                ByteReader ok(bytes + 5, have - 1);
                uint64_t affected = 0, lastId = 0;
                lenenc(ok, affected);
                lenenc(ok, lastId);
                const uint16_t status = ok.remaining() >= 2 ? ok.u16_le() : 0, warnings = ok.remaining() >= 2 ? ok.u16_le() : 0;
                info = "Response " + typeName + " (Seq " + std::to_string(seq) + ", affected rows " + std::to_string(affected) + ")";
                items.push_back({"Affected Rows: " + std::to_string(affected), {po, 0}});
                items.push_back({"Last Insert ID: " + std::to_string(lastId), {po, 0}});
                items.push_back({"Server Status: " + hexString(status, 4), {po, 0}});
                items.push_back({"Warnings: " + std::to_string(warnings), {po, 0}});
            };
            const auto showEof = [&]() {
                info = "Response EOF (Seq " + std::to_string(seq) + ")";
                if (have >= 5) items.push_back({"Warnings: " + std::to_string(le16(data + 5)), {po + 1, 2}});
            };
            switch (mp.kind) {
                case MyPacket::Ok: typeName = "OK"; showOk(); if (mp.more) info += ", more results follow"; break;
                case MyPacket::Eof: case MyPacket::PrepEof: typeName = "EOF"; showEof(); break;
                case MyPacket::RowsEnd:
                    if (first == 0xfe && payloadLen < 7) { typeName = "EOF"; showEof(); } else { typeName = "OK (EOF)"; showOk(); }   // EOF: 0xfe + warnings + status (5 bytes); the CLIENT_DEPRECATE_EOF form is an OK packet (7 or more)
                    if (mp.more) info += ", more results follow";
                    break;
                case MyPacket::ColCount:
                    typeName = "Column Count";
                    info = "Result Set: " + std::to_string(mp.index) + " column" + (mp.index == 1 ? "" : "s") + (mp.binary ? " (binary protocol)" : "");
                    items.push_back({"Column Count: " + std::to_string(mp.index), {po, have}});
                    break;
                case MyPacket::ColDef: typeName = "Column Definition"; showColumn("Column Definition"); break;
                case MyPacket::PrepColDef: typeName = "Column Definition"; showColumn("Column Definition"); break;
                case MyPacket::PrepParamDef: typeName = "Parameter Definition"; showColumn("Parameter Definition"); break;
                case MyPacket::LocalInfile: {
                    typeName = "Local Infile Request";
                    const std::string file = std::string(reinterpret_cast<const char *>(bytes + 5), have - 1);
                    info = "LOCAL INFILE request: " + printableText(file.data(), file.size(), 120);
                    items.push_back({"Filename: " + printableText(file.data(), file.size(), 120), {po + 1, have - 1}});
                    break;
                }
                case MyPacket::PrepareOk: {
                    // COM_STMT_PREPARE_OK: 0x00, statement id (4), columns (2), parameters (2), filler (1), warnings (2)
                    typeName = "Prepare OK";
                    pack.app_flags |= kFlagPrepareOk;
                    const uint32_t id = have >= 5 ? le32(data + 5) : 0;
                    const uint16_t cols = have >= 7 ? le16(data + 9) : 0, params = have >= 9 ? le16(data + 11) : 0;
                    pack.app_text2 = std::to_string(id);
                    setQuery(mp.statement);
                    info = "Prepare OK: statement " + std::to_string(id) + " (" + std::to_string(cols) + " columns, " + std::to_string(params) + " parameters)" + queryAside(mp.statement, 80);
                    items.push_back({"Statement ID: " + std::to_string(id), {po + 1, 4}});
                    items.push_back({"Columns: " + std::to_string(cols), {po + 5, 2}});
                    items.push_back({"Parameters: " + std::to_string(params), {po + 7, 2}});
                    break;
                }
                case MyPacket::Row: {
                    typeName = "Result Row";
                    pack.app_flags |= kFlagRow;
                    std::vector<RowValue> values;
                    const size_t seen = mp.binary ? binaryRow(bytes + 4, have, mp.columns, values) : textRow(bytes + 4, have, mp.columns, values);
                    for (size_t i = 0; i < values.size(); ++i) {
                        if (i < kTreeValues) items.push_back({(values[i].name.empty() ? "Column " + std::to_string(i + 1) : printableText(values[i].name.data(), values[i].name.size(), 40)) +
                                                              (values[i].type.empty() ? "" : " (" + values[i].type + ")") + ": " + values[i].text, {po + values[i].offset, values[i].length}});
                        if (i < kFilterValues) pack.app_text += (i ? ", " : "") + values[i].text;
                    }
                    if (seen > kTreeValues) items.push_back({std::to_string(seen - kTreeValues) + " more columns not shown", {po, 0}});
                    info = "Result Row (Seq " + std::to_string(seq) + ")" + (values.empty() ? std::string() : ": " + joinInfo(values, kInfoValues));
                    break;
                }
                default: break;
            }
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
            if (!cut && (have <= 32 || 4 + 32 + user.size() >= 4 + have)) malformed = "MySQL login request: user name is not terminated";
            pack.app_text2 = printableText(user.data(), user.size(), 63);
            info = "Login Request user=" + printableText(user.data(), user.size(), 63);
            items.push_back({"Client Capabilities: " + hexString(have >= 4 ? le32(data + 4) : 0, 8), {po, std::min<size_t>(have, 4)}});
            items.push_back({"Username: " + printableText(user.data(), user.size(), 63), {po + 32, user.size()}});
            items.push_back({"Authentication Response: (not shown)", {po + 32 + user.size() + 1, 0}});
            if (ctx.sessions) ctx.sessions->markServerEndpoint(pack.destination, pack.dst_port);
            if (loadPass && have >= 4) { const uint32_t clientCaps = le32(data + 4); observe([&](DbTable &t, size_t max, bool &lost) { t.myLogin(conn, clientCaps, max, lost); }); }
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
            std::string commandArg;   // the SQL of COM_STMT_PREPARE, which the table pairs with the statement id of the response
            if (first == 0x03 || first == 0x16) { // COM_QUERY, COM_STMT_PREPARE: the SQL text to the end of the packet
                const std::string q = p.remainingString();
                if (first == 0x16) commandArg = q;
                pack.app_text = printableText(q.data(), q.size(), 512);
                info = std::string(first == 0x03 ? "Query: " : "Prepare: ") + printableText(q.data(), q.size(), 200);
                items.push_back({"Statement: " + pack.app_text, {po + 1, have - 1}});
            } else if (first == 0x02) { // COM_INIT_DB
                const std::string db = p.remainingString();
                pack.app_text = printableText(db.data(), db.size(), 128);
                info = "Init DB: " + pack.app_text;
                items.push_back({"Schema: " + pack.app_text, {po + 1, have - 1}});
            }
            if (loadPass) observe([&](DbTable &t, size_t max, bool &lost) { t.myCommand(conn, first, commandArg, max, lost); });
            if ((first == kMyStmtExecute || first == kMyStmtClose || first == kMyStmtReset || first == kMyStmtSendLongData) && p.remaining() >= 4) {
                const uint32_t id = p.u32_le();
                pack.app_text2 = std::to_string(id);
                items.push_back({"Statement ID: " + std::to_string(id), {po + 1, 4}});
                const DbStatement *known = nullptr;   // the statement as this packet saw it
                if (sessions) known = loadPass ? sessions->dbTable().myStatement(conn, id) : sessions->dbTable().myNote(number, streamSeq);
                std::vector<RowValue> params;
                std::vector<uint8_t> boundTypes;
                bool newBound = false;
                if (first == kMyStmtExecute && p.remaining() >= 5) {
                    // flags (1), iteration count (4); then, for a statement with parameters, the NULL bitmap, "new parameters bound", the
                    // types (type, unsigned flag) when new, and the values of the parameters that are not NULL
                    p.skip(5);
                    const size_t n = known ? known->params : 0;
                    const size_t bitmapBytes = (n + 7) / 8;
                    if (n > 0 && p.remaining() >= bitmapBytes + 1) {
                        const uint8_t *bitmap = p.current();
                        p.skip(bitmapBytes);
                        newBound = p.u8() != 0;
                        std::vector<uint8_t> types = known->paramTypes;
                        if (newBound) {
                            types.clear();
                            if (p.remaining() >= n * 2) { types.assign(p.current(), p.current() + n * 2); p.skip(n * 2); }
                        }
                        if (newBound && types.size() == n * 2) boundTypes = types;
                        for (size_t i = 0; i < n && types.size() == n * 2; ++i) {
                            RowValue v;
                            v.name = "$" + std::to_string(i + 1);
                            v.type = typeText(types[i * 2]);
                            v.offset = 1 + p.offset();
                            if (bitmap[i / 8] & (1u << (i % 8))) v.text = "NULL";
                            else if (!binaryValue(p, types[i * 2], (types[i * 2 + 1] & 0x80) != 0, false, v.text)) break;
                            v.length = 1 + p.offset() - v.offset;
                            if (params.size() < 256) params.push_back(std::move(v));
                        }
                    }
                }
                const DbStatement *st = known;
                if (loadPass) st = observe([&](DbTable &t, size_t max, bool &lost) { return t.myStatementCommand(conn, number, streamSeq, id, newBound && !boundTypes.empty() ? &boundTypes : nullptr, first == kMyStmtClose, max, lost); });
                setQuery(st);
                const char *verb = first == kMyStmtExecute ? "Execute" : first == kMyStmtClose ? "Close" : first == kMyStmtReset ? "Reset" : "Send Long Data";
                info = std::string(verb) + ": statement " + std::to_string(id) + queryAside(st, 80);
                if (first == kMyStmtSendLongData && p.remaining() >= 2) {
                    const uint16_t param = p.u16_le();
                    info += ", parameter " + std::to_string(param) + ", " + std::to_string(p.remaining()) + " bytes";
                    items.push_back({"Parameter: " + std::to_string(param), {po + 5, 2}});
                }
                if (!st && sessions) items.push_back({"[statement not prepared in this capture]", {po, 0}});
                if (!params.empty()) info += ": " + joinInfo(params, kInfoValues);
                for (size_t i = 0; i < params.size() && i < kTreeValues; ++i) items.push_back({"Parameter " + params[i].name + " (" + params[i].type + "): " + params[i].text, {po + params[i].offset, params[i].length}});
            }
        }
    }

    pack.info = info + (cut ? " [cut]" : "");
    if (malformed) ctx.markMalformed(malformed);
    if (ctx.wantFields()) {
        Field &l = ctx.addLayer("MySQL Protocol (" + typeName + ")", o, std::min<size_t>(4 + payloadLen, length));
        for (const auto &it: items) {
            const size_t rel = it.second.first - o;
            if (rel <= length) l.add(it.first, it.second.first, std::min(it.second.second, length - rel));
        }
    }
}

} // namespace dissect
