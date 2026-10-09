// PostgreSQL frontend/backend protocol 3.0 (https://www.postgresql.org/docs/current/protocol-message-formats.html).
// A message is a 1 byte type and an Int32 length that counts itself but not the type. The startup packets (StartupMessage,
// SSLRequest, GSSENCRequest, CancelRequest) have no type byte: Int32 length, Int32 code. The server answers an SSLRequest /
// GSSENCRequest with one byte, 'S' (go on, TLS follows) or 'N'.
#include "postgres.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "db_session.h"
#include "reader.h"
#include "util.h"

using packet::Field;

namespace dissect {

namespace {

constexpr uint32_t kSslRequest = 80877103, kCancelRequest = 80877102, kGssEncRequest = 80877104;
constexpr uint32_t kMaxStartup = 10000;                 // MAX_STARTUP_PACKET_LENGTH of the server
constexpr size_t kMaxMessage = 8u << 20;                // not more than the stream table buffers

const char *backendName(char type) {
    switch (type) {
        case 'R': return "Authentication";
        case 'K': return "BackendKeyData";
        case 'S': return "ParameterStatus";
        case 'Z': return "ReadyForQuery";
        case 'T': return "RowDescription";
        case 'D': return "DataRow";
        case 'C': return "CommandComplete";
        case '1': return "ParseComplete";
        case '2': return "BindComplete";
        case '3': return "CloseComplete";
        case 'n': return "NoData";
        case 't': return "ParameterDescription";
        case 's': return "PortalSuspended";
        case 'I': return "EmptyQueryResponse";
        case 'E': return "ErrorResponse";
        case 'N': return "NoticeResponse";
        case 'A': return "NotificationResponse";
        case 'V': return "FunctionCallResponse";
        case 'v': return "NegotiateProtocolVersion";
        case 'G': return "CopyInResponse";
        case 'H': return "CopyOutResponse";
        case 'W': return "CopyBothResponse";
        case 'd': return "CopyData";
        case 'c': return "CopyDone";
        default: return nullptr;
    }
}

const char *frontendName(char type) {
    switch (type) {
        case 'Q': return "SimpleQuery";
        case 'P': return "Parse";
        case 'B': return "Bind";
        case 'E': return "Execute";
        case 'D': return "Describe";
        case 'C': return "Close";
        case 'S': return "Sync";
        case 'H': return "Flush";
        case 'F': return "FunctionCall";
        case 'X': return "Terminate";
        case 'p': return "PasswordMessage";
        case 'd': return "CopyData";
        case 'c': return "CopyDone";
        case 'f': return "CopyFail";
        default: return nullptr;
    }
}

bool knownType(char type) { return backendName(type) || frontendName(type); }

const char *authTypeName(uint32_t t) {
    switch (t) {
        case 0: return "Ok";
        case 2: return "KerberosV5";
        case 3: return "CleartextPassword";
        case 5: return "MD5Password";
        case 6: return "SCMCredential";
        case 7: return "GSS";
        case 8: return "GSSContinue";
        case 9: return "SSPI";
        case 10: return "SASL";
        case 11: return "SASLContinue";
        case 12: return "SASLFinal";
        default: return "Unknown";
    }
}

// Length of the startup-style packet at `p` (first byte is 0 for any length below 16 MB, a typed message starts with a letter).
bool startupLength(const uint8_t *p, size_t n, uint32_t &len) {
    if (n < 4) return false;
    len = (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | p[3];
    return true;
}

bool fromServerSide(const Context &ctx) {
    const auto &p = ctx.pack;
    if (p.src_port == 5432) return true;
    if (p.dst_port == 5432) return false;
    return ctx.sessions && ctx.sessions->isServerEndpoint(p.source, p.src_port);
}

// Error / Notice fields: a series of (byte code, string), ended by a zero byte
void errorFields(ByteReader r, std::string &severity, std::string &sqlstate, std::string &message) {
    while (r.remaining() > 0) {
        const uint8_t code = r.u8();
        if (code == 0) break;
        const std::string v = r.stringZ();
        if (code == 'S' || (code == 'V' && severity.empty())) severity = v;
        else if (code == 'C') sqlstate = v;
        else if (code == 'M') message = v;
    }
}


// ---- values (the caps keep Info, the tree and the stored state bounded) -------------------------------------------------------
// A value shows at most kValueChars characters (then "..." and its length), a message at most kTreeValues values in the tree and
// kInfoValues in Info (the rest is counted), and app_text keeps the first kFilterValues of a DataRow.
constexpr size_t kValueChars = 64, kTreeValues = 32, kInfoValues = 4, kFilterValues = 8, kMaxCells = 256, kCopyPreview = 64;

const char *typeLabel(uint32_t oid) {
    switch (oid) {
        case 16: return "bool";
        case 17: return "bytea";
        case 18: return "char";
        case 19: return "name";
        case 20: return "int8";
        case 21: return "int2";
        case 23: return "int4";
        case 25: return "text";
        case 26: return "oid";
        case 114: return "json";
        case 142: return "xml";
        case 700: return "float4";
        case 701: return "float8";
        case 1042: return "bpchar";
        case 1043: return "varchar";
        case 1082: return "date";
        case 1083: return "time";
        case 1114: return "timestamp";
        case 1184: return "timestamptz";
        case 1700: return "numeric";
        case 2950: return "uuid";
        case 3802: return "jsonb";
        default: return nullptr;
    }
}

std::string typeText(uint32_t oid) {
    if (oid == 0) return "unspecified";
    const char *n = typeLabel(oid);
    return n ? std::string(n) : "oid " + std::to_string(oid);
}

std::string withLength(std::string shown, size_t n) { return n > kValueChars ? shown + " (" + std::to_string(n) + " bytes)" : shown; }

std::string textValue(const uint8_t *v, size_t n) { return withLength(printableText(v, n, kValueChars), n); }

std::string hexValue(const uint8_t *v, size_t n) {
    static const char digits[] = "0123456789abcdef";
    std::string out = "\\x";
    for (size_t i = 0; i < n && i < kValueChars / 2; ++i) { out += digits[v[i] >> 4]; out += digits[v[i] & 15]; }
    if (n > kValueChars / 2) out += "...";
    return withLength(out, n * 2);
}

uint64_t bigEndian(const uint8_t *v, size_t n) {
    uint64_t r = 0;
    for (size_t i = 0; i < n; ++i) r = (r << 8) | v[i];
    return r;
}

// shortest %g form that reads back as the same number
std::string floatText(double d, bool single) {
    if (std::isnan(d)) return "NaN";
    if (std::isinf(d)) return d < 0 ? "-Infinity" : "Infinity";
    char buf[40];
    for (int precision = 1; precision <= 17; ++precision) {
        std::snprintf(buf, sizeof buf, "%.*g", precision, d);
        const double back = std::strtod(buf, nullptr);
        if (single ? static_cast<float>(back) == static_cast<float>(d) : back == d) break;
    }
    return buf;
}

// days since 1970-01-01 -> civil date (proleptic Gregorian)
void civilDate(int64_t z, int64_t &year, unsigned &month, unsigned &day) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    day = doy - (153 * mp + 2) / 5 + 1;
    month = mp < 10 ? mp + 3 : mp - 9;
    year = static_cast<int64_t>(yoe) + era * 400 + (month <= 2);
}

std::string two(unsigned v) { char b[8]; std::snprintf(b, sizeof b, "%02u", v); return b; }

std::string dateText(int64_t daysSince2000) {
    int64_t y; unsigned m, d;
    civilDate(daysSince2000 + 10957, y, m, d);   // 2000-01-01 is day 10957 after 1970-01-01
    char b[48];
    std::snprintf(b, sizeof b, "%04lld-%02u-%02u", static_cast<long long>(y), m, d);
    return b;
}

std::string timeText(int64_t micros) {
    std::string out = two(static_cast<unsigned>(micros / 3600000000LL)) + ":" + two(static_cast<unsigned>(micros / 60000000LL % 60)) + ":" + two(static_cast<unsigned>(micros / 1000000LL % 60));
    if (micros % 1000000) { char b[16]; std::snprintf(b, sizeof b, ".%06u", static_cast<unsigned>(micros % 1000000)); std::string f = b; while (f.back() == '0') f.pop_back(); out += f; }
    return out;
}

// numeric, binary: Int16 digits, Int16 weight, Int16 sign (0 +, 0x4000 -, 0xC000 NaN), Int16 dscale, then base 10000 digits
std::string numericText(const uint8_t *v, size_t n) {
    if (n < 8) return hexValue(v, n);
    const unsigned ndigits = static_cast<unsigned>(bigEndian(v, 2));
    const int weight = static_cast<int16_t>(bigEndian(v + 2, 2));
    const unsigned sign = static_cast<unsigned>(bigEndian(v + 4, 2)), dscale = static_cast<unsigned>(bigEndian(v + 6, 2));
    if (sign == 0xC000) return "NaN";
    if (n < 8 + static_cast<size_t>(ndigits) * 2 || (sign != 0 && sign != 0x4000) || dscale > 1000) return hexValue(v, n);
    const auto digit = [&](int i) { return i >= 0 && i < static_cast<int>(ndigits) ? static_cast<unsigned>(bigEndian(v + 8 + i * 2, 2)) : 0u; };
    std::string whole, fraction;
    char b[8];
    for (int i = 0; i <= weight && whole.size() < 200; ++i) { std::snprintf(b, sizeof b, whole.empty() ? "%u" : "%04u", digit(i)); whole += b; }
    if (whole.empty()) whole = "0";
    for (int i = weight + 1; fraction.size() < dscale + 4; ++i) { std::snprintf(b, sizeof b, "%04u", digit(i)); fraction += b; if (i - weight > 260) break; }
    fraction.resize(std::min<size_t>(fraction.size(), dscale));
    return std::string(sign == 0x4000 ? "-" : "") + whole + (dscale ? "." + fraction : "");
}

std::string binaryValue(const uint8_t *v, size_t n, uint32_t oid) {
    switch (oid) {
        case 16: if (n == 1) return v[0] ? "true" : "false"; break;
        case 21: if (n == 2) return std::to_string(static_cast<int16_t>(bigEndian(v, 2))); break;
        case 23: if (n == 4) return std::to_string(static_cast<int32_t>(bigEndian(v, 4))); break;
        case 26: if (n == 4) return std::to_string(bigEndian(v, 4)); break;
        case 20: if (n == 8) return std::to_string(static_cast<int64_t>(bigEndian(v, 8))); break;
        case 700: if (n == 4) { const uint32_t u = static_cast<uint32_t>(bigEndian(v, 4)); float f; std::memcpy(&f, &u, 4); return floatText(f, true); } break;
        case 701: if (n == 8) { const uint64_t u = bigEndian(v, 8); double d; std::memcpy(&d, &u, 8); return floatText(d, false); } break;
        case 18: case 19: case 25: case 114: case 142: case 1042: case 1043: return textValue(v, n);
        case 3802: if (n >= 1 && v[0] == 1) return textValue(v + 1, n - 1); break;   // jsonb: version byte 1, then the text
        case 17: return hexValue(v, n);
        case 2950:
            if (n == 16) {
                static const char digits[] = "0123456789abcdef";
                std::string out;
                for (size_t i = 0; i < 16; ++i) { if (i == 4 || i == 6 || i == 8 || i == 10) out += '-'; out += digits[v[i] >> 4]; out += digits[v[i] & 15]; }
                return out;
            }
            break;
        case 1082:
            if (n == 4) {
                const int32_t d = static_cast<int32_t>(bigEndian(v, 4));
                return d == INT32_MAX ? "infinity" : d == INT32_MIN ? "-infinity" : dateText(d);
            }
            break;
        case 1083: if (n == 8) return timeText(static_cast<int64_t>(bigEndian(v, 8))); break;
        case 1114: case 1184:
            if (n == 8) {
                const int64_t us = static_cast<int64_t>(bigEndian(v, 8));
                if (us == INT64_MAX) return "infinity";
                if (us == INT64_MIN) return "-infinity";
                int64_t days = us / 86400000000LL, rest = us % 86400000000LL;
                if (rest < 0) { rest += 86400000000LL; --days; }
                return dateText(days) + " " + timeText(rest) + (oid == 1184 ? "+00" : "");
            }
            break;
        case 1700: return numericText(v, n);
        default: break;
    }
    return hexValue(v, n);
}

// One value as the wire carries it: text format is text whatever the type, binary format is told by the type OID.
std::string valueText(const uint8_t *v, size_t n, uint32_t oid, int format) { return format == 0 ? textValue(v, n) : binaryValue(v, n, oid); }

// The values of a DataRow / Bind: Int32 length (-1 = NULL) and the bytes, as far as they are captured.
struct Cell {
    bool null = false;
    size_t offset = 0, length = 0;   // inside the message body
};

size_t readCells(ByteReader &b, size_t count, std::vector<Cell> &cells) {
    size_t seen = 0;
    while (seen < count && b.remaining() >= 4) {
        const size_t at = b.offset();
        const int32_t len = b.i32_be();
        Cell c;
        if (len == -1) {
            c.null = true;
            c.offset = at + 4;
        } else if (len < 0) {
            break;
        } else {
            c.offset = at + 4;
            c.length = std::min<size_t>(static_cast<uint32_t>(len), b.remaining());
            b.skip(static_cast<uint32_t>(len) <= b.remaining() ? static_cast<uint32_t>(len) : b.remaining());
        }
        if (cells.size() < kMaxCells) cells.push_back(c);
        ++seen;
    }
    return seen;
}

std::string joinFirst(const std::vector<std::string> &v, size_t n) {
    std::string out;
    for (size_t i = 0; i < v.size() && i < n; ++i) out += (i ? ", " : "") + v[i];
    if (v.size() > n) out += ", ...";
    return out;
}

// CopyData: text format shows the first characters with the line ends spelled out, binary format spots the signature header
std::string copyPreview(const uint8_t *v, size_t n, int format) {
    static const char signature[] = "PGCOPY\n\377\r\n\0";
    if (format == 1 && n >= 11 && std::memcmp(v, signature, 11) == 0) return "binary COPY header (signature PGCOPY)";
    if (format == 1) return hexValue(v, std::min<size_t>(n, kCopyPreview / 2)) + (n > kCopyPreview / 2 ? " (" + std::to_string(n) + " bytes)" : "");
    std::string out;
    for (size_t i = 0; i < n && out.size() < kCopyPreview; ++i) {
        if (v[i] == '\n') out += "\\n";
        else if (v[i] == '\t') out += "\\t";
        else if (v[i] == '\r') out += "\\r";
        else out += (v[i] >= 32 && v[i] < 127) ? static_cast<char>(v[i]) : '?';
    }
    if (n > kCopyPreview) out += "... (" + std::to_string(n) + " bytes)";
    return out;
}

} // namespace

StreamFrame framePostgreSql(const char *data, size_t length) {
    if (length == 0) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const auto *p = reinterpret_cast<const uint8_t *>(data);
    // the one byte answer to an SSLRequest / GSSENCRequest ('S' goes on with TLS, 'N' stays plain); a typed message with
    // that letter is at least five bytes and arrives in one send, so a lone letter is the answer
    if (length == 1 && (p[0] == 'S' || p[0] == 'N')) return StreamFrame{StreamFrame::Kind::Complete, 1};

    if (p[0] == 0) { // StartupMessage / SSLRequest / GSSENCRequest / CancelRequest: Int32 length, Int32 code
        uint32_t len = 0;
        if (!startupLength(p, length, len)) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
        if (len < 8 || len > kMaxStartup) return StreamFrame{StreamFrame::Kind::Reject, 0};
        return StreamFrame{length < len ? StreamFrame::Kind::NeedMore : StreamFrame::Kind::Complete, len};
    }

    if (!knownType(static_cast<char>(p[0]))) return StreamFrame{StreamFrame::Kind::Reject, 0};
    if (length < 5) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const uint32_t msgLen = (static_cast<uint32_t>(p[1]) << 24) | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 8) | p[4];
    if (msgLen < 4 || msgLen > kMaxMessage) return StreamFrame{StreamFrame::Kind::Reject, 0};
    const size_t total = 1 + static_cast<size_t>(msgLen);
    return StreamFrame{length < total ? StreamFrame::Kind::NeedMore : StreamFrame::Kind::Complete, total};
}

void dissectPostgreSql(Context &ctx, const char *data, size_t length) {
    if (!data || length == 0) return;
    auto &pack = ctx.pack;
    pack.protocol = "PGSQL";
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    const size_t o = ctx.offsetOf(data);
    const bool server = fromServerSide(ctx);

    // facts for the filter: app_type 1 startup, 2 SSLRequest, 3 CancelRequest, 4 GSSENCRequest, 5 answer to those, 6 typed message;
    // app_flags = the type letter of a typed message; app_text = query; app_text2 = user (startup) or SQLSTATE (error)
    std::string info;
    std::vector<std::pair<std::string, std::pair<size_t, size_t>>> items;   // detail-tree children: text, offset, length
    size_t layerLength = length;
    std::string layerName;

    auto markSwitch = [&](size_t end) { // the server agreed to TLS: both directions carry TLS from here (load pass; Replay reads)
        if (ctx.sessions && ctx.tcpStreamSeq >= 0 && pack.tcp_relative_ack >= 0) {
            ctx.sessions->markTlsUpgrade(pack.source, pack.src_port, pack.destination, pack.dst_port, static_cast<uint32_t>(ctx.tcpStreamSeq) + static_cast<uint32_t>(end));
            ctx.sessions->markTlsUpgrade(pack.destination, pack.dst_port, pack.source, pack.src_port, static_cast<uint32_t>(pack.tcp_relative_ack));
        }
    };

    if (length == 1 && (bytes[0] == 'S' || bytes[0] == 'N')) {   // answer to an SSLRequest / GSSENCRequest
        pack.app_type = 5;
        if (bytes[0] == 'S') {
            info = "SSLRequest answer: supported (S) - TLS follows";
            markSwitch(1);
        } else {
            info = "SSLRequest answer: not supported (N)";
        }
        layerName = "PostgreSQL (SSL answer)";
        items.push_back({std::string("Answer: ") + (bytes[0] == 'S' ? "S (SSL supported)" : "N (SSL not supported)"), {o, 1}});
    } else if (bytes[0] == 0) { // startup-style packet
        uint32_t len = 0, code = 0;
        ByteReader r(bytes, length);
        len = r.u32_be();
        if (length >= 8) code = r.u32_be();
        layerLength = std::min<size_t>(len, length);
        if (length < 8) {
            info = "Startup packet [cut]";
            layerName = "PostgreSQL (startup)";
        } else if (code == kSslRequest || code == kGssEncRequest) {
            const bool ssl = code == kSslRequest;
            pack.app_type = ssl ? 2 : 4;
            info = ssl ? "SSLRequest" : "GSSENCRequest";
            layerName = std::string("PostgreSQL (") + info + ")";
            items.push_back({"Length: " + std::to_string(len), {o, 4}});
            items.push_back({std::string("Code: ") + info + " (" + std::to_string(code) + ")", {o + 4, 4}});
            if (ctx.sessions) ctx.sessions->markServerEndpoint(pack.destination, pack.dst_port);
        } else if (code == kCancelRequest) {
            pack.app_type = 3;
            uint32_t pid = length >= 12 ? be32(data + 8) : 0;
            info = "CancelRequest (pid=" + std::to_string(pid) + ")";
            layerName = "PostgreSQL (CancelRequest)";
            items.push_back({"Code: CancelRequest (80877102)", {o + 4, 4}});
            if (length >= 12) items.push_back({"Process ID: " + std::to_string(pid), {o + 8, 4}});
            if (ctx.sessions) ctx.sessions->markServerEndpoint(pack.destination, pack.dst_port);
        } else {
            // StartupMessage: Int32 protocol version (major << 16 | minor), then name/value pairs, ended by a zero byte
            pack.app_type = 1;
            const uint32_t major = code >> 16, minor = code & 0xffff;
            std::string user, db;
            std::vector<std::pair<std::string, std::string>> params;
            ByteReader pr(bytes + 8, std::min<size_t>(len, length) > 8 ? std::min<size_t>(len, length) - 8 : 0);
            while (pr.remaining() > 1 && params.size() < 64) {
                const std::string k = pr.stringZ(), v = pr.stringZ();
                if (k.empty()) break;
                if (k == "user") user = v;
                else if (k == "database") db = v;
                params.push_back({k, v});
            }
            info = "StartupMessage (" + std::to_string(major) + "." + std::to_string(minor) + ")";
            if (!user.empty()) info += " user=" + printableText(user.data(), user.size(), 63);
            if (!db.empty()) info += " db=" + printableText(db.data(), db.size(), 63);
            pack.app_text2 = printableText(user.data(), user.size(), 63);
            layerName = "PostgreSQL (StartupMessage)";
            // a new connection: the statements and columns of an earlier one on the same endpoints are forgotten (load pass)
            if (ctx.mode != ParseMode::Replay && ctx.sessions && !ctx.sessions->isFrozen() && length >= len) {
                const std::string conn = dbConnectionKey(pack.source, pack.src_port, pack.destination, pack.dst_port);
                ctx.sessions->dbObserve([&](DbTable &t, size_t max, bool &lost) { t.pgStart(conn, max, lost); });
            }
            items.push_back({"Length: " + std::to_string(len), {o, 4}});
            items.push_back({"Protocol Version: " + std::to_string(major) + "." + std::to_string(minor), {o + 4, 4}});
            for (const auto &kv: params) items.push_back({"Parameter: " + printableText(kv.first.data(), kv.first.size(), 63) + " = " + printableText(kv.second.data(), kv.second.size(), 100), {o + 8, 0}});
            if (ctx.sessions) ctx.sessions->markServerEndpoint(pack.destination, pack.dst_port);
        }
    } else { // typed message
        const char type = static_cast<char>(bytes[0]);
        pack.app_type = 6;
        pack.app_flags = bytes[0];
        if (server) pack.app_code = 1;   // the message comes from the server
        const char *name = server ? backendName(type) : frontendName(type);
        if (!name) name = server ? frontendName(type) : backendName(type);
        const std::string typeName = name ? name : std::string("Msg '") + (type >= 32 && type < 127 ? type : '?') + "'";
        info = typeName;
        uint32_t msgLen = 0;
        bool haveLen = length >= 5;
        if (haveLen) msgLen = be32(data + 1);
        const size_t total = haveLen ? 1 + static_cast<size_t>(msgLen) : length;
        layerLength = std::min(total, length);
        layerName = "PostgreSQL (" + typeName + ")";
        items.push_back({std::string("Type: ") + (type >= 32 && type < 127 ? type : '?') + " (" + typeName + ")", {o, 1}});
        if (haveLen) items.push_back({"Length: " + std::to_string(msgLen), {o + 1, 4}});
        if (haveLen && msgLen < 4) {
            info += " [Malformed length]";
        } else if (haveLen) {
            // the body, as far as it was captured
            const size_t bodyEnd = std::min(total, length);
            ByteReader b(bytes + 5, bodyEnd > 5 ? bodyEnd - 5 : 0);
            const uint8_t *body = bytes + 5;
            const size_t bo = o + 5;
            // session state: decided while the capture loads (only for a message that was captured whole), Replay reads it
            const bool whole = length >= total;
            SessionTables *sessions = ctx.sessions;
            const bool loadPass = ctx.mode != ParseMode::Replay && sessions && !sessions->isFrozen() && whole;
            const uint32_t number = static_cast<uint32_t>(pack.number);
            const int32_t seq = static_cast<int32_t>(ctx.tcpStreamSeq);
            const std::string conn = sessions ? dbConnectionKey(pack.source, pack.src_port, pack.destination, pack.dst_port) : std::string();
            const auto observe = [&](auto &&f) { return sessions->dbObserve(f); };
            const auto nameText = [](const std::string &n) { return n.empty() ? std::string("<unnamed>") : printableText(n.data(), n.size(), 63); };
            const auto queryAside = [](const DbStatement *st, size_t cap) { return st && st->query && !st->query->empty() ? " (" + printableText(st->query->data(), st->query->size(), cap) + ")" : std::string(); };
            const auto setQuery = [&](const DbStatement *st) { if (st && st->query) pack.app_text = printableText(st->query->data(), st->query->size(), 512); };
            if (loadPass && (type == 'c' || (server && (type == 'C' || type == 'E' || type == 't' || type == 'n')))) {
                observe([&](DbTable &t, size_t max, bool &lost) { t.pgServerMessage(conn, number, seq, type, max, lost); });
            }
            if (server) {
                if (type == 'R' && b.remaining() >= 4) {
                    const uint32_t a = b.u32_be();
                    info = std::string("Authentication: ") + authTypeName(a);
                    items.push_back({std::string("Authentication Type: ") + authTypeName(a) + " (" + std::to_string(a) + ")", {bo, 4}});
                    if (a == 5 && b.remaining() >= 4) items.push_back({"Salt: " + hexString(be32(data + 9), 8), {bo + 4, 4}});
                    if (a == 10) {
                        std::string mechs;
                        while (b.remaining() > 1) { const std::string m = b.stringZ(); if (m.empty()) break; mechs += (mechs.empty() ? "" : ", ") + printableText(m.data(), m.size(), 40); }
                        if (!mechs.empty()) { info += " (" + mechs + ")"; items.push_back({"SASL Mechanisms: " + mechs, {bo + 4, bodyEnd - 5 - 4}}); }
                    }
                } else if (type == 'K' && b.remaining() >= 8) {
                    const uint32_t pid = b.u32_be();
                    info = "BackendKeyData (pid=" + std::to_string(pid) + ")";
                    items.push_back({"Process ID: " + std::to_string(pid), {bo, 4}});
                } else if (type == 'S') {
                    const std::string k = b.stringZ(), v = b.stringZ();
                    info = "ParameterStatus: " + printableText(k.data(), k.size(), 63) + "=" + printableText(v.data(), v.size(), 100);
                    items.push_back({"Parameter: " + printableText(k.data(), k.size(), 63) + " = " + printableText(v.data(), v.size(), 100), {bo, bodyEnd - 5}});
                } else if (type == 'Z' && b.remaining() >= 1) {
                    const char st = static_cast<char>(b.u8());
                    const char *sn = st == 'I' ? "idle" : st == 'T' ? "in a transaction" : st == 'E' ? "in a failed transaction" : "unknown";
                    info = std::string("ReadyForQuery (") + sn + ")";
                    items.push_back({std::string("Transaction Status: ") + (st >= 32 && st < 127 ? st : '?') + " (" + sn + ")", {bo, 1}});
                } else if (type == 'C') {
                    const std::string tag = b.stringZ();
                    info = "CommandComplete: " + printableText(tag.data(), tag.size(), 100);
                    items.push_back({"Command Tag: " + printableText(tag.data(), tag.size(), 100), {bo, bodyEnd - 5}});
                } else if (type == 'T' && b.remaining() >= 2) {
                    // RowDescription: Int16 columns; per column name, table OID (4), column number (2), type OID (4), size (2), modifier (4), format (2)
                    const uint16_t n = b.u16_be();
                    items.push_back({"Columns: " + std::to_string(n), {bo, 2}});
                    pack.app_stream = n;
                    std::vector<PgColumn> columns;
                    std::vector<std::string> names;
                    for (uint16_t i = 0; i < n && b.remaining() > 18; ++i) {
                        const size_t at = bo + b.offset();
                        PgColumn col;
                        col.name = b.stringZ();
                        if (b.remaining() < 18) break;
                        b.skip(6);                        // table OID, column number
                        col.typeOid = b.u32_be();
                        b.skip(6);                        // size, modifier
                        col.format = b.i16_be();
                        const std::string shown = printableText(col.name.data(), col.name.size(), 63);
                        if (i < kTreeValues) items.push_back({"Column: " + shown + " (type " + typeText(col.typeOid) + ", " + (col.format == 1 ? "binary" : "text") + ")", {at, col.name.size() + 1 + 18}});
                        names.push_back(shown);
                        if (columns.size() < DbTable::kMaxColumns) columns.push_back(std::move(col));
                    }
                    info = "RowDescription (" + std::to_string(n) + " columns)" + (names.empty() ? "" : ": " + joinFirst(names, kInfoValues));
                    if (loadPass) observe([&](DbTable &t, size_t max, bool &lost) { return t.pgRowDescription(conn, number, seq, columns, n, max, lost); });
                } else if (type == 'D' && b.remaining() >= 2) {
                    // DataRow: Int16 columns, per column Int32 length (-1 NULL) and the bytes; typed by the RowDescription in effect
                    const uint16_t n = b.u16_be();
                    items.push_back({"Columns: " + std::to_string(n), {bo, 2}});
                    pack.app_stream = n;
                    std::vector<Cell> cells;
                    const size_t seen = readCells(b, n, cells);
                    const DbTable::PgRows rows = sessions ? sessions->dbTable().pgRows(conn, number, seq) : DbTable::PgRows();
                    std::vector<std::string> shown;
                    for (size_t i = 0; i < cells.size(); ++i) {
                        const PgColumn *col = rows.columns && i < rows.columns->pg.size() ? &rows.columns->pg[i] : nullptr;
                        const int format = rows.columns ? rows.format(i) : 0;
                        std::string v = cells[i].null ? "NULL" : valueText(body + cells[i].offset, cells[i].length, col ? col->typeOid : 0, format);
                        const std::string label = col ? printableText(col->name.data(), col->name.size(), 40) : "Column " + std::to_string(i + 1);
                        if (i < kTreeValues) items.push_back({label + (col && col->typeOid ? " (" + typeText(col->typeOid) + ")" : std::string()) + ": " + v,
                                                              {bo + cells[i].offset - 4, (cells[i].null ? 0 : cells[i].length) + 4}});
                        shown.push_back(col && !col->name.empty() ? label + "=" + v : v);
                        if (i < kFilterValues) pack.app_text += (i ? ", " : "") + v;
                    }
                    if (seen > kTreeValues) items.push_back({std::to_string(seen - kTreeValues) + " more columns not shown", {bo, 0}});
                    info = "DataRow (" + std::to_string(n) + " columns)" + (shown.empty() ? "" : ": " + joinFirst(shown, kInfoValues));
                    if (seen < n) info += " [cut]";
                } else if (type == 't' && b.remaining() >= 2) {
                    const uint16_t n = b.u16_be();
                    info = "ParameterDescription (" + std::to_string(n) + " parameters)";
                    items.push_back({"Parameters: " + std::to_string(n), {bo, 2}});
                    pack.app_stream = n;
                    for (uint16_t i = 0; i < n && b.remaining() >= 4; ++i) {
                        const size_t at = bo + b.offset();
                        const uint32_t oid = b.u32_be();
                        if (i < kTreeValues) items.push_back({"Parameter $" + std::to_string(i + 1) + ": " + typeText(oid), {at, 4}});
                    }
                } else if ((type == 'G' || type == 'H' || type == 'W') && b.remaining() >= 3) {
                    // Copy{In,Out,Both}Response: Int8 overall format (0 text, 1 binary), Int16 columns, Int16 format per column
                    const int format = b.u8();
                    const uint16_t n = b.u16_be();
                    info = typeName + " (" + (format == 1 ? "binary" : "text") + ", " + std::to_string(n) + " columns)";
                    items.push_back({std::string("Format: ") + (format == 1 ? "binary (1)" : "text (0)"), {bo, 1}});
                    items.push_back({"Columns: " + std::to_string(n), {bo + 1, 2}});
                    pack.app_stream = n;
                    if (loadPass) observe([&](DbTable &t, size_t max, bool &lost) { return t.pgCopyResponse(conn, number, seq, format, n, max, lost); });
                } else if ((type == 'E' || type == 'N') && b.remaining() > 0) {
                    std::string sev, state, msg;
                    errorFields(b, sev, state, msg);
                    info = typeName + ": " + printableText(sev.data(), sev.size(), 20) + " " + printableText(state.data(), state.size(), 5) + " " + printableText(msg.data(), msg.size(), 120);
                    pack.app_text2 = printableText(state.data(), state.size(), 5);
                    items.push_back({"Severity: " + printableText(sev.data(), sev.size(), 20), {bo, 0}});
                    items.push_back({"SQLSTATE: " + printableText(state.data(), state.size(), 5), {bo, 0}});
                    items.push_back({"Message: " + printableText(msg.data(), msg.size(), 200), {bo, bodyEnd - 5}});
                } else if (type == 'A' && b.remaining() >= 4) {
                    const uint32_t pid = b.u32_be();
                    const std::string ch = b.stringZ();
                    info = "NotificationResponse (pid=" + std::to_string(pid) + ", channel=" + printableText(ch.data(), ch.size(), 63) + ")";
                }
            } else {
                if (type == 'Q') {
                    const std::string q = b.stringZ();
                    info = "Query: " + printableText(q.data(), q.size(), 200);
                    pack.app_text = printableText(q.data(), q.size(), 512);
                    items.push_back({"Query: " + pack.app_text, {bo, bodyEnd - 5}});
                } else if (type == 'P') {
                    // Parse: statement name, query, Int16 parameter types, Int32 type OID each (0 = unspecified)
                    const std::string stmt = b.stringZ(), q = b.stringZ();
                    std::vector<uint32_t> oids;
                    if (b.remaining() >= 2) {
                        const uint16_t n = b.u16_be();
                        for (uint16_t i = 0; i < n && b.remaining() >= 4; ++i) oids.push_back(b.u32_be());
                    }
                    info = "Parse: " + printableText(q.data(), q.size(), 200) + (stmt.empty() ? std::string() : " (statement " + nameText(stmt) + ")");
                    pack.app_text = printableText(q.data(), q.size(), 512);
                    pack.app_text2 = printableText(stmt.data(), stmt.size(), 63);
                    items.push_back({"Statement: " + nameText(stmt), {bo, stmt.size() + 1}});
                    items.push_back({"Query: " + pack.app_text, {bo + stmt.size() + 1, q.size() + 1}});
                    for (size_t i = 0; i < oids.size() && i < kTreeValues; ++i) items.push_back({"Parameter $" + std::to_string(i + 1) + " type: " + typeText(oids[i]), {bo + stmt.size() + q.size() + 4 + i * 4, 4}});
                    if (loadPass) observe([&](DbTable &t, size_t max, bool &lost) { return t.pgParse(conn, number, seq, stmt, q, oids, max, lost); });
                } else if (type == 'p') {
                    info = "PasswordMessage (the password is not shown)";
                } else if (type == 'B' && b.remaining() > 0) {
                    // Bind: portal, statement, Int16 parameter format codes (0 = all text, 1 = all the same, n = one each), Int16 parameters
                    // (Int32 length, -1 NULL, bytes), Int16 result format codes
                    const std::string portal = b.stringZ(), stmt = b.stringZ();
                    items.push_back({"Portal: " + nameText(portal), {bo, portal.size() + 1}});
                    items.push_back({"Statement: " + nameText(stmt), {bo + portal.size() + 1, stmt.size() + 1}});
                    std::vector<int16_t> paramFormats, resultFormats;
                    std::vector<Cell> cells;
                    uint16_t nparams = 0;
                    size_t seen = 0;
                    if (b.remaining() >= 2) {
                        const uint16_t nf = b.u16_be();
                        for (uint16_t i = 0; i < nf && b.remaining() >= 2; ++i) { const int16_t f = b.i16_be(); if (paramFormats.size() < kMaxCells) paramFormats.push_back(f); }
                        if (b.remaining() >= 2) { nparams = b.u16_be(); seen = readCells(b, nparams, cells); }
                        if (seen == nparams && b.remaining() >= 2) {
                            const uint16_t nr = b.u16_be();
                            for (uint16_t i = 0; i < nr && b.remaining() >= 2; ++i) { const int16_t f = b.i16_be(); if (resultFormats.size() < kMaxCells) resultFormats.push_back(f); }
                        }
                    }
                    pack.app_stream = nparams;
                    pack.app_text2 = printableText(stmt.data(), stmt.size(), 63);
                    const DbStatement *st = nullptr;
                    if (loadPass) st = observe([&](DbTable &t, size_t max, bool &lost) { return t.pgBind(conn, number, seq, portal, stmt, resultFormats, max, lost); });
                    else if (sessions) st = sessions->dbTable().pgNote(number, seq);
                    setQuery(st);
                    std::vector<std::string> shown;
                    for (size_t i = 0; i < cells.size(); ++i) {
                        const int format = paramFormats.empty() ? 0 : paramFormats.size() == 1 ? paramFormats[0] : i < paramFormats.size() ? paramFormats[i] : 0;
                        const uint32_t oid = st && i < st->paramOids.size() ? st->paramOids[i] : 0;
                        const std::string v = cells[i].null ? "NULL" : valueText(body + cells[i].offset, cells[i].length, oid, format);
                        if (i < kTreeValues) items.push_back({"Parameter $" + std::to_string(i + 1) + " (" + typeText(oid) + ", " + (format == 1 ? "binary" : "text") + "): " + v,
                                                              {bo + cells[i].offset - 4, (cells[i].null ? 0 : cells[i].length) + 4}});
                        shown.push_back(v);
                    }
                    if (seen > kTreeValues) items.push_back({std::to_string(seen - kTreeValues) + " more parameters not shown", {bo, 0}});
                    info = "Bind: statement=" + nameText(stmt) + (nparams ? ", " + std::to_string(nparams) + " parameters: " + joinFirst(shown, kInfoValues) : std::string());
                    if (!st && !stmt.empty() && sessions) items.push_back({"[statement not seen in this capture]", {bo, 0}});
                    if (!resultFormats.empty()) items.push_back({"Result format codes: " + std::to_string(resultFormats.size()), {bo, 0}});
                } else if ((type == 'D' || type == 'C') && b.remaining() >= 1) {
                    // Describe / Close: 'S' statement or 'P' portal, then its name
                    const char kind = static_cast<char>(b.u8());
                    const std::string n = b.stringZ();
                    const DbStatement *st = nullptr;
                    if (loadPass) st = observe([&](DbTable &t, size_t max, bool &lost) { return t.pgDescribeClose(conn, number, seq, kind == 'S', n, type == 'C', max, lost); });
                    else if (sessions) st = sessions->dbTable().pgNote(number, seq);
                    setQuery(st);
                    if (kind == 'S') pack.app_text2 = printableText(n.data(), n.size(), 63);
                    info = typeName + ": " + (kind == 'S' ? "statement " : "portal ") + nameText(n) + queryAside(st, 80);
                    items.push_back({std::string(kind == 'S' ? "Statement: " : "Portal: ") + nameText(n), {bo + 1, n.size() + 1}});
                } else if (type == 'E') {
                    const std::string portal = b.stringZ();
                    const DbStatement *st = nullptr;
                    if (loadPass) st = observe([&](DbTable &t, size_t max, bool &lost) { return t.pgExecute(conn, number, seq, portal, max, lost); });
                    else if (sessions) st = sessions->dbTable().pgNote(number, seq);
                    setQuery(st);
                    info = "Execute: portal " + nameText(portal) + queryAside(st, 80);
                    items.push_back({"Portal: " + nameText(portal), {bo, portal.size() + 1}});
                    if (b.remaining() >= 4) items.push_back({"Max Rows: " + std::to_string(b.u32_be()), {bo + portal.size() + 1, 4}});
                }
            }
            if (type == 'd') {   // CopyData, either direction: the bytes are rows of the COPY in effect
                const DbTable::PgRows rows = sessions ? sessions->dbTable().pgRows(conn, number, seq) : DbTable::PgRows();
                const int format = rows.columns && rows.columns->copyFormat >= 0 ? rows.columns->copyFormat : 0;
                const std::string preview = copyPreview(body, bodyEnd > 5 ? bodyEnd - 5 : 0, format);
                info = "CopyData (" + std::to_string(msgLen - 4) + " bytes): " + preview;
                items.push_back({"Data: " + preview, {bo, bodyEnd > 5 ? bodyEnd - 5 : 0}});
                pack.app_stream = static_cast<uint32_t>(msgLen - 4);
            } else if (type == 'f' && !server) {
                const std::string m = b.stringZ();
                info = "CopyFail: " + printableText(m.data(), m.size(), 120);
            }
        }
    }

    pack.info = info;
    if (ctx.wantFields()) {
        Field &l = ctx.addLayer(layerName.empty() ? "PostgreSQL" : layerName, o, layerLength);
        for (const auto &it: items) { // a cut message: only what lies inside the captured bytes
            const size_t rel = it.second.first - o;
            if (rel <= length) l.add(it.first, it.second.first, std::min(it.second.second, length - rel));
        }
    }
    if (bytes[0] != 0 && !(length == 1) && length >= 5 && be32(data + 1) < 4) ctx.markMalformed("PostgreSQL message length below 4");
}

} // namespace dissect
