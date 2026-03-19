// PostgreSQL frontend/backend protocol 3.0 (https://www.postgresql.org/docs/current/protocol-message-formats.html).
// A message is a 1 byte type and an Int32 length that counts itself but not the type. The startup packets (StartupMessage,
// SSLRequest, GSSENCRequest, CancelRequest) have no type byte: Int32 length, Int32 code. The server answers an SSLRequest /
// GSSENCRequest with one byte, 'S' (go on, TLS follows) or 'N'.
#include "postgres.h"

#include <string>
#include <vector>

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
            items.push_back({"Length: " + std::to_string(len), {o, 4}});
            items.push_back({"Protocol Version: " + std::to_string(major) + "." + std::to_string(minor), {o + 4, 4}});
            for (const auto &kv: params) items.push_back({"Parameter: " + printableText(kv.first.data(), kv.first.size(), 63) + " = " + printableText(kv.second.data(), kv.second.size(), 100), {o + 8, 0}});
            if (ctx.sessions) ctx.sessions->markServerEndpoint(pack.destination, pack.dst_port);
        }
    } else { // typed message
        const char type = static_cast<char>(bytes[0]);
        pack.app_type = 6;
        pack.app_flags = bytes[0];
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
            const size_t bo = o + 5;
            if (server) {
                if (type == 'R' && b.remaining() >= 4) {
                    const uint32_t a = b.u32_be();
                    info = std::string("Authentication: ") + authTypeName(a);
                    items.push_back({std::string("Authentication Type: ") + authTypeName(a) + " (" + std::to_string(a) + ")", {bo, 4}});
                    if (a == 5 && b.remaining() >= 4) items.push_back({"Salt: " + hexString(be32(data + 9), 8), {bo + 4, 4}});
                    if (a == 10) {
                        std::string mechs;
                        while (b.remaining() > 1) { const std::string m = b.stringZ(); if (m.empty()) break; mechs += (mechs.empty() ? "" : ", ") + printableText(m.data(), m.size(), 40); }
                        if (!mechs.empty()) { info += " (" + mechs + ")"; items.push_back({"SASL Mechanisms: " + mechs, {bo + 4, bodyEnd - bo - 4}}); }
                    }
                } else if (type == 'K' && b.remaining() >= 8) {
                    const uint32_t pid = b.u32_be();
                    info = "BackendKeyData (pid=" + std::to_string(pid) + ")";
                    items.push_back({"Process ID: " + std::to_string(pid), {bo, 4}});
                } else if (type == 'S') {
                    const std::string k = b.stringZ(), v = b.stringZ();
                    info = "ParameterStatus: " + printableText(k.data(), k.size(), 63) + "=" + printableText(v.data(), v.size(), 100);
                    items.push_back({"Parameter: " + printableText(k.data(), k.size(), 63) + " = " + printableText(v.data(), v.size(), 100), {bo, bodyEnd - bo}});
                } else if (type == 'Z' && b.remaining() >= 1) {
                    const char st = static_cast<char>(b.u8());
                    const char *sn = st == 'I' ? "idle" : st == 'T' ? "in a transaction" : st == 'E' ? "in a failed transaction" : "unknown";
                    info = std::string("ReadyForQuery (") + sn + ")";
                    items.push_back({std::string("Transaction Status: ") + (st >= 32 && st < 127 ? st : '?') + " (" + sn + ")", {bo, 1}});
                } else if (type == 'C') {
                    const std::string tag = b.stringZ();
                    info = "CommandComplete: " + printableText(tag.data(), tag.size(), 100);
                    items.push_back({"Command Tag: " + printableText(tag.data(), tag.size(), 100), {bo, bodyEnd - bo}});
                } else if (type == 'T' && b.remaining() >= 2) {
                    const uint16_t n = b.u16_be();
                    info = "RowDescription (" + std::to_string(n) + " columns)";
                    items.push_back({"Columns: " + std::to_string(n), {bo, 2}});
                    for (uint16_t i = 0; i < n && i < 16 && b.remaining() > 18; ++i) {
                        const size_t at = bo + b.offset();
                        const std::string col = b.stringZ();
                        items.push_back({"Column: " + printableText(col.data(), col.size(), 63), {at, col.size() + 1}});
                        if (!b.skip(18)) break;   // table oid, column number, type oid, size, modifier, format
                    }
                } else if (type == 'D' && b.remaining() >= 2) {
                    const uint16_t n = b.u16_be();
                    info = "DataRow (" + std::to_string(n) + " columns)";
                    items.push_back({"Columns: " + std::to_string(n), {bo, 2}});
                } else if ((type == 'E' || type == 'N') && b.remaining() > 0) {
                    std::string sev, state, msg;
                    errorFields(b, sev, state, msg);
                    info = typeName + ": " + printableText(sev.data(), sev.size(), 20) + " " + printableText(state.data(), state.size(), 5) + " " + printableText(msg.data(), msg.size(), 120);
                    pack.app_text2 = printableText(state.data(), state.size(), 5);
                    items.push_back({"Severity: " + printableText(sev.data(), sev.size(), 20), {bo, 0}});
                    items.push_back({"SQLSTATE: " + printableText(state.data(), state.size(), 5), {bo, 0}});
                    items.push_back({"Message: " + printableText(msg.data(), msg.size(), 200), {bo, bodyEnd - bo}});
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
                    items.push_back({"Query: " + pack.app_text, {bo, bodyEnd - bo}});
                } else if (type == 'P') {
                    const std::string stmt = b.stringZ(), q = b.stringZ();
                    info = "Parse: " + printableText(q.data(), q.size(), 200);
                    pack.app_text = printableText(q.data(), q.size(), 512);
                    items.push_back({"Statement: " + (stmt.empty() ? std::string("<unnamed>") : printableText(stmt.data(), stmt.size(), 63)), {bo, stmt.size() + 1}});
                    items.push_back({"Query: " + pack.app_text, {bo + stmt.size() + 1, q.size() + 1}});
                } else if (type == 'p') {
                    info = "PasswordMessage (the password is not shown)";
                } else if (type == 'B' && b.remaining() > 0) {
                    const std::string portal = b.stringZ(), stmt = b.stringZ();
                    info = "Bind: statement=" + (stmt.empty() ? std::string("<unnamed>") : printableText(stmt.data(), stmt.size(), 63));
                    items.push_back({"Portal: " + (portal.empty() ? std::string("<unnamed>") : printableText(portal.data(), portal.size(), 63)), {bo, portal.size() + 1}});
                } else if ((type == 'D' || type == 'C') && b.remaining() >= 1) {
                    const char kind = static_cast<char>(b.u8());
                    const std::string n = b.stringZ();
                    info = typeName + ": " + (kind == 'S' ? "statement " : "portal ") + (n.empty() ? std::string("<unnamed>") : printableText(n.data(), n.size(), 63));
                } else if (type == 'E') {
                    const std::string portal = b.stringZ();
                    info = "Execute: portal " + (portal.empty() ? std::string("<unnamed>") : printableText(portal.data(), portal.size(), 63));
                }
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
