// TDS (Tabular Data Stream, [MS-TDS]) packets. Packet header (8 bytes): Type, Status (bit 0 = end of message), Length (big-endian,
// header included), SPID (big-endian), PacketID, Window (zero). Decoded: Pre-Login options (version, ENCRYPTION, MARS ...),
// Login7 (host, user, application, server, database; the password is masked), SQL Batch text, RPC procedure, and the tokens of a
// Tabular Result that can be walked without the column metadata (LOGINACK, ENVCHANGE, INFO, ERROR, DONE ...).
// TLS: with ENCRYPT_ON / ENCRYPT_REQ / ENCRYPT_OFF the TLS handshake travels inside Pre-Login packets (recognised and named, not
// handed to the TLS dissector); after it the encrypted records follow without a TDS header and are shown as TLS.
#include "tds.h"

#include <string>
#include <vector>

#include "reader.h"
#include "util.h"

using packet::Field;

namespace dissect {

namespace {

// app_flags: low byte = the TDS status byte, then
constexpr uint16_t kFlagError = 0x100, kFlagPreLogin = 0x200, kFlagLogin7 = 0x400, kFlagTlsHandshake = 0x800;
// the ENCRYPTION option of a Pre-Login is kept in bits 12..13 of app_flags together with kFlagPreLogin
constexpr int kEncryptShift = 12;

const char *packetTypeName(uint8_t type) {
    switch (type) {
        case 1: return "SQL Batch";
        case 2: return "Pre-TDS7 Login";
        case 3: return "RPC";
        case 4: return "Tabular Response";
        case 6: return "Attention Signal";
        case 7: return "Bulk Load Data";
        case 8: return "Federated Auth Token";
        case 14: return "Transaction Manager Request";
        case 16: return "TDS7 Login";
        case 17: return "SSPI Message";
        case 18: return "Pre-Login";
        default: return nullptr;
    }
}

const char *encryptionName(uint8_t v) {
    switch (v) {
        case 0: return "ENCRYPT_OFF";
        case 1: return "ENCRYPT_ON";
        case 2: return "ENCRYPT_NOT_SUP";
        case 3: return "ENCRYPT_REQ";
        case 0x80: return "ENCRYPT_CLIENT_CERT_OFF";
        case 0x81: return "ENCRYPT_CLIENT_CERT_ON";
        case 0x83: return "ENCRYPT_CLIENT_CERT_REQ";
        default: return "ENCRYPT_?";
    }
}

const char *preLoginTokenName(uint8_t t) {
    switch (t) {
        case 0: return "VERSION";
        case 1: return "ENCRYPTION";
        case 2: return "INSTOPT";
        case 3: return "THREADID";
        case 4: return "MARS";
        case 5: return "TRACEID";
        case 6: return "FEDAUTHREQUIRED";
        case 7: return "NONCEOPT";
        default: return nullptr;
    }
}

const char *tokenName(uint8_t t) {
    switch (t) {
        case 0x79: return "RETURNSTATUS";
        case 0x81: return "COLMETADATA";
        case 0x88: return "ALTMETADATA";
        case 0xA4: return "TABNAME";
        case 0xA5: return "COLINFO";
        case 0xA9: return "ORDER";
        case 0xAA: return "ERROR";
        case 0xAB: return "INFO";
        case 0xAC: return "RETURNVALUE";
        case 0xAD: return "LOGINACK";
        case 0xAE: return "FEATUREEXTACK";
        case 0xD1: return "ROW";
        case 0xD2: return "NBCROW";
        case 0xE3: return "ENVCHANGE";
        case 0xED: return "SSPI";
        case 0xFD: return "DONE";
        case 0xFE: return "DONEPROC";
        case 0xFF: return "DONEINPROC";
        default: return nullptr;
    }
}

// UTF-16LE -> printable ASCII ('?' for anything else), at most `maxChars` characters
std::string utf16(const uint8_t *p, size_t bytes, size_t maxChars = 200) {
    std::string out;
    for (size_t i = 0; i + 1 < bytes && out.size() < maxChars; i += 2) {
        const uint16_t ch = static_cast<uint16_t>(p[i] | (p[i + 1] << 8));
        if (ch == 0) break;
        out += (ch >= 32 && ch < 127) ? static_cast<char>(ch) : (ch == '\n' || ch == '\r' || ch == '\t') ? ' ' : '?';
    }
    if (bytes / 2 > maxChars) out += "...";
    return out;
}

// A Pre-Login payload: options (token, offset BE16, length BE16) ended by 0xFF; offsets count from the start of the payload.
bool validPreLogin(const uint8_t *p, size_t n) {
    size_t i = 0;
    int options = 0;
    while (i < n && p[i] != 0xFF) {
        if (i + 5 > n || options++ > 16 || p[i] > 0x10) return false;
        const size_t off = (static_cast<size_t>(p[i + 1]) << 8) | p[i + 2], len = (static_cast<size_t>(p[i + 3]) << 8) | p[i + 4];
        if (off + len > n) return false;
        i += 5;
    }
    return options > 0 && i < n;
}

bool startsTlsRecord(const uint8_t *p, size_t n) {
    return n >= 6 && p[0] >= 20 && p[0] <= 23 && p[1] == 3 && p[2] <= 4 && (p[0] != 22 || p[5] <= 24);
}

} // namespace

StreamFrame frameTds(const char *data, size_t length) {
    if (length == 0) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    // the first bytes decide: a known packet type, status without the reserved bits
    if (!packetTypeName(bytes[0])) return StreamFrame{StreamFrame::Kind::Reject, 0};
    if (length >= 2 && (bytes[1] & 0xE0) != 0) return StreamFrame{StreamFrame::Kind::Reject, 0};
    if (length < 8) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    if (bytes[7] != 0) return StreamFrame{StreamFrame::Kind::Reject, 0};   // Window is unused and zero
    const size_t pktLen = (static_cast<size_t>(bytes[2]) << 8) | bytes[3];
    if (pktLen < 8) return StreamFrame{StreamFrame::Kind::Reject, 0};
    return StreamFrame{length < pktLen ? StreamFrame::Kind::NeedMore : StreamFrame::Kind::Complete, pktLen};
}

void dissectTds(Context &ctx, const char *data, size_t length) {
    if (!data || length < 8) return;
    auto &pack = ctx.pack;
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    const uint8_t type = r.u8();
    const uint8_t status = r.u8();
    const uint16_t pktLen = r.u16_be();
    const uint16_t spid = r.u16_be();
    const uint8_t packetId = r.u8();
    const uint8_t window = r.u8();
    const size_t o = ctx.offsetOf(data);

    pack.protocol = "TDS";
    pack.app_type = type;
    pack.app_code = spid;
    pack.app_flags = status;

    const char *typeName = packetTypeName(type);
    const std::string typeStr = typeName ? typeName : "Type " + std::to_string(type);
    const bool eom = (status & 0x01) != 0;
    const size_t end = std::min<size_t>(pktLen < 8 ? 8 : pktLen, length);   // the payload ends here
    const uint8_t *payload = bytes + 8;
    const size_t payloadLen = end > 8 ? end - 8 : 0;
    const bool cut = pktLen > length;

    std::string summary = typeStr;
    const char *malformed = nullptr;   // set when the packet is complete (not cut) but its body does not decode
    std::vector<std::pair<std::string, std::pair<size_t, size_t>>> items;   // detail-tree children: text, offset, length
    auto add = [&](const std::string &text, size_t off, size_t len) { items.push_back({text, {off, len}}); };

    if (type == 18 && startsTlsRecord(payload, payloadLen)) {
        // the TLS handshake of an encrypted connection travels inside Pre-Login packets
        pack.app_flags |= kFlagTlsHandshake;
        summary = "Pre-Login (TLS handshake)";
        add("TLS handshake data (" + std::to_string(payloadLen) + " bytes)", o + 8, payloadLen);
    } else if ((type == 18 || type == 4) && payloadLen > 0 && payload[0] <= 7 && validPreLogin(payload, payloadLen)) {
        // Pre-Login request (type 18) or response (type 4)
        pack.app_flags |= kFlagPreLogin;
        std::string what;
        size_t i = 0;
        while (i + 5 <= payloadLen && payload[i] != 0xFF) {
            const uint8_t token = payload[i];
            const size_t off = (static_cast<size_t>(payload[i + 1]) << 8) | payload[i + 2], len = (static_cast<size_t>(payload[i + 3]) << 8) | payload[i + 4];
            const char *tn = preLoginTokenName(token);
            const std::string name = tn ? tn : "option " + std::to_string(token);
            if (token == 0 && len >= 4) { // VERSION: major, minor, build (BE16), subbuild (BE16)
                const std::string v = std::to_string(payload[off]) + "." + std::to_string(payload[off + 1]) + "." + std::to_string(static_cast<unsigned>((payload[off + 2] << 8) | payload[off + 3]));
                add("VERSION: " + v, o + 8 + off, len);
                what += " version " + v;
            } else if (token == 1 && len >= 1) {
                const uint8_t e = payload[off];
                add(std::string("ENCRYPTION: ") + encryptionName(e) + " (" + std::to_string(e) + ")", o + 8 + off, 1);
                what += std::string(" ") + encryptionName(e);
                pack.app_flags = static_cast<uint16_t>((pack.app_flags & ~(3u << kEncryptShift)) | ((e & 3u) << kEncryptShift));
            } else if (token == 2 && len > 0) {
                add("INSTOPT: " + printableText(payload + off, len - 1, 63), o + 8 + off, len);
            } else if (token == 4 && len >= 1) {
                add(std::string("MARS: ") + (payload[off] ? "on" : "off"), o + 8 + off, 1);
            } else {
                add(name + " (" + std::to_string(len) + " bytes)", o + 8 + off, len);
            }
            i += 5;
        }
        summary = std::string("Pre-Login ") + (type == 18 ? "request" : "response") + what;
    } else if (type == 18 && packetId == 1 && payloadLen > 0) {
        // the first Pre-Login packet is an option table or the start of a wrapped TLS record; anything else is not Pre-Login
        if (!cut) malformed = "TDS Pre-Login payload is neither an option table nor a TLS record";
    } else if (type == 16 && payloadLen < 36 + 58) {
        if (!cut) malformed = "TDS Login7 shorter than its fixed part";
    } else if (type == 16) { // Login7: fixed part, then (offset, length) pairs, then the data
        pack.app_flags |= kFlagLogin7;
        const uint8_t *b = payload;
        const auto le16At = [&](size_t at) { return static_cast<size_t>(b[at] | (b[at + 1] << 8)); };
        const auto field = [&](size_t pair, const char *label, bool mask) {
            const size_t off = le16At(36 + pair * 4), chars = le16At(36 + pair * 4 + 2);
            if (chars == 0) return std::string();
            if (off + chars * 2 > payloadLen) { add(std::string(label) + ": [outside the packet]", o + 8, 0); if (!cut) malformed = "TDS Login7 string lies outside the packet"; return std::string(); }
            if (mask) {   // the password is obfuscated on the wire (nibble swap, XOR 0xA5); it is never decoded or shown
                add(std::string(label) + ": " + std::string(std::min<size_t>(chars, 16), '*') + " (masked, " + std::to_string(chars) + " characters)", o + 8 + off, chars * 2);
                return std::string();
            }
            const std::string v = utf16(b + off, chars * 2, 128);
            add(std::string(label) + ": " + v, o + 8 + off, chars * 2);
            return v;
        };
        const uint32_t version = static_cast<uint32_t>(b[4] | (b[5] << 8) | (b[6] << 16)) | (static_cast<uint32_t>(b[7]) << 24);
        add("TDS Version: " + hexString(version, 8), o + 8 + 4, 4);
        const std::string host = field(0, "Client Host Name", false);
        const std::string user = field(1, "User Name", false);
        field(2, "Password", true);
        const std::string app = field(3, "Application Name", false);
        const std::string server = field(4, "Server Name", false);
        field(7, "Language", false);
        const std::string db = field(8, "Database Name", false);
        pack.app_text2 = user;
        summary = "Login7 user=" + user + (db.empty() ? "" : " db=" + db) + (app.empty() ? "" : " app=" + app);
        (void) host; (void) server;
    } else if (type == 1 && payloadLen > 0) {
        // SQL Batch: the first packet of a TDS 7.2+ message starts with ALL_HEADERS (TotalLength, then headers), then UTF-16LE text
        size_t textOffset = 0;
        if (packetId == 1 && payloadLen >= 4) {
            const size_t total = static_cast<size_t>(payload[0] | (payload[1] << 8) | (payload[2] << 16)) | (static_cast<size_t>(payload[3]) << 24);
            if (total >= 4 && total <= payloadLen) {
                size_t at = 4;
                bool chain = true;
                while (at < total) {   // each header: Length (4), Type (2), data
                    if (total - at < 6) { chain = false; break; }
                    const size_t hl = static_cast<size_t>(payload[at] | (payload[at + 1] << 8) | (payload[at + 2] << 16)) | (static_cast<size_t>(payload[at + 3]) << 24);
                    if (hl < 6 || hl > total - at) { chain = false; break; }
                    at += hl;
                }
                if (chain && at == total) { textOffset = total; add("ALL_HEADERS (" + std::to_string(total) + " bytes)", o + 8, total); }
            }
        }
        const std::string text = utf16(payload + textOffset, payloadLen - textOffset, 512);
        if (!text.empty()) {
            summary = "Query: " + text.substr(0, 200);
            pack.app_text = text;
            add("SQL Text: " + text, o + 8 + textOffset, payloadLen - textOffset);
        }
    } else if (type == 3 && payloadLen > 0) {
        // RPC: ALL_HEADERS, then ProcName (US_VARCHAR) or 0xFFFF + a well-known procedure id
        size_t at = 0;
        if (packetId == 1 && payloadLen >= 4) {
            const size_t total = static_cast<size_t>(payload[0] | (payload[1] << 8) | (payload[2] << 16)) | (static_cast<size_t>(payload[3]) << 24);
            if (total >= 4 && total <= payloadLen) at = total;
        }
        if (payloadLen >= at + 2) {
            const size_t nameLen = static_cast<size_t>(payload[at] | (payload[at + 1] << 8));
            std::string proc;
            if (nameLen == 0xFFFF && payloadLen >= at + 4) {
                const unsigned id = static_cast<unsigned>(payload[at + 2] | (payload[at + 3] << 8));
                static const char *const names[] = {"", "sp_Cursor", "sp_CursorOpen", "sp_CursorPrepare", "sp_CursorExecute", "sp_CursorPrepExec", "sp_CursorUnprepare",
                                                    "sp_CursorFetch", "sp_CursorOption", "sp_CursorClose", "sp_ExecuteSql", "sp_Prepare", "sp_Execute", "sp_PrepExec",
                                                    "sp_PrepExecRpc", "sp_Unprepare"};
                proc = id >= 1 && id <= 15 ? names[id] : "procedure id " + std::to_string(id);
            } else if (nameLen > 0 && payloadLen >= at + 2 + nameLen * 2) {
                proc = utf16(payload + at + 2, nameLen * 2, 128);
            }
            if (!proc.empty()) {
                summary = "RPC " + proc;
                pack.app_text = proc;
                add("Procedure: " + proc, o + 8 + at, payloadLen - at);
            }
        }
    } else if (type == 4 && payloadLen > 0) {
        // Tabular Result: walk the tokens whose size is known without the column metadata
        std::string tokens;
        size_t at = 0;
        int count = 0;
        while (at < payloadLen && count++ < 32) {
            const uint8_t t = payload[at];
            const char *tn = tokenName(t);
            if (!tn) break;
            const std::string name = tn;
            size_t size = 0;   // bytes of the token including its type byte; 0 = unknown, stop after naming it
            if (t == 0xFD || t == 0xFE || t == 0xFF) size = 1 + 12;
            else if (t == 0x79) size = 1 + 4;
            else if (t == 0xAA || t == 0xAB || t == 0xAD || t == 0xE3 || t == 0xA9 || t == 0xA4 || t == 0xA5 || t == 0xED) {
                if (at + 3 > payloadLen) break;
                size = 3 + static_cast<size_t>(payload[at + 1] | (payload[at + 2] << 8));
            }
            tokens += (tokens.empty() ? "" : ", ") + name;
            if (t == 0xAA && size && at + size <= payloadLen && size >= 3 + 4 + 1 + 1 + 2) { // ERROR: Number (4), State (1), Class (1), MsgText (US_VARCHAR)
                const uint8_t *e = payload + at + 3;
                const uint32_t number = static_cast<uint32_t>(e[0] | (e[1] << 8) | (e[2] << 16)) | (static_cast<uint32_t>(e[3]) << 24);
                const size_t msgChars = static_cast<size_t>(e[6] | (e[7] << 8));
                const std::string msg = (8 + msgChars * 2 <= size - 3) ? utf16(e + 8, msgChars * 2, 200) : std::string();
                pack.app_flags |= kFlagError;
                pack.app_stream = number;
                tokens += " " + std::to_string(number) + (msg.empty() ? "" : " (" + msg.substr(0, 120) + ")");
                add("ERROR " + std::to_string(number) + ", state " + std::to_string(e[4]) + ", class " + std::to_string(e[5]) + ": " + msg, o + 8 + at, size);
            } else if (t == 0xAD && size && at + size <= payloadLen) {
                add("LOGINACK", o + 8 + at, size);
            } else {
                add(name + (size ? " (" + std::to_string(size) + " bytes)" : ""), o + 8 + at, size ? std::min(size, payloadLen - at) : 1);
            }
            if (size == 0 || at + size > payloadLen) break;
            at += size;
        }
        if (!tokens.empty()) summary = "Tabular Response: " + tokens;
    }

    if (eom) summary += " (EOM)";
    if (spid != 0) summary += " SPID=" + std::to_string(spid);
    pack.info = summary;

    if (ctx.wantFields()) {
        Field &root = ctx.addLayer("Tabular Data Stream (" + typeStr + ")", o, std::min<size_t>(pktLen < 8 ? 8 : pktLen, length));
        root.add("Type: " + typeStr + " (" + std::to_string(type) + ")", o, 1);
        root.add("Status: " + hexString(status, 2) + (eom ? " (End of Message)" : ""), o + 1, 1);
        root.add("Length: " + std::to_string(pktLen), o + 2, 2);
        root.add("SPID: " + std::to_string(spid), o + 4, 2);
        root.add("Packet ID: " + std::to_string(packetId), o + 6, 1);
        root.add("Window: " + std::to_string(window), o + 7, 1);
        for (const auto &it: items) {
            const size_t rel = it.second.first - o;
            if (rel <= length) root.add(it.first, it.second.first, std::min(it.second.second, length - rel));
        }
    }
    // a packet continued in the next segment (cut) is not an error
    if (pktLen < 8) ctx.markMalformed("TDS packet length below the 8 byte header");
    else if (malformed) ctx.markMalformed(malformed);   // after the summary: it replaces it
}

} // namespace dissect
