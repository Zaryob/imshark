#include "postgres.h"
#include "reader.h"
#include "util.h"
#include <cstdio>
#include <string>

namespace dissect {

namespace {

const char *pgBackendMsgName(char type) {
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
        case 'I': return "EmptyQueryResponse";
        case 'E': return "ErrorResponse";
        case 'N': return "NoticeResponse";
        case 'A': return "NotificationResponse";
        default: return nullptr;
    }
}

const char *pgFrontendMsgName(char type) {
    switch (type) {
        case 'Q': return "SimpleQuery";
        case 'P': return "Parse";
        case 'B': return "Bind";
        case 'E': return "Execute";
        case 'D': return "Describe";
        case 'C': return "Close";
        case 'S': return "Sync";
        case 'F': return "FunctionCall";
        case 'X': return "Terminate";
        case 'p': return "PasswordMessage";
        default: return nullptr;
    }
}

const char *pgAuthTypeName(uint32_t authType) {
    switch (authType) {
        case 0: return "Ok";
        case 2: return "KerberosV5";
        case 3: return "CleartextPassword";
        case 5: return "MD5Password";
        case 6: return "SCM";
        case 7: return "GSS";
        case 8: return "GSSContinue";
        case 9: return "SSPI";
        case 10: return "SASL";
        case 11: return "SASLContinue";
        case 12: return "SASLFinal";
        default: return "Unknown";
    }
}

} // namespace

StreamFrame framePostgreSql(const char *data, size_t length) {
    if (length < 4) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);

    // StartupMessage / SSLRequest doesn't have a 1-byte type character prefix.
    // Length is first 4 bytes.
    uint32_t first4 = (static_cast<uint32_t>(bytes[0]) << 24) |
                      (static_cast<uint32_t>(bytes[1]) << 16) |
                      (static_cast<uint32_t>(bytes[2]) << 8) |
                      static_cast<uint32_t>(bytes[3]);

    if (first4 == 8 || (first4 >= 8 && first4 <= 10000 && (bytes[0] == 0))) {
        // StartupMessage or SSLRequest or CancelRequest
        if (length < first4) return StreamFrame{StreamFrame::Kind::NeedMore, 0};
        return StreamFrame{StreamFrame::Kind::Complete, first4};
    }

    // Standard message: 1 byte type + 4 bytes length (length includes the 4 length bytes, but not the type byte)
    if (length < 5) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    uint32_t msgLen = (static_cast<uint32_t>(bytes[1]) << 24) |
                      (static_cast<uint32_t>(bytes[2]) << 16) |
                      (static_cast<uint32_t>(bytes[3]) << 8) |
                      static_cast<uint32_t>(bytes[4]);

    if (msgLen < 4 || msgLen > 16 * 1024 * 1024) {
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }

    size_t total = 1 + static_cast<size_t>(msgLen);
    if (length < total) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    return StreamFrame{StreamFrame::Kind::Complete, total};
}

void dissectPostgreSql(Context &ctx, const char *data, size_t length) {
    if (!data || length < 4) return;

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    ctx.pack.protocol = "PGSQL";

    uint32_t len0 = r.u32_be();

    // Check for SSLRequest (8 bytes, code 80877103 = 0x04D2162F)
    if (len0 == 8 && length >= 8) {
        uint32_t code = r.u32_be();
        if (code == 80877103) {
            ctx.pack.info = "SSLRequest";
            if (ctx.wantFields()) {
                auto &root = ctx.addLayer("PostgreSQL (SSLRequest)", ctx.offsetOf(data), 8);
                root.add("Length: 8");
                root.add("Code: SSLRequest (80877103)");
            }
            return;
        } else if (code == 80877102) {
            ctx.pack.info = "CancelRequest";
            return;
        }
    }

    // Check for StartupMessage: 4 bytes length, 4 bytes version (e.g. 3.0 = 0x00030000 = 196608)
    if (len0 >= 8 && len0 <= 10000 && length >= 8) {
        uint32_t protoVer = (static_cast<uint32_t>(bytes[4]) << 24) |
                            (static_cast<uint32_t>(bytes[5]) << 16) |
                            (static_cast<uint32_t>(bytes[6]) << 8) |
                            static_cast<uint32_t>(bytes[7]);
        if (protoVer == 0x00030000) { // PostgreSQL 3.0
            std::string user;
            std::string db;
            // Parse null-terminated string pairs: user, database, etc.
            size_t p = 8;
            while (p < length && p < len0 && bytes[p] != 0) {
                std::string k;
                while (p < length && p < len0 && bytes[p] != 0) k.push_back(static_cast<char>(bytes[p++]));
                if (p < length) p++; // skip 0
                std::string v;
                while (p < length && p < len0 && bytes[p] != 0) v.push_back(static_cast<char>(bytes[p++]));
                if (p < length) p++; // skip 0

                if (k == "user") user = v;
                else if (k == "database") db = v;
            }

            std::string summary = "StartupMessage (3.0)";
            if (!user.empty()) summary += " user=" + user;
            if (!db.empty()) summary += " db=" + db;

            ctx.pack.info = summary;
            if (ctx.wantFields()) {
                auto &root = ctx.addLayer("PostgreSQL (StartupMessage)", ctx.offsetOf(data), len0 <= length ? len0 : length);
                root.add("Protocol Version: 3.0");
                if (!user.empty()) root.add("User: " + user);
                if (!db.empty()) root.add("Database: " + db);
            }
            return;
        }
    }

    // Check for SSLRequest response: single byte 'S' or 'N' (1 byte)
    if (length == 1) {
        if (data[0] == 'S') {
            ctx.pack.info = "SSLRequest Response: Supported (S)";
            return;
        } else if (data[0] == 'N') {
            ctx.pack.info = "SSLRequest Response: Unsupported (N)";
            return;
        }
    }

    // Regular typed message: 1 byte type, 4 bytes length
    char type = data[0];
    uint32_t msgLen = (static_cast<uint32_t>(bytes[1]) << 24) |
                      (static_cast<uint32_t>(bytes[2]) << 16) |
                      (static_cast<uint32_t>(bytes[3]) << 8) |
                      static_cast<uint32_t>(bytes[4]);

    const char *bName = pgBackendMsgName(type);
    const char *fName = pgFrontendMsgName(type);
    std::string typeName = bName ? bName : (fName ? fName : std::string("Msg '") + type + "'");

    std::string summary = typeName;

    if (type == 'Q' && length >= 5) { // SimpleQuery
        std::string query;
        for (size_t i = 5; i < length && bytes[i] != 0; ++i) {
            query.push_back(static_cast<char>(bytes[i]));
        }
        summary = "Query: " + query;
        ctx.pack.app_text = query;
    } else if (type == 'R' && length >= 9) { // Authentication
        uint32_t authCode = (static_cast<uint32_t>(bytes[5]) << 24) |
                            (static_cast<uint32_t>(bytes[6]) << 16) |
                            (static_cast<uint32_t>(bytes[7]) << 8) |
                            static_cast<uint32_t>(bytes[8]);
        summary = "Authentication: " + std::string(pgAuthTypeName(authCode));
    } else if (type == 'C' && length >= 5) { // CommandComplete
        std::string tag;
        for (size_t i = 5; i < length && bytes[i] != 0; ++i) {
            tag.push_back(static_cast<char>(bytes[i]));
        }
        summary = "CommandComplete: " + tag;
    } else if (type == 'Z' && length >= 6) { // ReadyForQuery
        char txStatus = data[5];
        summary = "ReadyForQuery (" + std::string(1, txStatus) + ")";
    }

    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("PostgreSQL (" + typeName + ")", o, 1 + msgLen <= length ? 1 + msgLen : length);
        root.add("Type: " + std::string(1, type) + " (" + typeName + ")");
        root.add("Length: " + std::to_string(msgLen));
        if (type == 'Q' && !ctx.pack.app_text.empty()) {
            root.add("Query: " + ctx.pack.app_text);
        }
    }
}

} // namespace dissect
