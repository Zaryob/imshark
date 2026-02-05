#include "tds.h"
#include "reader.h"
#include "util.h"
#include <cstdio>
#include <string>

namespace dissect {

namespace {

const char *tdsPacketTypeName(uint8_t type) {
    switch (type) {
        case 1: return "SQL Batch";
        case 2: return "Pre-TDS7 Login";
        case 3: return "RPC";
        case 4: return "Tabular Response";
        case 6: return "Attention Signal";
        case 7: return "Bulk Load Data";
        case 8: return "Federated Auth Token";
        case 14: return "Transaction Manager Request";
        case 16: return "TDS7/8 Login";
        case 17: return "SSPI Message";
        case 18: return "Pre-Login";
        default: return nullptr;
    }
}

} // namespace

StreamFrame frameTds(const char *data, size_t length) {
    if (length < 8) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    // TDS header:
    // byte 0: Type
    // byte 1: Status
    // byte 2..3: Length (big-endian 16-bit, includes 8-byte header)
    uint16_t pktLen = (static_cast<uint16_t>(bytes[2]) << 8) | static_cast<uint16_t>(bytes[3]);

    if (pktLen < 8) {
        return StreamFrame{StreamFrame::Kind::Reject, 0};
    }

    if (length < pktLen) {
        return StreamFrame{StreamFrame::Kind::NeedMore, 0};
    }
    return StreamFrame{StreamFrame::Kind::Complete, pktLen};
}

void dissectTds(Context &ctx, const char *data, size_t length) {
    if (!data || length < 8) return;

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    ByteReader r(bytes, length);

    uint8_t type = r.u8();
    uint8_t status = r.u8();
    uint16_t pktLen = r.u16_be();
    uint16_t spid = r.u16_be();
    uint8_t packetId = r.u8();
    uint8_t window = r.u8();

    ctx.pack.protocol = "TDS";
    ctx.pack.app_type = type;

    const char *typeName = tdsPacketTypeName(type);
    std::string typeStr = typeName ? typeName : ("Type " + std::to_string(type));

    bool isEom = (status & 0x01) != 0; // End of message

    std::string summary = typeStr;
    if (isEom) summary += " (EOM)";
    if (spid != 0) summary += " SPID=" + std::to_string(spid);

    // SQL Batch (Type 1): In TDS 7.2+, contains ALL_HEADERS followed by UTF-16LE SQL text
    if (type == 1 && length > 8) {
        // Try to check if text follows: if TDS 7.2+ header exists (starts with uint32 total header len)
        size_t textOffset = 8;
        if (length >= 12) {
            uint32_t headerLen = static_cast<uint32_t>(bytes[8]) |
                                 (static_cast<uint32_t>(bytes[9]) << 8) |
                                 (static_cast<uint32_t>(bytes[10]) << 16) |
                                 (static_cast<uint32_t>(bytes[11]) << 24);
            if (headerLen >= 4 && headerLen + 8 <= length) {
                textOffset = 8 + headerLen;
            }
        }

        // Decode UTF-16LE characters
        std::string queryText;
        for (size_t i = textOffset; i + 1 < length && i + 1 < pktLen; i += 2) {
            uint16_t ch = static_cast<uint16_t>(bytes[i]) | (static_cast<uint16_t>(bytes[i + 1]) << 8);
            if (ch == 0) break;
            if (ch >= 32 && ch < 127) queryText.push_back(static_cast<char>(ch));
            else if (ch == '\n' || ch == '\r' || ch == '\t') queryText.push_back(' ');
            else queryText.push_back('?');
        }

        if (!queryText.empty()) {
            summary = "Query: " + queryText;
            ctx.pack.app_text = queryText;
        }
    } else if (type == 18) { // Pre-Login
        summary = "Pre-Login Handshake";
    }

    ctx.pack.info = summary;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        auto &root = ctx.addLayer("Tabular Data Stream (" + typeStr + ")", o, pktLen <= length ? pktLen : length);
        root.add("Type: " + typeStr + " (" + std::to_string(type) + ")");
        root.add("Status: 0x" + hexString(status, 2) + (isEom ? " (End of Message)" : ""));
        root.add("Length: " + std::to_string(pktLen));
        root.add("SPID: " + std::to_string(spid));
        root.add("Packet ID: " + std::to_string(packetId));
        root.add("Window: " + std::to_string(window));
        if (!ctx.pack.app_text.empty()) {
            root.add("SQL Text: " + ctx.pack.app_text);
        }
    }
}

} // namespace dissect
