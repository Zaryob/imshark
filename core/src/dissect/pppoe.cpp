#include "pppoe.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "ppp.h"
#include "protocols.h"
#include "util.h"

using packet::Field;

namespace {
    using dissect::be16;
    using dissect::hexString;

    const char *pppoeCodeName(uint8_t code) {
        switch (code) {
            case 0x00: return "Session Data";
            case 0x09: return "Active Discovery Initiation (PADI)";
            case 0x07: return "Active Discovery Offer (PADO)";
            case 0x19: return "Active Discovery Request (PADR)";
            case 0x65: return "Active Discovery Session-confirmation (PADS)";
            case 0xa7: return "Active Discovery Terminate (PADT)";
            default: return "Unknown Code";
        }
    }

    const char *pppoeCodeShort(uint8_t code) {
        switch (code) {
            case 0x00: return "Session";
            case 0x09: return "PADI";
            case 0x07: return "PADO";
            case 0x19: return "PADR";
            case 0x65: return "PADS";
            case 0xa7: return "PADT";
            default: return "Unknown";
        }
    }

    const char *pppoeTagName(uint16_t tag) {
        switch (tag) {
            case 0x0000: return "End-Of-List";
            case 0x0101: return "Service-Name";
            case 0x0102: return "AC-Name";
            case 0x0103: return "Host-Uniq";
            case 0x0104: return "AC-Cookie";
            case 0x0105: return "Vendor-Specific";
            case 0x0106: return "Relay-Session-Id";
            case 0x0201: return "Service-Name-Error";
            case 0x0202: return "AC-System-Error";
            case 0x0203: return "Generic-Error";
            default: return "Unknown Tag";
        }
    }
} // namespace

void dissect::dissectPppoeDiscovery(Context &ctx, const char *data, size_t length) {
    if (length < 6) {
        ctx.markMalformed("frame too short for PPPoE header");
        ctx.pack.protocol = "PPPoED";
        return;
    }

    const uint8_t verType = static_cast<uint8_t>(data[0]);
    const uint8_t ver = (verType >> 4) & 0x0F;
    const uint8_t type = verType & 0x0F;
    if (ver != 1 || type != 1) {
        ctx.markMalformed("unsupported PPPoE version/type");
        ctx.pack.protocol = "PPPoED";
        return;
    }
    const uint8_t code = static_cast<uint8_t>(data[1]);
    const uint16_t sessionId = be16(data + 2);
    const uint16_t payloadLen = be16(data + 4);

    ctx.pack.protocol = "PPPoED";
    ctx.pack.pppoe_code = code;
    ctx.pack.pppoe_session_id = sessionId;
    ctx.pack.l2_size = static_cast<uint16_t>(ctx.pack.l2_size + 6);

    const size_t baseOffset = ctx.offsetOf(data);
    const size_t effLen = std::min<size_t>(length - 6, payloadLen);

    std::string serviceName;
    std::string acName;

    // Parse discovery tags
    size_t off = 6;
    while (off + 4 <= 6 + effLen) {
        const uint16_t tagType = be16(data + off);
        const uint16_t tagLen = be16(data + off + 2);
        if (off + 4 + tagLen > 6 + effLen) break;

        if (tagType == 0x0101 && serviceName.empty() && tagLen > 0) {
            serviceName = std::string(data + off + 4, tagLen);
        } else if (tagType == 0x0102 && acName.empty() && tagLen > 0) {
            acName = std::string(data + off + 4, tagLen);
        }

        off += 4 + tagLen;
    }

    ctx.pack.app_text = serviceName;
    ctx.pack.app_text2 = acName;

    std::string infoStr = pppoeCodeShort(code);
    if (!acName.empty() || !serviceName.empty()) {
        infoStr += " (";
        if (!acName.empty()) infoStr += "AC: \"" + acName + "\"";
        if (!serviceName.empty()) {
            if (!acName.empty()) infoStr += ", ";
            infoStr += "Service: \"" + serviceName + "\"";
        }
        infoStr += ")";
    }
    infoStr += "  Session ID: " + hexString(sessionId, 4);
    ctx.pack.info = infoStr;

    if (ctx.wantFields()) {
        Field &pppoe = ctx.addLayer("PPP-over-Ethernet Discovery (" + std::string(pppoeCodeShort(code)) + ")",
                                    baseOffset, 6 + effLen);
        pppoe.add("Version: " + std::to_string(ver), baseOffset, 1);
        pppoe.add("Type: " + std::to_string(type), baseOffset, 1);
        pppoe.add("Code: " + std::string(pppoeCodeName(code)) + " (" + hexString(code, 2) + ")", baseOffset + 1, 1);
        pppoe.add("Session ID: " + hexString(sessionId, 4), baseOffset + 2, 2);
        pppoe.add("Payload Length: " + std::to_string(payloadLen), baseOffset + 4, 2);

        // Tags tree
        off = 6;
        while (off + 4 <= 6 + effLen) {
            const uint16_t tagType = be16(data + off);
            const uint16_t tagLen = be16(data + off + 2);
            if (off + 4 + tagLen > 6 + effLen) {
                pppoe.add("Truncated Tag: Type " + hexString(tagType, 4) + ", Length " + std::to_string(tagLen),
                          baseOffset + off, (6 + effLen) - off);
                break;
            }

            std::string tagDesc = pppoeTagName(tagType);
            std::string valStr;
            if ((tagType == 0x0101 || tagType == 0x0102) && tagLen > 0) {
                valStr = ": \"" + std::string(data + off + 4, tagLen) + "\"";
            }

            Field &tagF = pppoe.add("Tag: " + tagDesc + valStr, baseOffset + off, 4 + tagLen);
            tagF.add("Tag Type: " + tagDesc + " (" + hexString(tagType, 4) + ")", baseOffset + off, 2);
            tagF.add("Tag Length: " + std::to_string(tagLen), baseOffset + off + 2, 2);
            if (tagLen > 0) {
                tagF.add("Tag Data: " + dissect::asciiPreview(data + off + 4, tagLen), baseOffset + off + 4, tagLen);
            }

            off += 4 + tagLen;
        }
    }
}

void dissect::dissectPppoeSession(Context &ctx, const char *data, size_t length) {
    if (length < 6) {
        ctx.markMalformed("frame too short for PPPoE header");
        ctx.pack.protocol = "PPPoES";
        return;
    }

    const uint8_t verType = static_cast<uint8_t>(data[0]);
    const uint8_t ver = (verType >> 4) & 0x0F;
    const uint8_t type = verType & 0x0F;
    if (ver != 1 || type != 1) {
        ctx.markMalformed("unsupported PPPoE version/type");
        ctx.pack.protocol = "PPPoES";
        return;
    }
    const uint8_t code = static_cast<uint8_t>(data[1]);
    const uint16_t sessionId = be16(data + 2);
    const uint16_t payloadLen = be16(data + 4);

    ctx.pack.protocol = "PPPoES";
    ctx.pack.pppoe_code = code;
    ctx.pack.pppoe_session_id = sessionId;
    ctx.pack.l2_size = static_cast<uint16_t>(ctx.pack.l2_size + 6);

    const size_t baseOffset = ctx.offsetOf(data);
    const size_t effPayloadLen = std::min<size_t>(length - 6, payloadLen);

    if (ctx.wantFields()) {
        Field &pppoe = ctx.addLayer("PPP-over-Ethernet Session", baseOffset, 6);
        pppoe.add("Version: " + std::to_string(ver), baseOffset, 1);
        pppoe.add("Type: " + std::to_string(type), baseOffset, 1);
        pppoe.add("Code: " + std::string(pppoeCodeName(code)) + " (" + hexString(code, 2) + ")", baseOffset + 1, 1);
        pppoe.add("Session ID: " + hexString(sessionId, 4), baseOffset + 2, 2);
        pppoe.add("Payload Length: " + std::to_string(payloadLen), baseOffset + 4, 2);
    }

    if (effPayloadLen == 0) {
        ctx.pack.info = "PPPoE Session ID: " + hexString(sessionId, 4);
        return;
    }

    dissectPpp(ctx, data + 6, effPayloadLen);
}
