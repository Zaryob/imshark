#include "ppp.h"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "protocols.h"
#include "util.h"

using packet::Field;

namespace {
    using dissect::be16;
    using dissect::be32;
    using dissect::hexString;
    using dissect::ip4;

    const char *pppProtocolName(uint16_t proto) {
        switch (proto) {
            case 0x0021: return "IPv4";
            case 0x0057: return "IPv6";
            case 0x0029: return "AppleTalk";
            case 0x002b: return "Novell IPX";
            case 0x002d: return "Van Jacobson Compressed TCP/IP";
            case 0x002f: return "Van Jacobson Uncompressed TCP/IP";
            case 0x003f: return "MPLS Unicast";
            case 0x8021: return "Internet Protocol Control Protocol";
            case 0x8057: return "IPv6 Control Protocol";
            case 0x802b: return "Novell IPX Control Protocol";
            case 0x803f: return "MPLS Control Protocol";
            case 0x80fd: return "Compression Control Protocol";
            case 0xc021: return "Link Control Protocol";
            case 0xc023: return "Password Authentication Protocol";
            case 0xc025: return "Link Quality Report";
            case 0xc223: return "Challenge Handshake Authentication Protocol";
            case 0xc227: return "Extensible Authentication Protocol";
            default: return "Unknown";
        }
    }

    const char *controlCodeName(uint8_t code) {
        switch (code) {
            case 1: return "Configuration Request";
            case 2: return "Configuration Ack";
            case 3: return "Configuration Nak";
            case 4: return "Configuration Reject";
            case 5: return "Terminate Request";
            case 6: return "Terminate Ack";
            case 7: return "Code Reject";
            case 8: return "Protocol Reject";
            case 9: return "Echo Request";
            case 10: return "Echo Reply";
            case 11: return "Discard Request";
            default: return "Unknown Code";
        }
    }

    const char *lcpOptionName(uint8_t opt) {
        switch (opt) {
            case 1: return "Maximum Receive Unit";
            case 2: return "Async Control Character Map";
            case 3: return "Authentication Protocol";
            case 4: return "Quality Protocol";
            case 5: return "Magic Number";
            case 7: return "Protocol Field Compression";
            case 8: return "Address and Control Field Compression";
            default: return "Unknown Option";
        }
    }

    const char *ipcpOptionName(uint8_t opt) {
        switch (opt) {
            case 1: return "IP Addresses";
            case 2: return "IP Compression Protocol";
            case 3: return "IP Address";
            case 129: return "Primary DNS Server IP Address";
            case 130: return "Primary NBNS Server IP Address";
            case 131: return "Secondary DNS Server IP Address";
            case 132: return "Secondary NBNS Server IP Address";
            default: return "Unknown Option";
        }
    }

    void dissectControlProtocol(dissect::Context &ctx, const std::string &protoName, uint16_t pppProto,
                                const char *data, size_t length, size_t baseOffset) {
        if (length < 4) {
            ctx.markMalformed("truncated PPP control packet");
            ctx.pack.protocol = protoName;
            return;
        }

        const uint8_t code = static_cast<uint8_t>(data[0]);
        const uint8_t id = static_cast<uint8_t>(data[1]);
        const uint16_t ctrlLen = be16(data + 2);

        ctx.pack.protocol = protoName;
        ctx.pack.app_type = code;
        ctx.pack.app_code = id;

        const size_t effLen = std::min<size_t>(length, ctrlLen);
        ctx.pack.info = std::string(controlCodeName(code)) + " (id=" + std::to_string(id) +
                        ", len=" + std::to_string(ctrlLen) + ")";

        if (ctx.wantFields()) {
            Field &cp = ctx.addLayer(protoName + ", " + controlCodeName(code) + ", ID: " + std::to_string(id),
                                     baseOffset, effLen);
            cp.add("Code: " + std::string(controlCodeName(code)) + " (" + std::to_string(code) + ")", baseOffset, 1);
            cp.add("Identifier: " + std::to_string(id) + " (" + hexString(id, 2) + ")", baseOffset + 1, 1);
            cp.add("Length: " + std::to_string(ctrlLen), baseOffset + 2, 2);

            // Parse options for Config-Req, Config-Ack, Config-Nak, Config-Reject
            if ((code >= 1 && code <= 4) && effLen > 4) {
                size_t off = 4;
                while (off + 2 <= effLen) {
                    const uint8_t optType = static_cast<uint8_t>(data[off]);
                    const uint8_t optLen = static_cast<uint8_t>(data[off + 1]);
                    if (optLen < 2 || off + optLen > effLen) {
                        cp.add("Malformed Option: Type " + std::to_string(optType) + ", Length " + std::to_string(optLen),
                               baseOffset + off, effLen - off);
                        break;
                    }

                    std::string optName = (pppProto == 0xc021 ? lcpOptionName(optType) : ipcpOptionName(optType));
                    std::string optValStr;

                    if (pppProto == 0xc021) { // LCP
                        if (optType == 1 && optLen == 4) {
                            optValStr = ": " + std::to_string(be16(data + off + 2));
                        } else if (optType == 3 && optLen >= 4) {
                            uint16_t authProto = be16(data + off + 2);
                            optValStr = ": " + std::string(pppProtocolName(authProto)) + " (" + hexString(authProto, 4) + ")";
                        } else if (optType == 5 && optLen == 6) {
                            optValStr = ": " + hexString(be32(data + off + 2), 8);
                        }
                    } else if (pppProto == 0x8021) { // IPCP
                        if ((optType == 1 || optType == 3 || optType == 129 || optType == 130 || optType == 131 || optType == 132) &&
                            optLen == 6) {
                            std::string ipStr = ip4(data + off + 2);
                            optValStr = ": " + ipStr;
                            if (optType == 3 && ctx.pack.app_text.empty()) {
                                ctx.pack.app_text = ipStr;
                            } else if (optType == 129 && ctx.pack.app_text2.empty()) {
                                ctx.pack.app_text2 = ipStr;
                            }
                        }
                    }

                    Field &optF = cp.add(optName + optValStr, baseOffset + off, optLen);
                    optF.add("Type: " + std::to_string(optType) + " (" + optName + ")", baseOffset + off, 1);
                    optF.add("Length: " + std::to_string(optLen), baseOffset + off + 1, 1);
                    if (optLen > 2) {
                        optF.add("Data: " + dissect::asciiPreview(data + off + 2, optLen - 2), baseOffset + off + 2, optLen - 2);
                    }

                    off += optLen;
                }
            }
        }
    }
} // namespace

void dissect::dissectPpp(Context &ctx, const char *data, size_t length) {
    if (length < 2) {
        ctx.markMalformed("frame too short for PPP protocol field");
        ctx.pack.protocol = "PPP";
        return;
    }

    uint16_t proto = 0;
    size_t protoHdrLen = 0;

    // RFC 1661: if low-order bit of first octet is 1, it's 1-octet protocol; else 2-octet protocol
    if ((static_cast<uint8_t>(data[0]) & 0x01) != 0) {
        proto = static_cast<uint8_t>(data[0]);
        protoHdrLen = 1;
    } else {
        proto = be16(data);
        protoHdrLen = 2;
    }

    ctx.pack.ppp_protocol = proto;
    ctx.pack.l2_size = static_cast<uint16_t>(ctx.pack.l2_size + protoHdrLen);

    const size_t baseOffset = ctx.offsetOf(data);

    if (ctx.wantFields()) {
        Field &ppp = ctx.addLayer("Point-to-Point Protocol, Protocol: " + std::string(pppProtocolName(proto)) +
                                      " (" + hexString(proto, 4) + ")",
                                  baseOffset, protoHdrLen);
        ppp.add("Protocol: " + std::string(pppProtocolName(proto)) + " (" + hexString(proto, 4) + ")",
                baseOffset, protoHdrLen);
    }

    const char *payload = data + protoHdrLen;
    const size_t payloadLen = length - protoHdrLen;

    // ---------------------------------------------------------------------------------------------
    // Encapsulated Network Layer: IPv4 or IPv6
    // ---------------------------------------------------------------------------------------------
    if (proto == 0x0021) { // IPv4
        dissectIPv4(ctx, payload, payloadLen);
        return;
    }

    if (proto == 0x0057) { // IPv6
        dissectIPv6(ctx, payload, payloadLen);
        return;
    }

    // ---------------------------------------------------------------------------------------------
    // Control Protocols: LCP (0xc021), IPCP (0x8021), IPv6CP (0x8057)
    // ---------------------------------------------------------------------------------------------
    if (proto == 0xc021) {
        dissectControlProtocol(ctx, "LCP", proto, payload, payloadLen, baseOffset + protoHdrLen);
        return;
    }

    if (proto == 0x8021) {
        dissectControlProtocol(ctx, "IPCP", proto, payload, payloadLen, baseOffset + protoHdrLen);
        return;
    }

    if (proto == 0x8057) {
        dissectControlProtocol(ctx, "IPv6CP", proto, payload, payloadLen, baseOffset + protoHdrLen);
        return;
    }

    // ---------------------------------------------------------------------------------------------
    // Authentication: PAP (0xc023), CHAP (0xc223)
    // ---------------------------------------------------------------------------------------------
    if (proto == 0xc023) { // PAP
        ctx.pack.protocol = "PAP";
        if (payloadLen >= 4) {
            uint8_t code = static_cast<uint8_t>(payload[0]);
            uint8_t id = static_cast<uint8_t>(payload[1]);
            uint16_t papLen = be16(payload + 2);
            ctx.pack.app_type = code;
            ctx.pack.app_code = id;
            const char *codeStr = (code == 1 ? "Authenticate-Request" : code == 2 ? "Authenticate-Ack" : code == 3 ? "Authenticate-Nak" : "Unknown");
            ctx.pack.info = std::string(codeStr) + " (id=" + std::to_string(id) + ")";
            if (ctx.wantFields()) {
                Field &pap = ctx.addLayer("Password Authentication Protocol, " + std::string(codeStr), baseOffset + protoHdrLen, std::min<size_t>(payloadLen, papLen));
                pap.add("Code: " + std::string(codeStr) + " (" + std::to_string(code) + ")", baseOffset + protoHdrLen, 1);
                pap.add("Identifier: " + std::to_string(id), baseOffset + protoHdrLen + 1, 1);
                pap.add("Length: " + std::to_string(papLen), baseOffset + protoHdrLen + 2, 2);
            }
        }
        return;
    }

    if (proto == 0xc223) { // CHAP
        ctx.pack.protocol = "CHAP";
        if (payloadLen >= 4) {
            uint8_t code = static_cast<uint8_t>(payload[0]);
            uint8_t id = static_cast<uint8_t>(payload[1]);
            uint16_t chapLen = be16(payload + 2);
            ctx.pack.app_type = code;
            ctx.pack.app_code = id;
            const char *codeStr = (code == 1 ? "Challenge" : code == 2 ? "Response" : code == 3 ? "Success" : code == 4 ? "Failure" : "Unknown");
            ctx.pack.info = std::string(codeStr) + " (id=" + std::to_string(id) + ")";
            if (ctx.wantFields()) {
                Field &chap = ctx.addLayer("Challenge Handshake Authentication Protocol, " + std::string(codeStr), baseOffset + protoHdrLen, std::min<size_t>(payloadLen, chapLen));
                chap.add("Code: " + std::string(codeStr) + " (" + std::to_string(code) + ")", baseOffset + protoHdrLen, 1);
                chap.add("Identifier: " + std::to_string(id), baseOffset + protoHdrLen + 1, 1);
                chap.add("Length: " + std::to_string(chapLen), baseOffset + protoHdrLen + 2, 2);
            }
        }
        return;
    }

    // Other / generic PPP payload
    ctx.pack.protocol = "PPP";
    ctx.pack.info = std::string(pppProtocolName(proto)) + " (" + hexString(proto, 4) + ")";
    if (ctx.wantFields() && payloadLen > 0) {
        ctx.addLayer("PPP Data (" + std::to_string(payloadLen) + " bytes)", baseOffset + protoHdrLen, payloadLen);
    }
}
