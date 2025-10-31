#include "lldp.h"

#include <string>

#include "protocols.h"
#include "util.h"

namespace dissect {
    namespace {
        using packet::Field;

        bool isPrintable(const char *data, size_t length) {
            if (length == 0) return false;
            for (size_t i = 0; i < length; ++i) {
                const unsigned char c = static_cast<unsigned char>(data[i]);
                if (c < 0x20 || c > 0x7E) return false;
            }
            return true;
        }

        std::string bytesToHex(const char *data, size_t length) {
            static const char digits[] = "0123456789abcdef";
            std::string out;
            out.reserve(length * 2);
            for (size_t i = 0; i < length; ++i) {
                const unsigned char c = static_cast<unsigned char>(data[i]);
                out.push_back(digits[c >> 4]);
                out.push_back(digits[c & 0x0F]);
            }
            return out;
        }

        std::string macString(const char *data, size_t length) {
            static const char digits[] = "0123456789abcdef";
            std::string out;
            for (size_t i = 0; i < length; ++i) {
                if (i != 0) out.push_back(':');
                const unsigned char c = static_cast<unsigned char>(data[i]);
                out.push_back(digits[c >> 4]);
                out.push_back(digits[c & 0x0F]);
            }
            return out;
        }

        const char *chassisIdSubtypeName(uint8_t subtype) {
            switch (subtype) {
            case 1: return "Chassis component";
            case 2: return "Interface alias";
            case 3: return "Port component";
            case 4: return "MAC address";
            case 5: return "Network address";
            case 6: return "Interface name";
            case 7: return "Locally assigned";
            default: return "Reserved";
            }
        }

        const char *portIdSubtypeName(uint8_t subtype) {
            switch (subtype) {
            case 1: return "Interface alias";
            case 2: return "Port component";
            case 3: return "MAC address";
            case 4: return "Network address";
            case 5: return "Interface name";
            case 6: return "Agent circuit ID";
            case 7: return "Locally assigned";
            default: return "Reserved";
            }
        }

        std::string formatLldpId(const char *body, size_t bodyLength, uint8_t subtype, bool chassis) {
            if (bodyLength == 0) return {};
            const bool mac = chassis ? subtype == 4 : subtype == 3;
            const bool network = chassis ? subtype == 5 : subtype == 4;
            if (mac && bodyLength == 6) return macString(body, 6);
            if (network) return bytesToHex(body, bodyLength);
            if (isPrintable(body, bodyLength)) return std::string(body, bodyLength);
            return bytesToHex(body, bodyLength);
        }

        std::string capabilitiesText(uint16_t capabilities) {
            static const char *names[] = {
                "Other", "Repeater", "Bridge", "WLAN Access Point", "Router", "Telephone",
                "DOCSIS", "Station Only", "C-VLAN Component", "S-VLAN Component", "Two-port MAC Relay"};
            std::string out;
            for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i) {
                if (capabilities & (1u << i)) {
                    if (!out.empty()) out += ", ";
                    out += names[i];
                }
            }
            return out;
        }
    } // namespace

    void dissectLldp(Context &ctx, const char *data, size_t length) {
        if (length < 2) {
            ctx.markMalformed("LLDP frame too short");
            if (ctx.pack.protocol.empty()) ctx.pack.protocol = "LLDP";
            return;
        }

        const size_t baseOffset = ctx.offsetOf(data);
        Field *layer = nullptr;
        if (ctx.wantFields()) layer = &ctx.addLayer("Link Layer Discovery Protocol", baseOffset, length);

        std::string chassis;
        std::string port;
        std::string sysname;
        std::string portDescription;
        uint16_t ttl = 0;
        uint16_t enabledCapabilities = 0;

        size_t offset = 0;
        while (offset + 2 <= length) {
            const uint8_t byte0 = static_cast<uint8_t>(data[offset]);
            const uint8_t byte1 = static_cast<uint8_t>(data[offset + 1]);
            const uint8_t type = static_cast<uint8_t>((byte0 >> 1) & 0x7F);
            const size_t tlvLength = ((byte0 & 0x01) << 8) | byte1;

            if (type == 0) {
                if (layer) layer->add("End of LLDPDU", baseOffset + offset, 2);
                break;
            }
            if (offset + 2 + tlvLength > length) {
                ctx.markMalformed("LLDP TLV overruns frame");
                break;
            }

            const char *body = data + offset + 2;
            const size_t bodyLength = tlvLength;
            switch (type) {
            case 1: {
                if (bodyLength >= 1) {
                    const uint8_t subtype = static_cast<uint8_t>(body[0]);
                    chassis = formatLldpId(body + 1, bodyLength - 1, subtype, true);
                    if (layer)
                        layer->add("Chassis ID: " + chassis + " (subtype: " + chassisIdSubtypeName(subtype) + ")",
                                   baseOffset + offset, tlvLength + 2);
                }
                break;
            }
            case 2: {
                if (bodyLength >= 1) {
                    const uint8_t subtype = static_cast<uint8_t>(body[0]);
                    port = formatLldpId(body + 1, bodyLength - 1, subtype, false);
                    if (layer)
                        layer->add("Port ID: " + port + " (subtype: " + portIdSubtypeName(subtype) + ")",
                                   baseOffset + offset, tlvLength + 2);
                }
                break;
            }
            case 3: {
                if (bodyLength >= 2) ttl = be16(body);
                if (layer)
                    layer->add("Time To Live: " + std::to_string(ttl) + " seconds", baseOffset + offset, tlvLength + 2);
                break;
            }
            case 4: {
                const std::string text = isPrintable(body, bodyLength) ? std::string(body, bodyLength)
                                                                       : bytesToHex(body, bodyLength);
                portDescription = text;
                if (layer) layer->add("Port Description: " + text, baseOffset + offset, tlvLength + 2);
                break;
            }
            case 5: {
                const std::string text = isPrintable(body, bodyLength) ? std::string(body, bodyLength)
                                                                       : bytesToHex(body, bodyLength);
                sysname = text;
                if (layer) layer->add("System Name: " + text, baseOffset + offset, tlvLength + 2);
                break;
            }
            case 6: {
                const std::string text = isPrintable(body, bodyLength) ? std::string(body, bodyLength)
                                                                       : bytesToHex(body, bodyLength);
                if (layer) layer->add("System Description: " + text, baseOffset + offset, tlvLength + 2);
                break;
            }
            case 7: {
                if (bodyLength >= 4) enabledCapabilities = be16(body + 2);
                const std::string names = capabilitiesText(enabledCapabilities);
                if (layer)
                    layer->add("System Capabilities: " + (names.empty() ? std::string("none") : names),
                               baseOffset + offset, tlvLength + 2);
                break;
            }
            case 8: {
                if (layer) layer->add("Management Address: " + bytesToHex(body, bodyLength), baseOffset + offset, tlvLength + 2);
                break;
            }
            case 127: {
                std::string oui;
                if (bodyLength >= 3) oui = macString(body, 3);
                if (layer)
                    layer->add("Organizationally Specific TLV (OUI: " + (oui.empty() ? bytesToHex(body, bodyLength) : oui) + ")",
                               baseOffset + offset, tlvLength + 2);
                break;
            }
            default: {
                if (layer) layer->add("TLV type " + std::to_string(type), baseOffset + offset, tlvLength + 2);
                break;
            }
            }
            offset += 2 + tlvLength;
        }

        ctx.pack.app_text = chassis;
        ctx.pack.app_text2 = port;
        ctx.pack.app_code = ttl;
        ctx.pack.app_flags = enabledCapabilities;
        ctx.pack.protocol = "LLDP";
        if (ctx.pack.info.rfind("[Malformed Packet", 0) != 0) {
            if (!sysname.empty())
                ctx.pack.info = "LLDP System Name: " + sysname;
            else if (!chassis.empty() || !port.empty())
                ctx.pack.info = "LLDP Chassis ID: " + chassis + ", Port ID: " + port;
            else
                ctx.pack.info = "LLDP";
        }
    }
} // namespace dissect
