#include "slow_protocols.h"

#include <string>

#include "protocols.h"
#include "util.h"

namespace dissect {
    namespace {
        using packet::Field;

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

        const char *slowSubtypeName(uint8_t subtype) {
            switch (subtype) {
            case 0x01: return "LACP";
            case 0x02: return "Marker Protocol";
            case 0x03: return "Operations, Administration, and Maintenance (OAM)";
            default: return "Reserved";
            }
        }

        std::string lacpStateText(uint8_t state) {
            static const char *names[] = {
                "Activity", "Timeout", "Aggregation", "Synchronization",
                "Collecting", "Distributing", "Defaulted", "Expired"};
            std::string out;
            for (size_t i = 0; i < sizeof(names) / sizeof(*names); ++i) {
                if (state & (1u << i)) {
                    if (!out.empty()) out += ", ";
                    out += names[i];
                }
            }
            return out;
        }

        void parseParticipant(const char *body, size_t bodyLength, Field *layer, size_t tlvOffset, bool actor,
                              uint16_t &outPort, std::string &outSystem, uint8_t &outState) {
            if (bodyLength < 15) return;
            const uint16_t systemPriority = be16(body + 0);
            const std::string system = macString(body + 2, 6);
            const uint16_t key = be16(body + 8);
            const uint16_t portPriority = be16(body + 10);
            const uint16_t port = be16(body + 12);
            const uint8_t state = static_cast<uint8_t>(body[14]);

            outPort = port;
            outSystem = system;
            outState = state;

            if (layer) {
                Field &tlv = layer->add(std::string(actor ? "Actor Information TLV" : "Partner Information TLV"),
                                        tlvOffset, bodyLength + 2);
                const std::string prefix = actor ? "Actor " : "Partner ";
                tlv.add(prefix + "System Priority: " + std::to_string(systemPriority), tlvOffset + 2, 2);
                tlv.add(prefix + "System: " + system, tlvOffset + 4, 6);
                tlv.add(prefix + "Key: " + std::to_string(key), tlvOffset + 10, 2);
                tlv.add(prefix + "Port Priority: " + std::to_string(portPriority), tlvOffset + 12, 2);
                tlv.add(prefix + "Port: " + std::to_string(port), tlvOffset + 14, 2);
                tlv.add(prefix + "State: 0x" + hexString(state, 2) + " (" + lacpStateText(state) + ")", tlvOffset + 16, 1);
            }
        }

        void dissectLacp(Context &ctx, const char *data, size_t length, size_t baseOffset) {
            if (length < 2) {
                ctx.markMalformed("LACP frame too short");
                if (ctx.pack.protocol.empty()) ctx.pack.protocol = "LACP";
                return;
            }

            const uint8_t version = static_cast<uint8_t>(data[1]);
            Field *layer = nullptr;
            if (ctx.wantFields()) layer = &ctx.addLayer("Link Aggregation Control Protocol", baseOffset, length);
            if (layer) layer->add("Version: " + std::to_string(version), baseOffset + 1, 1);

            uint16_t actorPort = 0;
            uint16_t partnerPort = 0;
            std::string actorSystem;
            std::string partnerSystem;
            uint8_t actorState = 0;
            uint8_t partnerState = 0;

            size_t offset = 2;
            while (offset + 2 <= length) {
                const uint8_t tlvType = static_cast<uint8_t>(data[offset]);
                const uint8_t tlvLength = static_cast<uint8_t>(data[offset + 1]);
                if (tlvType == 0) {
                    if (layer) layer->add("Terminator", baseOffset + offset, 2);
                    break;
                }
                if (tlvLength < 2 || offset + tlvLength > length) {
                    ctx.markMalformed("LACP TLV overruns frame");
                    break;
                }
                const char *body = data + offset + 2;
                const size_t bodyLength = tlvLength - 2;
                if (tlvType == 1)
                    parseParticipant(body, bodyLength, layer, baseOffset + offset, true, actorPort, actorSystem, actorState);
                else if (tlvType == 2)
                    parseParticipant(body, bodyLength, layer, baseOffset + offset, false, partnerPort, partnerSystem, partnerState);
                else if (tlvType == 3) {
                    if (layer) layer->add("Collector Information TLV", baseOffset + offset, tlvLength);
                } else if (layer) {
                    layer->add("TLV type " + std::to_string(tlvType), baseOffset + offset, tlvLength);
                }
                offset += tlvLength;
            }

            ctx.pack.app_text = actorSystem;
            ctx.pack.app_text2 = partnerSystem;
            ctx.pack.app_type = actorPort;
            ctx.pack.app_code = partnerPort;
            ctx.pack.app_flags = static_cast<uint16_t>(actorState) | (static_cast<uint16_t>(partnerState) << 8);
            ctx.pack.protocol = "LACP";
            if (ctx.pack.info.rfind("[Malformed Packet", 0) != 0) ctx.pack.info = "LACP";
        }
    } // namespace

    void dissectSlowProtocols(Context &ctx, const char *data, size_t length) {
        if (length < 1) {
            ctx.markMalformed("Slow protocol frame too short");
            if (ctx.pack.protocol.empty()) ctx.pack.protocol = "Slow Protocols";
            return;
        }

        const uint8_t subtype = static_cast<uint8_t>(data[0]);
        if (subtype == 0x01) {
            dissectLacp(ctx, data, length, ctx.offsetOf(data));
            return;
        }

        const size_t baseOffset = ctx.offsetOf(data);
        if (ctx.wantFields())
            ctx.addLayer(std::string("Slow Protocols, Subtype: ") + slowSubtypeName(subtype), baseOffset, length);
        ctx.pack.protocol = "Slow Protocols";
        if (ctx.pack.info.rfind("[Malformed Packet", 0) != 0)
            ctx.pack.info = std::string("Slow Protocols ") + slowSubtypeName(subtype);
    }
} // namespace dissect
