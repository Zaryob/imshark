#include "mac_control.h"

#include <string>

#include "protocols.h"
#include "util.h"

namespace dissect {
    namespace {
        using packet::Field;

        const char *macControlOpcodeName(uint16_t opcode) {
            switch (opcode) {
            case 0x0001: return "PAUSE";
            case 0x0101: return "Priority Flow Control (PFC)";
            default: return nullptr;
            }
        }
    } // namespace

    void dissectEthernetControl(Context &ctx, const char *data, size_t length) {
        if (length < 2) {
            ctx.markMalformed("MAC Control frame too short");
            if (ctx.pack.protocol.empty()) ctx.pack.protocol = "MAC Control";
            return;
        }

        const size_t baseOffset = ctx.offsetOf(data);
        const uint16_t opcode = be16(data);
        ctx.pack.app_code = opcode;

        Field *layer = nullptr;
        if (ctx.wantFields()) layer = &ctx.addLayer("Ethernet MAC Control", baseOffset, length);

        std::string info;
        if (opcode == 0x0001) {
            const uint16_t pauseTime = length >= 4 ? be16(data + 2) : 0;
            ctx.pack.app_type = pauseTime;
            if (layer) {
                layer->add("Opcode: PAUSE (0x0001)", baseOffset, 2);
                layer->add("Pause Time: " + std::to_string(pauseTime), baseOffset + 2, 2);
            }
            info = "PAUSE";
        } else if (opcode == 0x0101) {
            const uint16_t classEnable = length >= 4 ? be16(data + 2) : 0;
            ctx.pack.app_type = classEnable;
            if (layer) {
                layer->add("Opcode: Priority Flow Control (0x0101)", baseOffset, 2);
                layer->add("Class Enable Vector: 0x" + hexString(classEnable, 4), baseOffset + 2, 2);
                for (int cls = 0; cls < 8; ++cls) {
                    const size_t quantaOffset = 4 + static_cast<size_t>(cls) * 2;
                    if (quantaOffset + 2 <= length)
                        layer->add("Class " + std::to_string(cls) + " Pause Quanta: " + std::to_string(be16(data + quantaOffset)),
                                   baseOffset + quantaOffset, 2);
                }
            }
            info = "PFC";
        } else {
            const char *name = macControlOpcodeName(opcode);
            const std::string label = name != nullptr ? std::string(name) : "0x" + hexString(opcode, 4);
            if (layer) layer->add("Opcode: " + label, baseOffset, 2);
            info = name != nullptr ? std::string("MAC Control ") + name : "MAC Control opcode " + label;
        }

        ctx.pack.protocol = "MAC Control";
        if (ctx.pack.info.rfind("[Malformed Packet", 0) != 0) ctx.pack.info = info;
    }
} // namespace dissect
