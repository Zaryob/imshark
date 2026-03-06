// IGMP (RFC 1112 / RFC 2236 / RFC 3376) dissector: v1, v2, v3
#include "igmp.h"

#include <string>
#include <vector>

#include "checksum.h"
#include "util.h"
#include <network/byteorder.h>
#include <network/utils.h>

using packet::Field;

namespace {
    using namespace dissect;

    std::string igmpTypeName(uint8_t type) {
        switch (type) {
            case 0x11: return "Membership Query";
            case 0x12: return "IGMPv1 Membership Report";
            case 0x16: return "IGMPv2 Membership Report";
            case 0x17: return "Leave Group";
            case 0x22: return "IGMPv3 Membership Report";
            default: return "Type 0x" + hexString(type, 2);
        }
    }

    std::string formatIpv4(const uint8_t *p) {
        return std::to_string(p[0]) + "." + std::to_string(p[1]) + "." +
               std::to_string(p[2]) + "." + std::to_string(p[3]);
    }
} // namespace

void dissect::dissectIgmp(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "IGMP";

    if (length < 8) {
        ctx.markMalformed("IGMP message truncated");
        pack.info = "IGMP [Truncated]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    const uint8_t type = bytes[0];
    const uint8_t maxRespTime = bytes[1]; // In 1/10th second (IGMPv2/v3 Query)
    const uint16_t storedCsum = network::ntoh16(*reinterpret_cast<const uint16_t *>(data + 2));
    const std::string groupAddr = formatIpv4(bytes + 4);

    pack.app_type = type;
    pack.app_code = maxRespTime;
    pack.app_text = groupAddr;

    // IGMP checksum: standard 16-bit 1's complement over entire IGMP payload (no pseudo-header)
    uint32_t csum = checksumAdd(0, data, length);
    uint16_t folded = checksumFold(csum);
    bool csumGood = (folded == 0 || folded == 0xffff);
    pack.checksum_state = static_cast<uint8_t>((pack.checksum_state & ~0x0c) |
                          ((csumGood ? kChecksumGood : kChecksumBad) << 2));

    std::string typeStr = igmpTypeName(type);
    if (type == 0x11) {
        if (groupAddr == "0.0.0.0") {
            pack.info = "General Membership Query";
        } else {
            pack.info = "Group-Specific Query, group " + groupAddr;
        }
    } else if (type == 0x22) {
        // IGMPv3 report has num_records at bytes 6..7
        if (length >= 8) {
            uint16_t numRecords = network::ntoh16(*reinterpret_cast<const uint16_t *>(data + 6));
            pack.info = "IGMPv3 Membership Report, " + std::to_string(numRecords) + " group record(s)";
        } else {
            pack.info = typeStr;
        }
    } else {
        pack.info = typeStr + ", group " + groupAddr;
    }

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("Internet Group Management Protocol (" + typeStr + ")", o, length);

        l.add("Type: " + hexString(type, 2) + " (" + typeStr + ")", o, 1);
        if (type == 0x11) {
            double respSec = static_cast<double>(maxRespTime) / 10.0;
            l.add("Max Response Time: " + std::to_string(respSec) + " sec (" + std::to_string(maxRespTime) + ")", o + 1, 1);
        } else if (type == 0x22) {
            l.add("Reserved", o + 1, 1);
        } else {
            l.add("Max Response Time / Unused: " + std::to_string(maxRespTime), o + 1, 1);
        }

        Field &csumField = l.add("Checksum: " + hexString(storedCsum, 4) +
                                 (csumGood ? " [Correct]" : " [Incorrect]"), o + 2, 2);
        csumField.add(std::string("[Checksum Status: ") + (csumGood ? "Good" : "Bad") + "]", o + 2, 2);

        if (type != 0x22) {
            l.add("Multicast Address: " + groupAddr, o + 4, 4);
        } else {
            l.add("Reserved", o + 4, 2);
            if (length >= 8) {
                uint16_t numRecords = network::ntoh16(*reinterpret_cast<const uint16_t *>(data + 6));
                l.add("Number of Group Records: " + std::to_string(numRecords), o + 6, 2);
            }
        }
    }
}
