// IGMP (RFC 1112 / RFC 2236 / RFC 3376) dissector: v1, v2, v3
#include "igmp.h"

#include <algorithm>
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

    // RFC 3376 4.1.1 / 4.1.7: Max Resp Code and QQIC below 128 are the value, otherwise 1 eeemmmm = (mmmm | 0x10) << (eee + 3)
    uint32_t decodeFloatCode(uint8_t c) {
        return c < 128 ? c : static_cast<uint32_t>((c & 0x0f) | 0x10) << (((c >> 4) & 7) + 3);
    }

    const char *recordTypeName(uint8_t t) {
        static const char *const names[] = {"", "MODE_IS_INCLUDE", "MODE_IS_EXCLUDE", "CHANGE_TO_INCLUDE_MODE",
                                            "CHANGE_TO_EXCLUDE_MODE", "ALLOW_NEW_SOURCES", "BLOCK_OLD_SOURCES"};
        return t >= 1 && t <= 6 ? names[t] : "Unknown";
    }

    // One IGMPv3 group record (RFC 3376 4.2): type, aux data length (32-bit words), number of sources, group, sources, aux data.
    struct Record {
        size_t off = 0, size = 0, shown = 0; // declared size and the part of it inside the message
        uint8_t type = 0, aux = 0;
        uint16_t sources = 0;
    };

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
    const uint16_t storedCsum = static_cast<uint16_t>((bytes[2] << 8) | bytes[3]);
    const std::string groupAddr = formatIpv4(bytes + 4);
    auto be16 = [&](size_t at) { return static_cast<uint16_t>((bytes[at] << 8) | bytes[at + 1]); };

    // IGMPv3 Query (RFC 3376 4.1): 12 bytes and more; the 8 byte form is v1 (Max Resp Code 0) or v2. Lengths 9..11 are neither.
    const bool queryV3 = type == 0x11 && length >= 12;
    const char *malformed = nullptr;
    uint16_t querySources = 0;
    if (type == 0x11 && length > 8 && length < 12) malformed = "IGMP query neither 8 nor at least 12 bytes";
    if (queryV3) {
        querySources = be16(10);
        if (12 + static_cast<size_t>(querySources) * 4 > length) malformed = "IGMPv3 query source list beyond the message";
    }

    // IGMPv3 Report (RFC 3376 4.2): the group records, walked within the message in both passes; a record or a record
    // count that does not fit is flagged and the record is cut at the end of the message.
    std::vector<Record> records;
    uint16_t recordCount = 0;
    if (type == 0x22) {
        recordCount = be16(6);
        size_t at = 8;
        for (unsigned k = 0; k < recordCount; ++k) {
            if (at + 8 > length) {
                malformed = "IGMPv3 report shorter than its group record count";
                break;
            }
            Record r;
            r.off = at;
            r.type = bytes[at];
            r.aux = bytes[at + 1];
            r.sources = be16(at + 2);
            r.size = 8 + static_cast<size_t>(r.sources) * 4 + static_cast<size_t>(r.aux) * 4;
            r.shown = std::min(r.size, length - at);
            if (r.size > length - at) malformed = "IGMPv3 group record beyond the message";
            records.push_back(r);
            at += r.size;
            if (at >= length && k + 1 < recordCount) {
                malformed = "IGMPv3 report shorter than its group record count";
                break;
            }
        }
    }

    pack.app_type = type;
    pack.app_code = maxRespTime;
    pack.app_text = type == 0x22 ? std::string() : groupAddr;   // bytes 4..7 of a v3 report are reserved/record count
    // igmp.version and igmp.num_records / igmp.num_sources: a query is v1 without a Max Resp Code, v2 with 8 bytes, v3 otherwise
    pack.app_flags = type == 0x22 ? 3 : type == 0x12 ? 1 : type == 0x11 ? (queryV3 ? 3 : maxRespTime == 0 ? 1 : 2) : 2;
    pack.app_stream = type == 0x22 ? recordCount : querySources;

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
        if (queryV3 && querySources > 0) pack.info += ", " + std::to_string(querySources) + " source(s)";
    } else if (type == 0x22) {
        pack.info = "IGMPv3 Membership Report, " + std::to_string(recordCount) + " group record(s)";
    } else {
        pack.info = typeStr + ", group " + groupAddr;
    }
    if (malformed) ctx.markMalformed(malformed);   // after the summary: it replaces it

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("Internet Group Management Protocol (" + typeStr + ")", o, length);

        l.add("Type: " + hexString(type, 2) + " (" + typeStr + ")", o, 1);
        if (type == 0x11) {
            double respSec = static_cast<double>(queryV3 ? decodeFloatCode(maxRespTime) : maxRespTime) / 10.0;
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
            if (queryV3) {
                const uint8_t sq = bytes[8];
                l.add(std::string("Flags: ") + hexString(sq, 2) + " (S=" + ((sq & 8) ? "1" : "0") + ", QRV=" + std::to_string(sq & 7) + ")", o + 8, 1);
                const uint8_t qqic = bytes[9];
                l.add("QQIC: " + std::to_string(decodeFloatCode(qqic)) + " sec (" + std::to_string(qqic) + ")", o + 9, 1);
                l.add("Number of Sources: " + std::to_string(querySources), o + 10, 2);
                for (unsigned k = 0; k < querySources && 12 + (k + 1) * 4 <= length; ++k)
                    l.add("Source Address: " + formatIpv4(bytes + 12 + k * 4), o + 12 + k * 4, 4);
            }
        } else {
            l.add("Reserved", o + 4, 2);
            l.add("Number of Group Records: " + std::to_string(recordCount), o + 6, 2);
            for (const Record &r: records) {
                Field &rf = l.add(std::string("Group Record: ") + recordTypeName(r.type) + " " + formatIpv4(bytes + r.off + 4), o + r.off, r.shown);
                rf.add("Record Type: " + std::to_string(r.type) + " (" + recordTypeName(r.type) + ")", o + r.off, 1);
                rf.add("Aux Data Len: " + std::to_string(r.aux) + " (32-bit words)", o + r.off + 1, 1);
                rf.add("Number of Sources: " + std::to_string(r.sources), o + r.off + 2, 2);
                rf.add("Multicast Address: " + formatIpv4(bytes + r.off + 4), o + r.off + 4, 4);
                size_t at = r.off + 8;
                for (unsigned q = 0; q < r.sources && at + 4 <= r.off + r.shown; ++q, at += 4)
                    rf.add("Source Address: " + formatIpv4(bytes + at), o + at, 4);
                const size_t auxStart = r.off + 8 + static_cast<size_t>(r.sources) * 4;
                if (r.aux > 0 && auxStart < r.off + r.shown)
                    rf.add("Auxiliary Data (" + std::to_string(r.aux * 4) + " bytes)", o + auxStart, r.off + r.shown - auxStart);
            }
        }
    }
}
