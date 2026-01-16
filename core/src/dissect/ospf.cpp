// OSPF (Open Shortest Path First, RFC 2328 v2 / RFC 5340 v3) dissector
#include "ospf.h"

#include <string>
#include <vector>

#include "checksum.h"
#include "util.h"
#include <filter/fields.h>
#include <network/byteorder.h>

using packet::Field;

namespace {
    using namespace dissect;

    std::string ospfPacketTypeName(uint8_t type) {
        switch (type) {
            case 1: return "Hello";
            case 2: return "Database Description (DD)";
            case 3: return "Link State Request (LSR)";
            case 4: return "Link State Update (LSU)";
            case 5: return "Link State Acknowledgment (LSAck)";
            default: return "Type " + std::to_string(type);
        }
    }

    std::string formatIpv4(const uint8_t *p) {
        return std::to_string(p[0]) + "." + std::to_string(p[1]) + "." +
               std::to_string(p[2]) + "." + std::to_string(p[3]);
    }

    std::string ospfLsaTypeName(uint8_t type) {
        switch (type) {
            case 1: return "Router LSA";
            case 2: return "Network LSA";
            case 3: return "Summary LSA (IP Network)";
            case 4: return "Summary LSA (ASBR)";
            case 5: return "AS-External LSA";
            case 7: return "NSSA-External LSA";
            default: return "LSA Type " + std::to_string(type);
        }
    }

    bool initOspfFilterFields() {
        filter::registerField({"ospf", filter::FieldType::Boolean,
            [](const packet::PacketInfo &p, const filter::Context &, filter::Values &o) {
                if (p.protocol == "OSPF" || p.ip_protocol == 89) o.addU(1);
            }, "Open Shortest Path First"});

        filter::registerField({"ospf.version", filter::FieldType::Unsigned,
            [](const packet::PacketInfo &p, const filter::Context &, filter::Values &o) {
                if (p.protocol == "OSPF") o.addU(p.app_code);
            }, "OSPF Version (2 or 3)"});

        filter::registerField({"ospf.type", filter::FieldType::Unsigned,
            [](const packet::PacketInfo &p, const filter::Context &, filter::Values &o) {
                if (p.protocol == "OSPF") o.addU(p.app_type);
            }, "OSPF Packet Type (1=Hello, 2=DD, 3=LSR, 4=LSU, 5=LSAck)"});

        filter::registerField({"ospf.router_id", filter::FieldType::String,
            [](const packet::PacketInfo &p, const filter::Context &, filter::Values &o) {
                if (p.protocol == "OSPF" && !p.app_text.empty()) o.addS(p.app_text);
            }, "OSPF Router ID"});

        filter::registerField({"ospf.area_id", filter::FieldType::String,
            [](const packet::PacketInfo &p, const filter::Context &, filter::Values &o) {
                if (p.protocol == "OSPF" && !p.app_text2.empty()) o.addS(p.app_text2);
            }, "OSPF Area ID"});

        return true;
    }
} // namespace

void dissect::dissectOspf(Context &ctx, const char *data, size_t length) {
    static const bool registered = initOspfFilterFields();
    (void)registered;

    auto &pack = ctx.pack;
    pack.protocol = "OSPF";

    auto readU16 = [](const uint8_t *p) -> uint16_t {
        return static_cast<uint16_t>((p[0] << 8) | p[1]);
    };
    auto readU32 = [](const uint8_t *p) -> uint32_t {
        return (static_cast<uint32_t>(p[0]) << 24) |
               (static_cast<uint32_t>(p[1]) << 16) |
               (static_cast<uint32_t>(p[2]) << 8)  |
                static_cast<uint32_t>(p[3]);
    };

    if (length < 16) {
        ctx.markMalformed("OSPF header truncated");
        pack.info = "OSPF [Truncated]";
        return;
    }

    const auto *bytes = reinterpret_cast<const uint8_t *>(data);
    const uint8_t version = bytes[0];
    const uint8_t type = bytes[1];
    const uint16_t packetLen = readU16(bytes + 2);
    const std::string routerId = formatIpv4(bytes + 4);
    const std::string areaId = formatIpv4(bytes + 8);
    const uint16_t storedCsum = readU16(bytes + 12);
    const uint16_t authType = (version == 2 && length >= 16) ? readU16(bytes + 14) : 0;

    pack.app_code = version;
    pack.app_type = type;
    pack.app_text = routerId;
    pack.app_text2 = areaId;

    // OSPFv2 checksum calculation: covers entire OSPF packet except the 8-byte authentication field at offset 16
    bool csumGood = false;
    if (version == 2 && authType != 2 && length >= packetLen && packetLen >= 16) {
        // Auth type 2 (Cryptographic) does not use standard checksum; types 0 and 1 do
        // Check standard 16-bit 1's complement over data (zeroing csum field at offset 12..13 and excluding 8-byte auth field)
        uint32_t sum = checksumAdd(0, data, 12);
        sum = checksumAdd(sum, data + 14, (packetLen > 14 ? packetLen - 14 - (authType == 0 || authType == 1 ? 8 : 0) : 0));
        uint16_t expected = static_cast<uint16_t>(~checksumFold(sum));
        csumGood = (expected == storedCsum);
        pack.checksum_state = static_cast<uint8_t>((pack.checksum_state & ~0x0c) |
                              ((csumGood ? kChecksumGood : kChecksumBad) << 2));
    }

    std::string typeStr = ospfPacketTypeName(type);
    pack.info = "OSPFv" + std::to_string(version) + " " + typeStr +
                ", Router ID: " + routerId + ", Area: " + areaId;

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("Open Shortest Path First (v" + std::to_string(version) + ", " + typeStr + ")", o, length);

        l.add("Version: " + std::to_string(version), o, 1);
        l.add("Type: " + std::to_string(type) + " (" + typeStr + ")", o + 1, 1);
        l.add("Packet Length: " + std::to_string(packetLen), o + 2, 2);
        l.add("Router ID: " + routerId, o + 4, 4);
        l.add("Area ID: " + areaId, o + 8, 4);
        Field &cf = l.add("Checksum: " + hexString(storedCsum, 4), o + 12, 2);
        if (version == 2 && authType != 2) {
            cf.add(std::string("[Checksum Status: ") + (csumGood ? "Good" : "Bad") + "]", o + 12, 2);
        }

        if (version == 2 && length >= 24) {
            std::string authName = (authType == 0) ? "Null" : (authType == 1) ? "Simple Password" : (authType == 2) ? "Cryptographic (MD5)" : "Unknown";
            l.add("Auth Type: " + std::to_string(authType) + " (" + authName + ")", o + 14, 2);
            l.add("Authentication Data", o + 16, 8);
        }

        // Parse Hello payload (type 1)
        if (type == 1 && length >= 44 && version == 2) {
            size_t ho = o + 24;
            const auto *hb = bytes + 24;
            std::string netmask = formatIpv4(hb);
            uint16_t helloInt = readU16(hb + 4);
            uint8_t options = hb[6];
            uint8_t prio = hb[7];
            uint32_t deadInt = readU32(hb + 8);
            std::string dr = formatIpv4(hb + 12);
            std::string bdr = formatIpv4(hb + 16);

            Field &hf = l.add("OSPF Hello Packet", ho, length - 24);
            hf.add("Network Mask: " + netmask, ho, 4);
            hf.add("Hello Interval: " + std::to_string(helloInt) + " seconds", ho + 4, 2);
            hf.add("Options: " + hexString(options, 2), ho + 6, 1);
            hf.add("Router Priority: " + std::to_string(prio), ho + 7, 1);
            hf.add("Router Dead Interval: " + std::to_string(deadInt) + " seconds", ho + 8, 4);
            hf.add("Designated Router: " + dr, ho + 12, 4);
            hf.add("Backup Designated Router: " + bdr, ho + 16, 4);

            // Active Neighbor list
            size_t nOffset = 44;
            while (nOffset + 4 <= length) {
                std::string neighbor = formatIpv4(bytes + nOffset);
                hf.add("Active Neighbor: " + neighbor, o + nOffset, 4);
                nOffset += 4;
            }
        }
        // Parse Database Description (type 2)
        else if (type == 2 && length >= 32 && version == 2) {
            size_t ddo = o + 24;
            const auto *db = bytes + 24;
            uint16_t ifMtu = readU16(db);
            uint8_t ddOptions = db[2];
            uint8_t ddFlags = db[3];
            uint32_t ddSeq = readU32(db + 4);

            Field &df = l.add("OSPF Database Description", ddo, length - 24);
            df.add("Interface MTU: " + std::to_string(ifMtu), ddo, 2);
            df.add("Options: " + hexString(ddOptions, 2), ddo + 2, 1);
            std::string flagsStr;
            if (ddFlags & 0x04) flagsStr += "I (Init) ";
            if (ddFlags & 0x02) flagsStr += "M (More) ";
            if (ddFlags & 0x01) flagsStr += "MS (Master/Slave) ";
            df.add("DD Flags: " + hexString(ddFlags, 2) + (flagsStr.empty() ? "" : " [" + flagsStr + "]"), ddo + 3, 1);
            df.add("DD Sequence Number: " + std::to_string(ddSeq), ddo + 4, 4);

            // LSA headers in DD (each LSA header is 20 bytes)
            size_t lsaOff = 32;
            while (lsaOff + 20 <= length) {
                const auto *lb = bytes + lsaOff;
                uint16_t lsaAge = readU16(lb);
                uint8_t lsaType = lb[3];
                std::string linkStateId = formatIpv4(lb + 4);
                std::string advRouter = formatIpv4(lb + 8);
                uint32_t lsaSeq = readU32(lb + 12);
                uint16_t lsaCsum = readU16(lb + 16);
                uint16_t lsaLen = readU16(lb + 18);

                Field &lf = df.add("LSA Header: " + ospfLsaTypeName(lsaType) + ", ID: " + linkStateId, o + lsaOff, 20);
                lf.add("Age: " + std::to_string(lsaAge) + " seconds", o + lsaOff, 2);
                lf.add("Type: " + std::to_string(lsaType) + " (" + ospfLsaTypeName(lsaType) + ")", o + lsaOff + 3, 1);
                lf.add("Link State ID: " + linkStateId, o + lsaOff + 4, 4);
                lf.add("Advertising Router: " + advRouter, o + lsaOff + 8, 4);
                lf.add("Sequence Number: " + hexString(lsaSeq, 8), o + lsaOff + 12, 4);
                lf.add("Checksum: " + hexString(lsaCsum, 4), o + lsaOff + 16, 2);
                lf.add("Length: " + std::to_string(lsaLen), o + lsaOff + 18, 2);

                lsaOff += 20;
            }
        }
    }
}
