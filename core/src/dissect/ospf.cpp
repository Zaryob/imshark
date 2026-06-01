// OSPF (Open Shortest Path First, RFC 2328 v2 / RFC 5340 v3) dissector
#include "ospf.h"

#include <algorithm>
#include <string>
#include <vector>

#include "checksum.h"
#include "util.h"
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
} // namespace

void dissect::dissectOspf(Context &ctx, const char *data, size_t length) {
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
    // v2: AuType (2 bytes) then the 8-byte authentication field; v3: Instance ID and a reserved byte (RFC 5340 A.3.1)
    const uint16_t authType = version == 2 ? readU16(bytes + 14) : 0;
    const uint8_t instanceId = version == 3 ? bytes[14] : 0;
    const size_t headerLen = version == 2 ? 24 : 16;

    pack.app_code = version;
    pack.app_type = type;
    pack.app_text = routerId;
    pack.app_text2 = areaId;

    // The packet ends where its own length field says, never later (IP padding, an MD5 digest) and never beyond what
    // was captured: everything below is bounded by `body`.
    const bool lengthValid = (version == 2 || version == 3) && packetLen >= headerLen;
    const size_t body = lengthValid ? std::min<size_t>(packetLen, length) : length;
    const char *malformed = nullptr;
    if (version != 2 && version != 3) {
        malformed = "unsupported OSPF version";
    } else if (!lengthValid) {
        malformed = "OSPF packet length shorter than its header";
    } else if (body < headerLen) {
        malformed = "OSPF header truncated";
    }

    // Checksum. v2 (RFC 2328 D.4): 16-bit one's complement over the whole packet (the Length field says how much)
    // except the 8-byte authentication field; not computed for cryptographic authentication (AuType 2).
    // v3 (RFC 5340 A.3.1): the IPv6 pseudo header checksum, upper-layer length = OSPF packet length, next header 89.
    uint8_t csumState = kChecksumNone;
    uint16_t csumExpected = 0;
    if (lengthValid) {
        if (version == 2 && authType != 2) {
            if (length < packetLen) {
                csumState = kChecksumUnverified;   // cut by the snap length
            } else {
                uint32_t sum = checksumAdd(0, data, 12);
                sum = checksumAdd(sum, data + 14, 2);
                sum = checksumAdd(sum, data + 24, packetLen - 24);
                csumExpected = static_cast<uint16_t>(~checksumFold(sum));
                csumState = csumExpected == storedCsum ? kChecksumGood : kChecksumBad;
            }
        } else if (version == 3 && ctx.addrs.valid && ctx.addrs.length == 16) {
            const ChecksumResult r = checkTransport(ctx, 89, data, length, packetLen, 12);
            csumState = r.state;
            csumExpected = r.expected;
        }
        setTransportChecksumState(pack, csumState);
    }

    // LSA checksums (RFC 2328 12.1.7): Fletcher over the whole LSA except its age, the check bytes sit at offset 16 of the
    // LSA. LSUs carry whole LSAs, so those are verified; DD and LSAck packets carry only the 20-byte headers, which
    // cannot be checked unless the LSA is that short (Unverified). The worst state of the packet goes to app_flags
    // (Bad, then Unverified, then Good) for ospf.lsa.checksum.status; bodies are not decoded.
    struct Lsa { size_t off, len; uint8_t state; uint16_t stored, expected; };
    std::vector<Lsa> lsas;
    size_t lsuCount = 0;
    if (version == 2 && body >= headerLen + 4) {
        auto addLsa = [&](size_t off, bool whole) {
            Lsa x{off, readU16(bytes + off + 18), kChecksumUnverified, readU16(bytes + off + 16), 0};
            if (x.len < 20) { lsas.push_back(x); return false; }   // not an LSA length: nothing to check
            if ((whole || x.len == 20) && off + x.len <= body) {
                const ChecksumResult r = checkFletcher(data + off + 2, x.len - 2, 14);
                x.state = r.state;
                x.expected = r.expected;
            }
            lsas.push_back(x);
            return true;
        };
        if (type == 2 && body >= 32) {
            for (size_t off = 32; off + 20 <= body; off += 20) addLsa(off, false);
        } else if (type == 5) {
            for (size_t off = 24; off + 20 <= body; off += 20) addLsa(off, false);
        } else if (type == 4) {
            lsuCount = readU32(bytes + 24);
            size_t off = 28;
            for (size_t i = 0; i < lsuCount && off + 20 <= body; ++i) {
                if (!addLsa(off, true)) break;
                off += lsas.back().len;
            }
        }
    }
    uint8_t lsaState = kChecksumNone;
    for (const Lsa &x: lsas) {
        auto rank = [](uint8_t st) { return st == kChecksumBad ? 3 : st == kChecksumUnverified ? 2 : st == kChecksumGood ? 1 : 0; };
        if (x.len >= 20 && rank(x.state) > rank(lsaState)) lsaState = x.state;
    }
    pack.app_flags = lsaState;

    std::string typeStr = ospfPacketTypeName(type);
    pack.info = "OSPFv" + std::to_string(version) + " " + typeStr +
                ", Router ID: " + routerId + ", Area: " + areaId;
    if (lsaState == kChecksumBad) pack.info += " [Bad LSA checksum]";
    if (malformed) ctx.markMalformed(malformed);   // after the summary: it replaces it

    if (ctx.wantFields()) {
        const size_t o = ctx.offsetOf(data);
        Field &l = ctx.addLayer("Open Shortest Path First (v" + std::to_string(version) + ", " + typeStr + ")", o, length);

        l.add("Version: " + std::to_string(version), o, 1);
        l.add("Type: " + std::to_string(type) + " (" + typeStr + ")", o + 1, 1);
        l.add("Packet Length: " + std::to_string(packetLen), o + 2, 2);
        l.add("Router ID: " + routerId, o + 4, 4);
        l.add("Area ID: " + areaId, o + 8, 4);
        Field &cf = l.add("Checksum: " + hexString(storedCsum, 4), o + 12, 2);
        if (csumState != kChecksumNone) {
            cf.add(std::string("[Checksum Status: ") + checksumStateText(csumState) + "]", o + 12, 2);
            if (csumState == kChecksumBad) cf.add("[Expected Checksum: " + hexString(csumExpected, 4) + "]", o + 12, 2);
        }
        if (version == 3) l.add("Instance ID: " + std::to_string(instanceId), o + 14, 1);

        if (version == 2 && body >= 24) {
            std::string authName = (authType == 0) ? "Null" : (authType == 1) ? "Simple Password" : (authType == 2) ? "Cryptographic (MD5)" : "Unknown";
            l.add("Auth Type: " + std::to_string(authType) + " (" + authName + ")", o + 14, 2);
            l.add("Authentication Data", o + 16, 8);
        }

        // One LSA (or LSA header) with its Fletcher checksum verdict.
        auto addLsaNode = [&](Field &parent, const Lsa &x) {
            const auto *lb = bytes + x.off;
            const uint16_t lsaAge = readU16(lb);
            const uint8_t lsaType = lb[3];
            const std::string linkStateId = formatIpv4(lb + 4);
            const std::string advRouter = formatIpv4(lb + 8);
            const uint32_t lsaSeq = readU32(lb + 12);
            const size_t shown = std::min<size_t>(std::max<size_t>(x.len, 20), body - x.off);
            Field &lf = parent.add(std::string(type == 4 ? "LSA: " : "LSA Header: ") + ospfLsaTypeName(lsaType) + ", ID: " + linkStateId, o + x.off, shown);
            lf.add("Age: " + std::to_string(lsaAge) + " seconds", o + x.off, 2);
            lf.add("Type: " + std::to_string(lsaType) + " (" + ospfLsaTypeName(lsaType) + ")", o + x.off + 3, 1);
            lf.add("Link State ID: " + linkStateId, o + x.off + 4, 4);
            lf.add("Advertising Router: " + advRouter, o + x.off + 8, 4);
            lf.add("Sequence Number: " + hexString(lsaSeq, 8), o + x.off + 12, 4);
            Field &lc = lf.add("Checksum: " + hexString(x.stored, 4), o + x.off + 16, 2);
            lc.add(std::string("[Checksum Status: ") + checksumStateText(x.state) + (x.state == kChecksumUnverified && x.len >= 20 ? " (the LSA body is not in this packet or was cut off)" : "") + "]", o + x.off + 16, 2);
            if (x.state == kChecksumBad) {
                lc.add("[Expected Checksum: " + hexString(x.expected, 4) + "]", o + x.off + 16, 2);
                lc.add("[Expert Info (Warning/Checksum): bad OSPF LSA Fletcher checksum]", o + x.off + 16, 2);
            }
            lf.add("Length: " + std::to_string(x.len), o + x.off + 18, 2);
        };

        // Parse Hello payload (type 1)
        if (type == 1 && body >= 44 && version == 2) {
            size_t ho = o + 24;
            const auto *hb = bytes + 24;
            std::string netmask = formatIpv4(hb);
            uint16_t helloInt = readU16(hb + 4);
            uint8_t options = hb[6];
            uint8_t prio = hb[7];
            uint32_t deadInt = readU32(hb + 8);
            std::string dr = formatIpv4(hb + 12);
            std::string bdr = formatIpv4(hb + 16);

            Field &hf = l.add("OSPF Hello Packet", ho, body - 24);
            hf.add("Network Mask: " + netmask, ho, 4);
            hf.add("Hello Interval: " + std::to_string(helloInt) + " seconds", ho + 4, 2);
            hf.add("Options: " + hexString(options, 2), ho + 6, 1);
            hf.add("Router Priority: " + std::to_string(prio), ho + 7, 1);
            hf.add("Router Dead Interval: " + std::to_string(deadInt) + " seconds", ho + 8, 4);
            hf.add("Designated Router: " + dr, ho + 12, 4);
            hf.add("Backup Designated Router: " + bdr, ho + 16, 4);

            // Active Neighbor list
            size_t nOffset = 44;
            while (nOffset + 4 <= body) {
                std::string neighbor = formatIpv4(bytes + nOffset);
                hf.add("Active Neighbor: " + neighbor, o + nOffset, 4);
                nOffset += 4;
            }
        }
        // Parse Database Description (type 2)
        else if (type == 2 && body >= 32 && version == 2) {
            size_t ddo = o + 24;
            const auto *db = bytes + 24;
            uint16_t ifMtu = readU16(db);
            uint8_t ddOptions = db[2];
            uint8_t ddFlags = db[3];
            uint32_t ddSeq = readU32(db + 4);

            Field &df = l.add("OSPF Database Description", ddo, body - 24);
            df.add("Interface MTU: " + std::to_string(ifMtu), ddo, 2);
            df.add("Options: " + hexString(ddOptions, 2), ddo + 2, 1);
            std::string flagsStr;
            if (ddFlags & 0x04) flagsStr += "I (Init) ";
            if (ddFlags & 0x02) flagsStr += "M (More) ";
            if (ddFlags & 0x01) flagsStr += "MS (Master/Slave) ";
            df.add("DD Flags: " + hexString(ddFlags, 2) + (flagsStr.empty() ? "" : " [" + flagsStr + "]"), ddo + 3, 1);
            df.add("DD Sequence Number: " + std::to_string(ddSeq), ddo + 4, 4);

            // LSA headers in DD (each LSA header is 20 bytes)
            for (const Lsa &x: lsas) addLsaNode(df, x);
        }
        // Link State Acknowledgment (type 5): LSA headers only
        else if (type == 5 && body >= 24 && version == 2) {
            Field &af = l.add("OSPF Link State Acknowledgment", o + 24, body - 24);
            for (const Lsa &x: lsas) addLsaNode(af, x);
        }
        // Link State Update (type 4): the number of LSAs, then the LSAs themselves (header and body; bodies not decoded)
        else if (type == 4 && body >= 28 && version == 2) {
            Field &uf = l.add("OSPF Link State Update", o + 24, body - 24);
            uf.add("Number of LSAs: " + std::to_string(lsuCount), o + 24, 4);
            for (const Lsa &x: lsas) addLsaNode(uf, x);
        }
    }
}
