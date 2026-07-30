// OSPF (Open Shortest Path First, RFC 2328 v2 / RFC 5340 v3) dissector
#include "ospf.h"

#include <algorithm>
#include <cstring>
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

    inline uint16_t rd16(const uint8_t *p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
    inline uint32_t rd24(const uint8_t *p) { return (static_cast<uint32_t>(p[0]) << 16) | (static_cast<uint32_t>(p[1]) << 8) | p[2]; }
    inline uint32_t rd32(const uint8_t *p) {
        return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | p[3];
    }

    // v2 LS type (RFC 2328 A.4.1) or the v3 LS type's function code (RFC 5340 A.4.2.1, the low 13 bits)
    std::string ospfLsaTypeName(uint16_t type, bool v3 = false) {
        if (v3) {
            switch (type & 0x1fff) {
                case 1: return "Router-LSA";
                case 2: return "Network-LSA";
                case 3: return "Inter-Area-Prefix-LSA";
                case 4: return "Inter-Area-Router-LSA";
                case 5: return "AS-External-LSA";
                case 7: return "NSSA-LSA";
                case 8: return "Link-LSA";
                case 9: return "Intra-Area-Prefix-LSA";
                default: return "LSA Type " + hexString(type, 4);
            }
        }
        switch (type) {
            case 1: return "Router LSA";
            case 2: return "Network LSA";
            case 3: return "Summary LSA (IP Network)";
            case 4: return "Summary LSA (ASBR)";
            case 5: return "AS-External LSA";
            case 7: return "NSSA-External LSA";
            case 9: return "Opaque LSA (link-local)";
            case 10: return "Opaque LSA (area-local)";
            case 11: return "Opaque LSA (AS)";
            default: return "LSA Type " + std::to_string(type);
        }
    }

    const char *v3ScopeName(uint16_t type) {
        switch ((type >> 13) & 3) {
            case 0: return "link-local";
            case 1: return "area";
            case 2: return "AS";
            default: return "reserved";
        }
    }

    // The body of one LSA (the bytes after its 20 byte header), RFC 2328 A.4.2-A.4.5 (v2) or RFC 5340 A.4.3-A.4.10 (v3).
    // `avail` is the part of the LSA inside the packet, `declared` its Length field; an item that runs past `declared` is
    // reported as a problem (the returned text), one that merely runs past `avail` is a capture cut and stops quietly.
    // `node` receives the tree (null in the summary pass, where only the verdict is wanted).
    class LsaBody {
    public:
        LsaBody(const uint8_t *b, size_t avail, size_t declared, bool v3, Field *node, size_t base)
            : b_(b), avail_(avail), declared_(declared), v3_(v3), node_(node), base_(base) {}

        const char *decode(uint16_t type) {
            if (v3_) {
                switch (type & 0x1fff) {
                    case 1: routerV3(); break;
                    case 2: networkV3(); break;
                    case 3: interAreaPrefix(); break;
                    case 4: interAreaRouter(); break;
                    case 5: case 7: external(); break;
                    case 8: linkLsa(); break;
                    case 9: intraAreaPrefix(); break;
                    default: break;
                }
            } else {
                switch (type) {
                    case 1: routerV2(); break;
                    case 2: networkV2(); break;
                    case 3: case 4: summaryV2(); break;
                    case 5: case 7: externalV2(); break;
                    default: break;
                }
            }
            return problem_;
        }

    private:
        const uint8_t *b_;
        size_t avail_, declared_;
        bool v3_;
        Field *node_;
        size_t base_;
        const char *problem_ = nullptr;

        bool fits(size_t at, size_t n) {
            if (at + n > declared_) {
                if (!problem_) problem_ = "OSPF LSA contents longer than the LSA length";
                return false;
            }
            return at + n <= avail_;
        }
        Field *put(Field *parent, const std::string &text, size_t at, size_t n) {
            return node_ ? &(parent ? parent : node_)->add(text, base_ + at, n) : nullptr;
        }
        void leaf(Field *parent, const std::string &text, size_t at, size_t n) { put(parent, text, at, n); }

        // ---- OSPFv2 (RFC 2328 A.4)
        void routerV2() {
            if (!fits(20, 4)) return;
            const uint8_t flags = b_[20];
            const unsigned links = rd16(b_ + 22);
            leaf(nullptr, std::string("Flags: ") + hexString(flags, 2) + ((flags & 4) ? " V" : "") + ((flags & 2) ? " E" : "") + ((flags & 1) ? " B" : ""), 20, 1);
            leaf(nullptr, "Number of Links: " + std::to_string(links), 22, 2);
            size_t at = 24;
            static const char *const linkTypes[] = {"", "Point-to-point", "Transit", "Stub", "Virtual"};
            for (unsigned i = 0; i < links; ++i) {
                if (!fits(at, 12)) return;
                const unsigned type = b_[at + 8], tos = b_[at + 9];
                Field *lf = put(nullptr, "Link: " + formatIpv4(b_ + at) + " (" + (type >= 1 && type <= 4 ? linkTypes[type] : "type " + std::to_string(type)) + ")", at, 12 + tos * 4u > avail_ - at ? avail_ - at : 12 + tos * 4u);
                leaf(lf, "Link ID: " + formatIpv4(b_ + at), at, 4);
                leaf(lf, "Link Data: " + formatIpv4(b_ + at + 4), at + 4, 4);
                leaf(lf, "Link Type: " + std::to_string(type), at + 8, 1);
                leaf(lf, "Number of TOS: " + std::to_string(tos), at + 9, 1);
                leaf(lf, "Metric: " + std::to_string(rd16(b_ + at + 10)), at + 10, 2);
                for (unsigned t = 0; t < tos; ++t) {
                    if (!fits(at + 12 + t * 4u, 4)) return;
                    leaf(lf, "TOS: " + std::to_string(b_[at + 12 + t * 4u]) + ", Metric: " + std::to_string(rd16(b_ + at + 14 + t * 4u)), at + 12 + t * 4u, 4);
                }
                at += 12 + tos * 4u;
            }
        }
        void networkV2() {
            if (!fits(20, 4)) return;
            leaf(nullptr, "Network Mask: " + formatIpv4(b_ + 20), 20, 4);
            if ((declared_ - 24) % 4 != 0 && !problem_) problem_ = "OSPF Network LSA length is not a whole number of routers";
            for (size_t at = 24; at + 4 <= declared_; at += 4) {
                if (!fits(at, 4)) return;
                leaf(nullptr, "Attached Router: " + formatIpv4(b_ + at), at, 4);
            }
        }
        void summaryV2() {
            if (!fits(20, 8)) return;
            leaf(nullptr, "Network Mask: " + formatIpv4(b_ + 20), 20, 4);
            leaf(nullptr, "Metric: " + std::to_string(rd24(b_ + 25)), 24, 4);
            for (size_t at = 28; at + 4 <= declared_; at += 4) {
                if (!fits(at, 4)) return;
                leaf(nullptr, "TOS: " + std::to_string(b_[at]) + ", Metric: " + std::to_string(rd24(b_ + at + 1)), at, 4);
            }
        }
        void externalV2() {
            if (!fits(20, 16)) return;
            leaf(nullptr, "Network Mask: " + formatIpv4(b_ + 20), 20, 4);
            for (size_t at = 24; at + 12 <= declared_; at += 12) {
                if (!fits(at, 12)) return;
                const std::string head = at == 24 ? "" : "TOS " + std::to_string(b_[at] & 0x7f) + " ";
                Field *g = at == 24 ? nullptr : put(nullptr, "Additional TOS: " + std::to_string(b_[at] & 0x7f), at, 12);
                leaf(g, std::string("External Type: ") + ((b_[at] & 0x80) ? "2 (E bit set)" : "1"), at, 1);
                leaf(g, "TOS: " + std::to_string(b_[at] & 0x7f), at, 1);
                leaf(g, head + "Metric: " + std::to_string(rd24(b_ + at + 1)), at + 1, 3);
                leaf(g, head + "Forwarding Address: " + formatIpv4(b_ + at + 4), at + 4, 4);
                leaf(g, head + "External Route Tag: " + hexString(rd32(b_ + at + 8), 8), at + 8, 4);
            }
        }

        // ---- OSPFv3 (RFC 5340 A.4)
        // A prefix as {length, options, 16 bits, address bytes}: the address takes ceil(length / 32) words.
        bool prefix(Field *parent, size_t at, const char *third, std::string &text, size_t &size) {
            if (!fits(at, 4)) return false;
            const unsigned plen = b_[at];
            if (plen > 128) {
                if (!problem_) problem_ = "OSPFv3 prefix length above 128";
                return false;
            }
            const size_t bytes = ((plen + 31) / 32) * 4;
            if (!fits(at + 4, bytes)) return false;
            uint8_t addr[16] = {0};
            std::memcpy(addr, b_ + at + 4, bytes);
            text = network::formatIPv6(addr) + "/" + std::to_string(plen);
            size = 4 + bytes;
            leaf(parent, "Prefix Length: " + std::to_string(plen), at, 1);
            leaf(parent, "Prefix Options: " + hexString(b_[at + 1], 2), at + 1, 1);
            if (third) leaf(parent, std::string(third) + ": " + std::to_string(rd16(b_ + at + 2)), at + 2, 2);
            leaf(parent, "Address Prefix: " + text, at + 4, bytes);
            return true;
        }
        void options(size_t at) { leaf(nullptr, "Options: " + hexString(rd24(b_ + at), 6), at, 3); }

        void routerV3() {
            if (!fits(20, 4)) return;
            const uint8_t flags = b_[20];
            leaf(nullptr, std::string("Flags: ") + hexString(flags, 2) + ((flags & 0x10) ? " Nt" : "") + ((flags & 4) ? " V" : "") + ((flags & 2) ? " E" : "") + ((flags & 1) ? " B" : ""), 20, 1);
            options(21);
            if ((declared_ - 24) % 16 != 0 && !problem_) problem_ = "OSPFv3 Router-LSA length is not a whole number of links";
            static const char *const linkTypes[] = {"", "Point-to-point", "Transit", "Reserved", "Virtual"};
            for (size_t at = 24; at + 16 <= declared_; at += 16) {
                if (!fits(at, 16)) return;
                const unsigned type = b_[at];
                Field *lf = put(nullptr, "Link: " + std::string(type >= 1 && type <= 4 ? linkTypes[type] : "type " + std::to_string(type)) + ", neighbor " + formatIpv4(b_ + at + 12), at, 16);
                leaf(lf, "Type: " + std::to_string(type), at, 1);
                leaf(lf, "Metric: " + std::to_string(rd16(b_ + at + 2)), at + 2, 2);
                leaf(lf, "Interface ID: " + std::to_string(rd32(b_ + at + 4)), at + 4, 4);
                leaf(lf, "Neighbor Interface ID: " + std::to_string(rd32(b_ + at + 8)), at + 8, 4);
                leaf(lf, "Neighbor Router ID: " + formatIpv4(b_ + at + 12), at + 12, 4);
            }
        }
        void networkV3() {
            if (!fits(20, 4)) return;
            options(21);
            if ((declared_ - 24) % 4 != 0 && !problem_) problem_ = "OSPFv3 Network-LSA length is not a whole number of routers";
            for (size_t at = 24; at + 4 <= declared_; at += 4) {
                if (!fits(at, 4)) return;
                leaf(nullptr, "Attached Router: " + formatIpv4(b_ + at), at, 4);
            }
        }
        void interAreaPrefix() {
            if (!fits(20, 4)) return;
            leaf(nullptr, "Metric: " + std::to_string(rd24(b_ + 21)), 21, 3);
            std::string text;
            size_t size = 0;
            Field *pf = nullptr;
            if (node_ && fits(24, 4)) pf = put(nullptr, "Prefix", 24, 4);
            if (prefix(pf, 24, "Reserved", text, size) && pf) {
                pf->text = "Prefix: " + text;
                pf->length = static_cast<uint32_t>(size);
            }
        }
        void interAreaRouter() {
            if (!fits(20, 12)) return;
            options(21);
            leaf(nullptr, "Metric: " + std::to_string(rd24(b_ + 25)), 25, 3);
            leaf(nullptr, "Destination Router ID: " + formatIpv4(b_ + 28), 28, 4);
        }
        void external() {
            if (!fits(20, 4)) return;
            const uint8_t flags = b_[20];
            leaf(nullptr, std::string("Flags: ") + hexString(flags, 2) + ((flags & 4) ? " E" : "") + ((flags & 2) ? " F" : "") + ((flags & 1) ? " T" : ""), 20, 1);
            leaf(nullptr, "Metric: " + std::to_string(rd24(b_ + 21)), 21, 3);
            if (!fits(24, 4)) return;
            const unsigned refType = rd16(b_ + 26);
            std::string text;
            size_t size = 0;
            Field *pf = node_ ? put(nullptr, "Prefix", 24, 4) : nullptr;
            if (!prefix(pf, 24, "Referenced LS Type", text, size)) return;
            if (pf) { pf->text = "Prefix: " + text; pf->length = static_cast<uint32_t>(size); }
            size_t at = 24 + size;
            if (flags & 2) {
                if (!fits(at, 16)) return;
                leaf(nullptr, "Forwarding Address: " + network::formatIPv6(b_ + at), at, 16);
                at += 16;
            }
            if (flags & 1) {
                if (!fits(at, 4)) return;
                leaf(nullptr, "External Route Tag: " + hexString(rd32(b_ + at), 8), at, 4);
                at += 4;
            }
            if (refType != 0) {
                if (!fits(at, 4)) return;
                leaf(nullptr, "Referenced Link State ID: " + formatIpv4(b_ + at), at, 4);
            }
        }
        void linkLsa() {
            if (!fits(20, 24)) return;
            leaf(nullptr, "Router Priority: " + std::to_string(b_[20]), 20, 1);
            options(21);
            leaf(nullptr, "Link-local Interface Address: " + network::formatIPv6(b_ + 24), 24, 16);
            if (!fits(40, 4)) return;
            const uint32_t count = rd32(b_ + 40);
            leaf(nullptr, "Number of Prefixes: " + std::to_string(count), 40, 4);
            size_t at = 44;
            for (uint32_t i = 0; i < count; ++i) {
                std::string text;
                size_t size = 0;
                Field *pf = node_ && fits(at, 4) ? put(nullptr, "Prefix", at, 4) : nullptr;
                if (!prefix(pf, at, "Reserved", text, size)) return;
                if (pf) { pf->text = "Prefix: " + text; pf->length = static_cast<uint32_t>(size); }
                at += size;
            }
        }
        void intraAreaPrefix() {
            if (!fits(20, 12)) return;
            const unsigned count = rd16(b_ + 20);
            leaf(nullptr, "Number of Prefixes: " + std::to_string(count), 20, 2);
            leaf(nullptr, "Referenced LS Type: " + hexString(rd16(b_ + 22), 4), 22, 2);
            leaf(nullptr, "Referenced Link State ID: " + formatIpv4(b_ + 24), 24, 4);
            leaf(nullptr, "Referenced Advertising Router: " + formatIpv4(b_ + 28), 28, 4);
            size_t at = 32;
            for (unsigned i = 0; i < count; ++i) {
                std::string text;
                size_t size = 0;
                Field *pf = node_ && fits(at, 4) ? put(nullptr, "Prefix", at, 4) : nullptr;
                if (!prefix(pf, at, "Metric", text, size)) return;
                if (pf) { pf->text = "Prefix: " + text; pf->length = static_cast<uint32_t>(size); }
                at += size;
            }
        }
    };
} // namespace

void dissect::dissectOspf(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "OSPF";

    auto readU16 = rd16;
    auto readU32 = rd32;

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
    const uint16_t authType = version == 2 && length >= 16 ? readU16(bytes + 14) : 0;
    const uint8_t instanceId = version == 3 ? bytes[14] : 0;
    const bool v3 = version == 3;
    const size_t headerLen = version == 2 ? 24 : 16;

    pack.app_code = version;
    pack.app_type = type;
    pack.app_text = routerId;
    pack.app_text2 = areaId;

    // The packet ends where its own length field says, never later (IP padding, an MD5 digest) and never beyond what
    // was captured: everything below is bounded by `body`.
    const bool lengthValid = (version == 2 || version == 3) && packetLen >= headerLen;
    const size_t body = lengthValid ? std::min<size_t>(packetLen, length) : length;
    const bool complete = lengthValid && length >= packetLen;   // not cut by the snap length: shortfalls are then malformations
    const char *malformed = nullptr;
    auto flag = [&](const char *why) { if (!malformed) malformed = why; };
    if (version != 2 && version != 3) {
        flag("unsupported OSPF version");
    } else if (!lengthValid) {
        flag("OSPF packet length shorter than its header");
    } else if (body < headerLen) {
        flag("OSPF header truncated");
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

    // The fixed part that follows the common header, and where the variable part starts, per packet type (v2 RFC 2328 A.3,
    // v3 RFC 5340 A.3): Hello 20 bytes then neighbors, DD 8 (v3: 12) bytes then LSA headers, LSR 12 byte requests, LSU an LSA
    // count then LSAs, LSAck LSA headers.
    const size_t fixedLen = type == 1 ? 20 : type == 2 ? (v3 ? 12 : 8) : type == 4 ? 4 : 0;
    const size_t listAt = headerLen + fixedLen;
    const bool known = type >= 1 && type <= 5;
    if (known && lengthValid && complete && body < listAt) flag("OSPF packet shorter than the fixed part of its type");

    // LSAs (RFC 2328 12.1 / RFC 5340 A.4.2): Fletcher over the whole LSA except its age, the check bytes sit at offset 16 of
    // the LSA (identical in v2 and v3). LSUs carry whole LSAs, so those are verified; DD and LSAck packets carry only the 20-byte
    // headers, which cannot be checked unless the LSA is that short (Unverified). The worst state of the packet goes to
    // app_flags (Bad, then Unverified, then Good) for ospf.lsa.checksum.status. Every LSA length is bounded by the packet;
    // an LSA body that contradicts its own length is flagged.
    struct Lsa { size_t off, len; uint16_t type; uint8_t state; uint16_t stored, expected; };
    std::vector<Lsa> lsas;
    size_t lsuCount = 0;
    if (lengthValid && body >= listAt && (type == 2 || type == 4 || type == 5)) {
        auto addLsa = [&](size_t off, bool whole) {
            Lsa x{off, readU16(bytes + off + 18), static_cast<uint16_t>(v3 ? readU16(bytes + off + 2) : bytes[off + 3]), kChecksumUnverified, readU16(bytes + off + 16), 0};
            if (x.len < 20) { lsas.push_back(x); flag("OSPF LSA length shorter than its header"); return false; }
            if ((whole || x.len == 20) && off + x.len <= body) {
                const ChecksumResult r = checkFletcher(data + off + 2, x.len - 2, 14);
                x.state = r.state;
                x.expected = r.expected;
            }
            lsas.push_back(x);
            if (whole) {
                if (off + x.len > body) {
                    if (complete) flag("OSPF LSA length beyond the end of the packet");
                } else if (const char *why = LsaBody(bytes + off, x.len, x.len, v3, nullptr, 0).decode(x.type)) {
                    flag(why);
                }
            }
            return true;
        };
        if (type == 2 || type == 5) {
            size_t off = listAt;
            for (; off + 20 <= body; off += 20) addLsa(off, false);
            if (complete && off < body) flag("OSPF packet ends inside an LSA header");
        } else {
            lsuCount = readU32(bytes + headerLen);
            size_t off = listAt;
            for (size_t i = 0; i < lsuCount && off + 20 <= body; ++i) {
                if (!addLsa(off, true)) break;
                off += lsas.back().len;
            }
            if (complete && lsas.size() < lsuCount && !malformed) flag("OSPF LSU shorter than its LSA count");
        }
    }
    if (known && type == 3 && complete && body >= headerLen && (body - headerLen) % 12 != 0) flag("OSPF LSR ends inside a request");
    if (type == 1 && complete && body > listAt && (body - listAt) % 4 != 0) flag("OSPF Hello ends inside a neighbor");
    uint8_t lsaState = kChecksumNone;
    for (const Lsa &x: lsas) {
        auto rank = [](uint8_t st) { return st == kChecksumBad ? 3 : st == kChecksumUnverified ? 2 : st == kChecksumGood ? 1 : 0; };
        if (x.len >= 20 && rank(x.state) > rank(lsaState)) lsaState = x.state;
    }
    pack.app_flags = static_cast<uint16_t>(lsaState | (instanceId << 8));
    pack.app_stream = static_cast<uint32_t>(authType) | (static_cast<uint32_t>(std::min<size_t>(lsas.size(), 0xffff)) << 16);

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
            if (authType == 1) {
                std::string pw;
                for (int i = 16; i < 24; ++i) {
                    if (bytes[i] == 0) break;
                    pw += (bytes[i] >= 0x20 && bytes[i] < 0x7f) ? static_cast<char>(bytes[i]) : '.';
                }
                l.add("Auth Data (simple password): " + pw, o + 16, 8);
            } else if (authType == 2) {
                // RFC 2328 D.3: 16 bits zero, Key ID, Auth Data Length, cryptographic sequence number; the digest follows the packet
                const unsigned authLen = bytes[19];
                Field &af = l.add("Cryptographic Authentication", o + 16, 8);
                af.add("Key ID: " + std::to_string(bytes[18]), o + 18, 1);
                af.add("Auth Data Length: " + std::to_string(authLen), o + 19, 1);
                af.add("Cryptographic Sequence Number: " + std::to_string(readU32(bytes + 20)), o + 20, 4);
                if (lengthValid && authLen > 0 && length > packetLen) {
                    l.add("Authentication Data (" + std::to_string(authLen) + " bytes, after the packet)", o + packetLen, std::min<size_t>(authLen, length - packetLen));
                }
            } else {
                l.add("Authentication Data", o + 16, 8);
            }
        }

        // One LSA (or LSA header) with its Fletcher checksum verdict and, in an LSU, its body.
        auto addLsaNode = [&](Field &parent, const Lsa &x) {
            const auto *lb = bytes + x.off;
            const uint16_t lsaAge = readU16(lb);
            const std::string linkStateId = formatIpv4(lb + 4);
            const std::string advRouter = formatIpv4(lb + 8);
            const uint32_t lsaSeq = readU32(lb + 12);
            const size_t shown = std::min<size_t>(std::max<size_t>(x.len, 20), body - x.off);
            Field &lf = parent.add(std::string(type == 4 ? "LSA: " : "LSA Header: ") + ospfLsaTypeName(x.type, v3) + ", ID: " + linkStateId, o + x.off, shown);
            lf.add("Age: " + std::to_string(lsaAge & 0x7fff) + " seconds" + ((v3 && (lsaAge & 0x8000)) ? " (DoNotAge)" : ""), o + x.off, 2);
            if (v3) {
                lf.add("Type: " + hexString(x.type, 4) + " (" + ospfLsaTypeName(x.type, true) + ", " + v3ScopeName(x.type) + " scope" + ((x.type & 0x8000) ? ", U bit set" : "") + ")", o + x.off + 2, 2);
            } else {
                lf.add("Options: " + hexString(lb[2], 2), o + x.off + 2, 1);
                lf.add("Type: " + std::to_string(x.type) + " (" + ospfLsaTypeName(x.type) + ")", o + x.off + 3, 1);
            }
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
            if (type == 4 && x.len > 20) {
                const size_t avail = std::min<size_t>(x.len, body - x.off);
                LsaBody(lb, avail, x.len, v3, &lf, o + x.off).decode(x.type);
            }
        };

        // Hello (type 1)
        if (type == 1 && body >= listAt) {
            const auto *hb = bytes + headerLen;
            Field &hf = l.add("OSPF Hello Packet", o + headerLen, body - headerLen);
            size_t at = headerLen;
            if (v3) {
                hf.add("Interface ID: " + std::to_string(readU32(hb)), o + at, 4);
                hf.add("Router Priority: " + std::to_string(hb[4]), o + at + 4, 1);
                hf.add("Options: " + hexString((static_cast<uint32_t>(hb[5]) << 16) | (hb[6] << 8) | hb[7], 6), o + at + 5, 3);
                hf.add("Hello Interval: " + std::to_string(readU16(hb + 8)) + " seconds", o + at + 8, 2);
                hf.add("Router Dead Interval: " + std::to_string(readU16(hb + 10)) + " seconds", o + at + 10, 2);
                hf.add("Designated Router: " + formatIpv4(hb + 12), o + at + 12, 4);
                hf.add("Backup Designated Router: " + formatIpv4(hb + 16), o + at + 16, 4);
            } else {
                hf.add("Network Mask: " + formatIpv4(hb), o + at, 4);
                hf.add("Hello Interval: " + std::to_string(readU16(hb + 4)) + " seconds", o + at + 4, 2);
                hf.add("Options: " + hexString(hb[6], 2), o + at + 6, 1);
                hf.add("Router Priority: " + std::to_string(hb[7]), o + at + 7, 1);
                hf.add("Router Dead Interval: " + std::to_string(readU32(hb + 8)) + " seconds", o + at + 8, 4);
                hf.add("Designated Router: " + formatIpv4(hb + 12), o + at + 12, 4);
                hf.add("Backup Designated Router: " + formatIpv4(hb + 16), o + at + 16, 4);
            }
            // Active Neighbor list
            for (size_t n = listAt; n + 4 <= body; n += 4) hf.add("Active Neighbor: " + formatIpv4(bytes + n), o + n, 4);
        }
        // Database Description (type 2)
        else if (type == 2 && body >= listAt) {
            const auto *db = bytes + headerLen;
            Field &df = l.add("OSPF Database Description", o + headerLen, body - headerLen);
            size_t at = headerLen;
            uint8_t ddFlags;
            if (v3) {
                df.add("Options: " + hexString((static_cast<uint32_t>(db[1]) << 16) | (db[2] << 8) | db[3], 6), o + at + 1, 3);
                df.add("Interface MTU: " + std::to_string(readU16(db + 4)), o + at + 4, 2);
                ddFlags = db[7];
                at += 8;
            } else {
                df.add("Interface MTU: " + std::to_string(readU16(db)), o + at, 2);
                df.add("Options: " + hexString(db[2], 2), o + at + 2, 1);
                ddFlags = db[3];
                at += 4;
            }
            std::string flagsStr;
            if (ddFlags & 0x04) flagsStr += "I (Init) ";
            if (ddFlags & 0x02) flagsStr += "M (More) ";
            if (ddFlags & 0x01) flagsStr += "MS (Master/Slave) ";
            df.add("DD Flags: " + hexString(ddFlags, 2) + (flagsStr.empty() ? "" : " [" + flagsStr + "]"), o + at - 1, 1);
            df.add("DD Sequence Number: " + std::to_string(readU32(bytes + at)), o + at, 4);
            for (const Lsa &x: lsas) addLsaNode(df, x);
        }
        // Link State Request (type 3): {LS type, Link State ID, Advertising Router} per request (RFC 2328 A.3.4 / RFC 5340 A.3.5)
        else if (type == 3 && body > headerLen) {
            Field &rf = l.add("OSPF Link State Request", o + headerLen, body - headerLen);
            for (size_t at = headerLen; at + 12 <= body; at += 12) {
                const uint32_t lsType = readU32(bytes + at);
                const std::string typeName = v3 ? ospfLsaTypeName(static_cast<uint16_t>(lsType), true) : ospfLsaTypeName(static_cast<uint16_t>(std::min<uint32_t>(lsType, 0xffff)));
                Field &qf = rf.add("Request: " + typeName + ", ID: " + formatIpv4(bytes + at + 4), o + at, 12);
                qf.add("LS Type: " + (v3 ? hexString(lsType & 0xffff, 4) : std::to_string(lsType)) + " (" + typeName + ")", o + at, 4);
                qf.add("Link State ID: " + formatIpv4(bytes + at + 4), o + at + 4, 4);
                qf.add("Advertising Router: " + formatIpv4(bytes + at + 8), o + at + 8, 4);
            }
        }
        // Link State Update (type 4): the number of LSAs, then the LSAs themselves
        else if (type == 4 && body >= listAt) {
            Field &uf = l.add("OSPF Link State Update", o + headerLen, body - headerLen);
            uf.add("Number of LSAs: " + std::to_string(lsuCount), o + headerLen, 4);
            for (const Lsa &x: lsas) addLsaNode(uf, x);
        }
        // Link State Acknowledgment (type 5): LSA headers only
        else if (type == 5 && body >= listAt) {
            Field &af = l.add("OSPF Link State Acknowledgment", o + headerLen, body - headerLen);
            for (const Lsa &x: lsas) addLsaNode(af, x);
        }
    }
}
