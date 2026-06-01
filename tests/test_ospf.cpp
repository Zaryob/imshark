#include <gtest/gtest.h>

#include <functional>

#include <core.h>
#include <filter/filter.h>

#include <dissect/checksum.h>

#include "frame_sweep.h"
#include "support.h"

using support::parse;

namespace {
    // Helper to wrap OSPF inside IPv4 + Ethernet
    // IPv4 src=10.0.0.1, dst=224.0.0.5 (AllSPFRouters), proto=89
    std::vector<char> makeOspfPacket(const std::vector<uint8_t> &ospfPayload) {
        std::vector<uint8_t> frame = {
            0x01, 0x00, 0x5e, 0x00, 0x00, 0x05,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x08, 0x00
        };

        size_t ipTotalLen = 20 + ospfPayload.size();
        std::vector<uint8_t> ip = {
            0x45, 0xc0, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff), // DSCP CS6 (Internetwork Control)
            0x00, 0x01, 0x00, 0x00,
            1, 89, 0x00, 0x00, // TTL=1, proto=89 (OSPF)
            10, 0, 0, 1,
            224, 0, 0, 5
        };

        uint32_t csum = 0;
        for (size_t i = 0; i < ip.size(); i += 2) csum += (ip[i] << 8) | ip[i + 1];
        while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
        uint16_t folded = static_cast<uint16_t>(~csum);
        ip[10] = static_cast<uint8_t>(folded >> 8);
        ip[11] = static_cast<uint8_t>(folded & 0xff);

        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.insert(frame.end(), ospfPayload.begin(), ospfPayload.end());
        return std::vector<char>(frame.begin(), frame.end());
    }
} // namespace

TEST(Ospf, HelloPacket) {
    // OSPFv2 Hello: 24-byte header + 20-byte Hello body = 44 bytes total
    // Version=2, Type=1 (Hello), Length=44 (0x002C)
    // Router ID: 192.168.1.1 (C0 A8 01 01)
    // Area ID: 0.0.0.0 (Backbone)
    // Auth Type: 0 (Null)
    std::vector<uint8_t> ospf = {
        0x02, 0x01, 0x00, 0x2c,
        0xc0, 0xa8, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,             // checksum placeholder
        0x00, 0x00,             // Auth Type = 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Auth data
        // Hello body:
        0xff, 0xff, 0xff, 0x00, // Netmask 255.255.255.0
        0x00, 0x0a,             // Hello Interval = 10 sec
        0x02,                   // Options (E-bit)
        0x01,                   // Router Priority = 1
        0x00, 0x00, 0x00, 0x28, // Dead Interval = 40 sec
        0xc0, 0xa8, 0x01, 0x01, // DR: 192.168.1.1
        0x00, 0x00, 0x00, 0x00  // BDR: 0.0.0.0
    };

    // Calculate OSPF checksum (RFC 2328: standard checksum excluding 8-byte auth field)
    uint32_t csum = 0;
    // bytes 0..11 and 14..15 (skip csum at 12..13 and auth at 16..23)
    for (size_t i = 0; i < 12; i += 2) csum += (ospf[i] << 8) | ospf[i + 1];
    csum += (ospf[14] << 8) | ospf[15];
    for (size_t i = 24; i < ospf.size(); i += 2) csum += (ospf[i] << 8) | ospf[i + 1];
    while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
    uint16_t folded = static_cast<uint16_t>(~csum);
    ospf[12] = static_cast<uint8_t>(folded >> 8);
    ospf[13] = static_cast<uint8_t>(folded & 0xff);

    auto pkt = parse(makeOspfPacket(ospf));
    EXPECT_EQ(pkt.protocol, "OSPF");
    EXPECT_EQ(pkt.app_code, 2); // Version 2
    EXPECT_EQ(pkt.app_type, 1); // Type 1 (Hello)
    EXPECT_EQ(pkt.app_text, "192.168.1.1");
    EXPECT_EQ(pkt.app_text2, "0.0.0.0");
    EXPECT_NE(pkt.info.find("Hello"), std::string::npos);

    // Filter check
    auto f = filter::Filter::compile("ospf && ospf.version == 2 && ospf.type == 1 && ospf.router_id == \"192.168.1.1\"");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}

TEST(Ospf, DatabaseDescriptionPacket) {
    // OSPFv2 DD: 24-byte header + 8-byte DD body = 32 bytes total
    // Version=2, Type=2 (DD), Length=32 (0x0020)
    std::vector<uint8_t> ospf = {
        0x02, 0x02, 0x00, 0x20,
        10, 0, 0, 1,            // Router ID 10.0.0.1
        0, 0, 0, 1,             // Area 0.0.0.1
        0, 0,                   // Checksum placeholder
        0, 0,                   // Auth Type = 0
        0, 0, 0, 0, 0, 0, 0, 0, // Auth data
        // DD body:
        0x05, 0xdc,             // MTU 1500
        0x02,                   // Options
        0x07,                   // Flags: I + M + MS
        0x00, 0x00, 0x12, 0x34  // DD Sequence Number = 0x1234
    };

    auto pkt = parse(makeOspfPacket(ospf));
    EXPECT_EQ(pkt.protocol, "OSPF");
    EXPECT_EQ(pkt.app_type, 2); // DD
    EXPECT_NE(pkt.info.find("Database Description"), std::string::npos);
}

namespace {
    using framesweep::Bytes;

    // Hello (RFC 2328 A.3.2) from 192.168.1.1, area 0, AuType 0, mask 255.255.255.0, hello 10 s, dead 40 s, DR 192.168.1.1
    Bytes helloV2(uint16_t csum) {
        Bytes b = {0x02, 0x01, 0x00, 0x2c, 0xc0, 0xa8, 0x01, 0x01, 0, 0, 0, 0, static_cast<uint8_t>(csum >> 8), static_cast<uint8_t>(csum & 0xff), 0, 0,
                   0, 0, 0, 0, 0, 0, 0, 0,
                   0xff, 0xff, 0xff, 0x00, 0x00, 0x0a, 0x02, 0x01, 0x00, 0x00, 0x00, 0x28, 0xc0, 0xa8, 0x01, 0x01, 0, 0, 0, 0};
        return b;
    }

    packet::PacketInfo ospfV2(const Bytes &ospf) {
        return framesweep::parseEthernet(framesweep::ethernet(0x0800, framesweep::ipv4Packet(89, ospf, {10, 0, 0, 1}, {224, 0, 0, 5})));
    }

    // Hello (RFC 5340 A.3.2): header of 16 bytes (Instance ID 0), interface 1, priority 1, options 0x13, hello 10, dead 40, DR 1.1.1.1
    Bytes helloV3(uint16_t csum) {
        return {0x03, 0x01, 0x00, 0x24, 1, 1, 1, 1, 0, 0, 0, 0, static_cast<uint8_t>(csum >> 8), static_cast<uint8_t>(csum & 0xff), 0, 0,
                0, 0, 0, 1, 1, 0, 0, 0x13, 0, 10, 0, 40, 1, 1, 1, 1, 0, 0, 0, 0};
    }

    packet::PacketInfo ospfV3(const Bytes &ospf) {
        const Bytes src = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        const Bytes dst = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5};
        return framesweep::parseEthernet(framesweep::ethernet(0x86dd, framesweep::ipv6Packet(89, ospf, src, dst)));
    }

    uint8_t csumState(const packet::PacketInfo &p) { return dissect::transportChecksumState(p); }
} // namespace

// Expected checksums: independent Python (stdlib only) one's complement sums per RFC 2328 D.4, over the whole packet
// except the 8-byte authentication field (bytes 16..23) with the checksum field zero:
//   def cs(b): b = b + b'\0' * (len(b) % 2); s = sum((b[i] << 8) | b[i+1] for i in range(0, len(b), 2)); fold; return ~s & 0xffff
//   cs(hello[:16] + hello[24:]) == 0x794b
TEST(Ospf, V2ChecksumFollowsRfc2328D4) {
    EXPECT_EQ(csumState(ospfV2(helloV2(0x794b))), dissect::kChecksumGood);
    EXPECT_EQ(csumState(ospfV2(helloV2(0x794c))), dissect::kChecksumBad);

    // the authentication field is not covered: changing it keeps the checksum Good
    Bytes auth = helloV2(0x794b);
    for (int i = 16; i < 24; ++i) auth[i] = 0xa5;
    EXPECT_EQ(csumState(ospfV2(auth)), dissect::kChecksumGood);

    // the last bytes of the packet are covered (the old code dropped the final 8): flipping one is detected
    Bytes tail = helloV2(0x794b);
    tail[43] ^= 0x01;
    EXPECT_EQ(csumState(ospfV2(tail)), dissect::kChecksumBad);

    // a neighbor appended, Length 48: cs(...) == 0x6f3e
    Bytes withNeighbor = helloV2(0x6f3e);
    withNeighbor[3] = 0x30;
    withNeighbor.insert(withNeighbor.end(), {10, 0, 0, 9});
    EXPECT_EQ(csumState(ospfV2(withNeighbor)), dissect::kChecksumGood);

    // an odd Length (45) is padded with a zero byte for the sum: cs(...) == 0x724a
    Bytes odd = helloV2(0x724a);
    odd[3] = 0x2d;
    odd.push_back(0x07);
    EXPECT_EQ(csumState(ospfV2(odd)), dissect::kChecksumGood);

    // Database Description, Length 32: cs(...) == 0xd9c4
    Bytes dd = {0x02, 0x02, 0x00, 0x20, 10, 0, 0, 1, 0, 0, 0, 1, 0xd9, 0xc4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05, 0xdc, 0x02, 0x07, 0x00, 0x00, 0x12, 0x34};
    EXPECT_EQ(csumState(ospfV2(dd)), dissect::kChecksumGood);

    // cut by the snap length: cannot be decided
    Bytes cut = helloV2(0x794b);
    cut.resize(40);
    EXPECT_EQ(csumState(ospfV2(cut)), dissect::kChecksumUnverified);
}

// OSPFv3 (RFC 5340 A.3.1): checksum over the IPv6 pseudo header (src fe80::1, dst ff02::5, length 36, next header 89)
// and the packet. Python: cs(src + dst + (36).to_bytes(4, 'big') + bytes([0, 0, 0, 89]) + pkt) == 0xf989
TEST(Ospf, V3ChecksumUsesTheIpv6PseudoHeader) {
    const auto good = ospfV3(helloV3(0xf989));
    EXPECT_EQ(csumState(good), dissect::kChecksumGood);
    EXPECT_EQ(good.app_code, 3);
    EXPECT_EQ(good.app_text, "1.1.1.1");
    EXPECT_EQ(csumState(ospfV3(helloV3(0xf98a))), dissect::kChecksumBad);
    // the plain (pseudo header less) sum of the packet is not what v3 stores
    Bytes noPseudo = helloV3(0);
    EXPECT_NE(csumState(ospfV3(noPseudo)), dissect::kChecksumGood);
}

// C-1: a Length below the header (0x14 = 20) made the checksum read about 2^64 bytes. Every Length value is safe.
TEST(Ospf, EveryPacketLengthValueIsSafe) {
    for (uint32_t len = 0; len <= 0xffff; ++len) {
        Bytes b = helloV2(0x794b);
        b[2] = static_cast<uint8_t>(len >> 8);
        b[3] = static_cast<uint8_t>(len & 0xff);
        const auto p = ospfV2(b);
        EXPECT_EQ(p.protocol, "OSPF");
        if (len < 24) EXPECT_NE(p.info.find("OSPF"), std::string::npos);
    }
    Bytes shortLen = helloV2(0x794b);
    shortLen[2] = 0x00;
    shortLen[3] = 0x14;
    const auto p = ospfV2(shortLen);
    EXPECT_EQ(p.protocol, "OSPF");
    EXPECT_EQ(csumState(p), dissect::kChecksumNone);
    EXPECT_NE(p.info.find("[Malformed Packet"), std::string::npos) << p.info;
    framesweep::expectInside(p, 14 + 20 + shortLen.size(), "length 20");
}

// I-3: bytes after the packet's own Length (IP padding, an MD5 digest) are not neighbors
TEST(Ospf, TrailingBytesBeyondTheLengthAreNotNeighbors) {
    Bytes b = helloV2(0x794b);
    b.insert(b.end(), {1, 2, 3, 4, 5, 6, 7, 8});
    const auto p = ospfV2(b);
    EXPECT_EQ(csumState(p), dissect::kChecksumGood);
    // reparse with the details builder tree: no Active Neighbor
    std::function<bool(const packet::Field &)> hasNeighbor = [&](const packet::Field &f) {
        if (f.text.rfind("Active Neighbor", 0) == 0) return true;
        for (const auto &c: f.children) if (hasNeighbor(c)) return true;
        return false;
    };
    for (const auto &f: p.fields) EXPECT_FALSE(hasNeighbor(f));
}

namespace {
    // Fills the OSPFv2 packet checksum (plain RFC 1071 sum without the authentication field), so only the LSA checksums vary.
    Bytes withPacketChecksum(Bytes b) {
        b[12] = b[13] = 0;
        Bytes c(b.begin(), b.begin() + 16);
        c.insert(c.end(), b.begin() + 24, b.end());
        uint32_t sum = 0;
        for (size_t i = 0; i < c.size(); i += 2) sum += (c[i] << 8) | (i + 1 < c.size() ? c[i + 1] : 0);
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        b[12] = static_cast<uint8_t>(~sum >> 8);
        b[13] = static_cast<uint8_t>(~sum);
        return b;
    }

    Bytes ospfCommon(uint8_t type, size_t total) {
        return {0x02, type, static_cast<uint8_t>(total >> 8), static_cast<uint8_t>(total), 10, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    }

    // LSA checksums come from stdlib Python (RFC 2328 12.1.7, RFC 905 Annex B; the script is in checksum tests):
    //   header-only Router LSA  00 01 02 01 01010101 01010101 80000001 .... 0014 -> 0x2b34
    //   Router LSA with one link (length 36, body 00000001 02020202 0a000001 0300000a) -> 0xf33a
    //   header 0e10 02 05 c0a80000 01010101 80000007 .... 0014 -> 0x638c
    Bytes lsaHeader(uint16_t age, uint8_t type, uint16_t csum, uint16_t len, uint32_t seq = 0x80000001u) {
        return {static_cast<uint8_t>(age >> 8), static_cast<uint8_t>(age), 2, type, 1, 1, 1, 1, 1, 1, 1, 1,
                static_cast<uint8_t>(seq >> 24), static_cast<uint8_t>(seq >> 16), static_cast<uint8_t>(seq >> 8), static_cast<uint8_t>(seq),
                static_cast<uint8_t>(csum >> 8), static_cast<uint8_t>(csum), static_cast<uint8_t>(len >> 8), static_cast<uint8_t>(len)};
    }
    Bytes routerLsa(uint16_t csum) {
        Bytes b = lsaHeader(1, 1, csum, 36);
        b[2] = 2;
        b.insert(b.end(), {0, 0, 0, 1, 2, 2, 2, 2, 10, 0, 0, 1, 3, 0, 0, 10});
        return b;
    }
    Bytes cat(Bytes a, const Bytes &b) { a.insert(a.end(), b.begin(), b.end()); return a; }

    Bytes lsUpdate(const Bytes &lsa1, const Bytes &lsa2) {
        Bytes b = ospfCommon(4, 24 + 4 + lsa1.size() + lsa2.size());
        b.insert(b.end(), {0, 0, 0, 2});
        return withPacketChecksum(cat(cat(b, lsa1), lsa2));
    }
    packet::PacketInfo parseOspf(const Bytes &ospf) { return ospfV2(ospf); }
    bool lsaMatches(const std::string &expr, const packet::PacketInfo &p) {
        auto f = filter::Filter::compile(expr);
        EXPECT_TRUE(f.ok) << expr;
        return f.ok && f.filter.matches(p);
    }
    const packet::Field *findField(const std::vector<packet::Field> &nodes, const std::string &prefix) {
        for (const auto &n: nodes) {
            if (n.text.rfind(prefix, 0) == 0) return &n;
            if (auto *c = findField(n.children, prefix)) return c;
        }
        return nullptr;
    }
} // namespace

TEST(Ospf, LsUpdateVerifiesTheLsaFletcherChecksums) {
    const Bytes good = lsUpdate(lsaHeader(0, 1, 0x2b34, 20), routerLsa(0xf33a));
    const auto p = parseOspf(good);
    EXPECT_EQ(csumState(p), dissect::kChecksumGood);   // the packet checksum is right too
    EXPECT_TRUE(lsaMatches("ospf.type == 4 && ospf.lsa.checksum.status == 1", p));
    EXPECT_NE(findField(p.fields, "Number of LSAs: 2"), nullptr);
    EXPECT_NE(findField(p.fields, "LSA: Router LSA, ID: 1.1.1.1"), nullptr);
    EXPECT_NE(findField(p.fields, "[Checksum Status: Good]"), nullptr);
    EXPECT_EQ(p.info.find("Bad LSA"), std::string::npos);

    // the age is not covered: the same LSAs aged by an hour still verify
    Bytes aged = good;
    aged[28] = 0x0e; aged[29] = 0x10;
    EXPECT_TRUE(lsaMatches("ospf.lsa.checksum.status == 1", parseOspf(withPacketChecksum(aged))));

    // one flipped body byte of the second LSA: bad, with the expected value and an expert line
    Bytes badBody = good;
    badBody[28 + 20 + 30] ^= 0x04;
    const auto bb = parseOspf(withPacketChecksum(badBody));
    EXPECT_TRUE(lsaMatches("ospf.lsa.checksum.status == 0", bb));
    EXPECT_NE(findField(bb.fields, "[Expected Checksum: "), nullptr);
    EXPECT_NE(findField(bb.fields, "[Expert Info (Warning/Checksum): bad OSPF LSA Fletcher checksum]"), nullptr);
    EXPECT_NE(bb.info.find("[Bad LSA checksum]"), std::string::npos);

    // a wrong stored checksum on the first LSA
    const auto wrong = parseOspf(lsUpdate(lsaHeader(0, 1, 0x2b35, 20), routerLsa(0xf33a)));
    EXPECT_TRUE(lsaMatches("ospf.lsa.checksum.status == 0", wrong));
    EXPECT_NE(findField(wrong.fields, "[Expected Checksum: 0x2b34]"), nullptr);

    // cut inside the second LSA: the first is still checked, the whole stays Unverified
    Bytes cut = good;
    cut.resize(cut.size() - 6);
    EXPECT_TRUE(lsaMatches("ospf.lsa.checksum.status == 2", parseOspf(cut)));
    Bytes cutBad = lsUpdate(lsaHeader(0, 1, 0x2b35, 20), routerLsa(0xf33a));
    cutBad.resize(cutBad.size() - 6);
    EXPECT_TRUE(lsaMatches("ospf.lsa.checksum.status == 0", parseOspf(cutBad)));
}

TEST(Ospf, LsAckAndDatabaseDescriptionCarryHeadersOnly) {
    // headers of LSAs longer than 20 bytes cannot be verified without their bodies: Unverified, never Bad
    Bytes ack = ospfCommon(5, 24 + 40);
    ack = withPacketChecksum(cat(cat(ack, lsaHeader(0x0e10, 5, 0x638c, 36)), lsaHeader(1, 1, 0xf33a, 36)));
    const auto a = parseOspf(ack);
    EXPECT_EQ(a.app_type, 5);
    EXPECT_TRUE(lsaMatches("ospf.lsa.checksum.status == 2", a));
    EXPECT_NE(findField(a.fields, "OSPF Link State Acknowledgment"), nullptr);
    EXPECT_NE(findField(a.fields, "LSA Header: AS-External LSA, ID: 1.1.1.1"), nullptr);

    // a 20-byte LSA is its own header, so it is checked (here: a header with a wrong checksum, then a right one)
    Bytes ack20 = withPacketChecksum(cat(cat(ospfCommon(5, 24 + 40), lsaHeader(0, 1, 0x2b00, 20)), lsaHeader(0, 1, 0x2b34, 20)));
    EXPECT_TRUE(lsaMatches("ospf.lsa.checksum.status == 0", parseOspf(ack20)));
    Bytes ack20Good = withPacketChecksum(cat(ospfCommon(5, 24 + 20), lsaHeader(0, 1, 0x2b34, 20)));
    EXPECT_TRUE(lsaMatches("ospf.lsa.checksum.status == 1", parseOspf(ack20Good)));

    Bytes dd = ospfCommon(2, 32 + 20);
    dd.insert(dd.end(), {0x05, 0xdc, 0x02, 0x07, 0x00, 0x00, 0x12, 0x34});
    const auto d = parseOspf(withPacketChecksum(cat(dd, lsaHeader(0, 1, 0x2b34, 20))));
    EXPECT_TRUE(lsaMatches("ospf.lsa.checksum.status == 1", d));
    EXPECT_NE(findField(d.fields, "LSA Header: Router LSA, ID: 1.1.1.1"), nullptr);

    // no LSAs: no status
    EXPECT_FALSE(lsaMatches("ospf.lsa.checksum.status == 1 || ospf.lsa.checksum.status == 0 || ospf.lsa.checksum.status == 2", ospfV2(helloV2(0x794b))));
}

TEST(Ospf, TruncationAndMutationStayInsideTheFrame) {
    Bytes dd = {0x02, 0x02, 0x00, 0x34, 10, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x05, 0xdc, 0x02, 0x07, 0x00, 0x00, 0x12, 0x34,
                0x00, 0x01, 0x02, 0x01, 1, 1, 1, 1, 1, 1, 1, 1, 0x80, 0, 0, 1, 0x12, 0x34, 0x00, 0x14};
    Bytes withNeighbors = helloV2(0x794b);
    withNeighbors.insert(withNeighbors.end(), {10, 0, 0, 9, 10, 0, 0, 10});
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(89, helloV2(0x794b), {10, 0, 0, 1}, {224, 0, 0, 5})), 0x05bf0001u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(89, withNeighbors, {10, 0, 0, 1}, {224, 0, 0, 5})), 0x05bf0002u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(89, dd, {10, 0, 0, 1}, {224, 0, 0, 5})), 0x05bf0003u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(89, lsUpdate(lsaHeader(0, 1, 0x2b34, 20), routerLsa(0xf33a)), {10, 0, 0, 1}, {224, 0, 0, 5})), 0x05bf0005u);
    Bytes ackSweep = withPacketChecksum(cat(cat(ospfCommon(5, 24 + 40), lsaHeader(0x0e10, 5, 0x638c, 36)), lsaHeader(0, 1, 0x2b34, 20)));
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(89, ackSweep, {10, 0, 0, 1}, {224, 0, 0, 5})), 0x05bf0006u);
    const Bytes src = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const Bytes dst = {0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5};
    framesweep::sweep(framesweep::ethernet(0x86dd, framesweep::ipv6Packet(89, helloV3(0xf989), src, dst)), 0x05bf0004u);
}

TEST(Ospf, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"OSPF"});
}
