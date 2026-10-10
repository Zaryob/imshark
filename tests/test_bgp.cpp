#include <gtest/gtest.h>

#include <functional>
#include <random>

#include <core.h>
#include <dissect/protocols.h>
#include <filter/filter.h>

#include "support.h"

using support::hex;

namespace {
    std::string bytes(const std::string &hexText) {
        auto v = hex(hexText);
        return std::string(v.begin(), v.end());
    }

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto r = find(f.children, prefix)) return r;
        }
        return nullptr;
    }

    bool matches(const std::string &expr, const packet::PacketInfo &p) {
        auto r = filter::Filter::compile(expr);
        EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
        return r.ok && r.filter.matches(p);
    }

    void expectRangesInside(const packet::PacketInfo &p, size_t frameSize) {
        std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
            EXPECT_LE(size_t(f.offset) + f.length, frameSize) << f.text;
            for (const auto &c: f.children) check(c);
        };
        for (const auto &l: p.fields) check(l);
    }

    packet::PacketInfo bgpPkt(const std::string &hexPayload) {
        auto frame = support::tcpPacket("0a000001", "0a000002", "c350", "00b3", "00000001", "00000001", "18", bytes(hexPayload)); // 179 = 0x00b3
        auto p = support::parse(frame);
        expectRangesInside(p, frame.size());
        return p;
    }

    std::string bgpHdr(uint16_t len, uint8_t type) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "%04x%02x", len, type);
        return std::string(32, 'f') + buf; // 16 bytes 0xff + len + type
    }
} // namespace

TEST(Bgp, StreamFramer) {
    // 1. Valid 19-byte KEEPALIVE
    const std::string keepalive = bytes(bgpHdr(19, 4));
    auto f1 = dissect::frameBgp(keepalive.data(), keepalive.size());
    EXPECT_EQ(f1.kind, dissect::StreamFrame::Kind::Complete);
    EXPECT_EQ(f1.length, 19u);

    // 2. NeedMore when only 10 bytes available
    auto f2 = dissect::frameBgp(keepalive.data(), 10);
    EXPECT_EQ(f2.kind, dissect::StreamFrame::Kind::NeedMore);

    // 3. NeedMore when header says 100 bytes but only 19 present
    const std::string partial = bytes(bgpHdr(100, 2));
    auto f3 = dissect::frameBgp(partial.data(), partial.size());
    EXPECT_EQ(f3.kind, dissect::StreamFrame::Kind::NeedMore);
    EXPECT_EQ(f3.length, 100u);

    // 4. Reject bad marker
    std::string badMarker = keepalive;
    badMarker[0] = 0x00;
    auto f4 = dissect::frameBgp(badMarker.data(), badMarker.size());
    EXPECT_EQ(f4.kind, dissect::StreamFrame::Kind::Reject);

    // 5. Reject invalid length (< 19 or > 4096)
    const std::string tooShort = bytes(bgpHdr(18, 4));
    EXPECT_EQ(dissect::frameBgp(tooShort.data(), tooShort.size()).kind, dissect::StreamFrame::Kind::Reject);
    const std::string tooLong = bytes(bgpHdr(5000, 4));
    EXPECT_EQ(dissect::frameBgp(tooLong.data(), tooLong.size()).kind, dissect::StreamFrame::Kind::Reject);
}

TEST(Bgp, OpenMessageWithCapabilities) {
    // OPEN message:
    // Version 4, My AS 65001 (0xfde9), Hold Time 180 (0x00b4), BGP ID 192.0.2.1 (c0000201)
    // Opt Param Len = 16 bytes (0x10)
    // Param 1: Type 2 (Capabilities), Len 14 (0x0e)
    //   Cap 1: Code 65 (4-octet AS), Len 4, Val: 0x0000fde9 (65001)
    //   Cap 2: Code 1 (Multiprotocol), Len 4, Val: 0x0001 (IPv4) 0x00 0x01 (Unicast)
    //   Cap 3: Code 2 (Route Refresh), Len 0
    // Total len = 19 + 10 + 16 = 45 bytes (0x002d)
    const std::string hexMsg =
        bgpHdr(45, 1) +
        "04"       // version 4
        "fde9"     // AS 65001
        "00b4"     // Hold Time 180
        "c0000201" // BGP Identifier 192.0.2.1
        "10"       // Opt Params Len 16
        "020e"     // Param Type 2 (Capabilities), Len 14
          "41040000fde9" // Cap 65 (0x41), Len 4, AS 65001
          "010400010001" // Cap 1, Len 4, IPv4 Unicast
          "0200";        // Cap 2, Len 0

    const auto p = bgpPkt(hexMsg);
    EXPECT_EQ(p.protocol, "BGP");
    EXPECT_EQ(p.info, "OPEN Message, AS 65001, hold time 180, ID 192.0.2.1");
    EXPECT_NE(find(p.fields, "Border Gateway Protocol - OPEN"), nullptr);
    EXPECT_NE(find(p.fields, "Version: 4"), nullptr);
    EXPECT_NE(find(p.fields, "My AS: 65001"), nullptr);
    EXPECT_NE(find(p.fields, "Hold Time: 180"), nullptr);
    EXPECT_NE(find(p.fields, "BGP Identifier: 192.0.2.1"), nullptr);
    EXPECT_NE(find(p.fields, "Support for 4-octet AS number: 65001"), nullptr);
    EXPECT_NE(find(p.fields, "Multiprotocol Extensions: AFI=1, SAFI=1"), nullptr);
    EXPECT_NE(find(p.fields, "Route Refresh Capability"), nullptr);

    EXPECT_TRUE(matches("bgp", p));
    EXPECT_TRUE(matches("bgp.type == 1", p));
    EXPECT_TRUE(matches("bgp.as == 65001", p));
}

TEST(Bgp, UpdateWithRoutesAndAttributes) {
    // UPDATE message:
    // Withdrawn Routes: 198.51.100.0/24 (len = 4 bytes: 0x18 c6 33 64) -> withdrawnLen = 4
    // Path Attributes:
    //   ORIGIN: IGP (Type 1, Flags 0x40, Len 1, Val 0x00) -> 4 bytes
    //   AS_PATH: 2-byte ASes [65001 65002] (Type 2, Flags 0x40, Len 6, Seg 2, Count 2, fde9 fdea) -> 9 bytes
    //   NEXT_HOP: 192.0.2.1 (Type 3, Flags 0x40, Len 4, c0 00 02 01) -> 7 bytes
    //   MED: 100 (Type 4, Flags 0x80, Len 4, 00 00 00 64) -> 7 bytes
    //   COMMUNITIES: 65001:100 (Type 8, Flags 0xc0, Len 4, fde9 0064) -> 7 bytes
    // Total Attr Len = 4 + 9 + 7 + 7 + 7 = 34 bytes (0x0022)
    // NLRI: 203.0.113.0/24 (0x18 cb 00 71) -> 4 bytes
    // Total len = 19 + 2 (withdrawnLen) + 4 (withdrawn) + 2 (attrLen) + 34 (attrs) + 4 (nlri) = 65 bytes (0x0041)
    const std::string hexMsg =
        bgpHdr(65, 2) +
        "0004" "18c63364" // Withdrawn: 198.51.100.0/24
        "0022"            // Attr Len 34
          "40010100"             // ORIGIN: IGP
          "4002060202fde9fdea"   // AS_PATH: AS_SEQUENCE 65001 65002
          "400304c0000201"       // NEXT_HOP: 192.0.2.1
          "80040400000064"       // MED: 100
          "c00804fde90064"       // COMMUNITIES: 65001:100
        "18cb0071";              // NLRI: 203.0.113.0/24

    const auto p = bgpPkt(hexMsg);
    EXPECT_EQ(p.protocol, "BGP");
    EXPECT_EQ(p.info, "UPDATE Message, withdrawn 1, NLRI 1, attrs ORIGIN AS_PATH NEXT_HOP MED COMMUNITIES");
    EXPECT_NE(find(p.fields, "ORIGIN: IGP (0)"), nullptr);
    EXPECT_NE(find(p.fields, "AS_PATH: 65001 65002"), nullptr);
    EXPECT_NE(find(p.fields, "NEXT_HOP: 192.0.2.1"), nullptr);
    EXPECT_NE(find(p.fields, "MULTI_EXIT_DISC: 100"), nullptr);
    EXPECT_NE(find(p.fields, "COMMUNITIES: 65001:100"), nullptr);
    EXPECT_NE(find(p.fields, "Route: 198.51.100.0/24"), nullptr);
    EXPECT_NE(find(p.fields, "NLRI: 203.0.113.0/24"), nullptr);

    EXPECT_TRUE(matches("bgp.type == 2", p));
    EXPECT_TRUE(matches("bgp.as == 65001", p));
    EXPECT_TRUE(matches("bgp.nlri == \"203.0.113.0/24\"", p));
}

TEST(Bgp, NotificationMessage) {
    // NOTIFICATION: Error Code 3 (UPDATE Message Error), Error Subcode 11 (Malformed AS_PATH)
    // Length = 19 + 2 = 21 (0x0015)
    const std::string hexMsg = bgpHdr(21, 3) + "030b";
    const auto p = bgpPkt(hexMsg);
    EXPECT_EQ(p.protocol, "BGP");
    EXPECT_EQ(p.info, "NOTIFICATION Message (UPDATE Message Error - Malformed AS_PATH)");
    EXPECT_NE(find(p.fields, "Error Code: UPDATE Message Error (3)"), nullptr);
    EXPECT_NE(find(p.fields, "Error Subcode: Malformed AS_PATH (11)"), nullptr);

    EXPECT_TRUE(matches("bgp.type == 3", p));
    EXPECT_TRUE(matches("bgp.notification.code == 3", p));
}

TEST(Bgp, KeepaliveAndRouteRefresh) {
    const auto ka = bgpPkt(bgpHdr(19, 4));
    EXPECT_EQ(ka.info, "KEEPALIVE Message");
    EXPECT_TRUE(matches("bgp.type == 4", ka));

    // ROUTE-REFRESH: AFI=1 (IPv4), Res=0, SAFI=1 (Unicast) -> 23 bytes (0x0017)
    const auto rr = bgpPkt(bgpHdr(23, 5) + "00010001");
    EXPECT_EQ(rr.info, "ROUTE-REFRESH Message (AFI=1, SAFI=1)");
    EXPECT_NE(find(rr.fields, "AFI: 1"), nullptr);
    EXPECT_NE(find(rr.fields, "SAFI: 1"), nullptr);
    EXPECT_TRUE(matches("bgp.type == 5", rr));
}

TEST(Bgp, UpdateLengthsLargerThanTheMessageAddNoFieldsOutsideTheFrame) {
    // found by fuzz_packet: the Withdrawn Routes / Path Attributes nodes were sized by the declared length
    // even though the message holds fewer bytes; bgpPkt() checks that every node lies inside the frame
    bgpPkt(bgpHdr(23, 2) + "0100" "0000");   // withdrawn routes length 256, nothing follows
    bgpPkt(bgpHdr(23, 2) + "0000" "0100");   // path attributes length 256, nothing follows
}

TEST(Bgp, SurviveDamageAndMalformedInputs) {
    std::mt19937 rng(55);
    const std::string seed =
        bgpHdr(65, 2) +
        "0004" "18c63364"
        "0022"
          "40010100"
          "4002060202fde9fdea"
          "400304c0000201"
          "80040400000064"
          "c00804fde90064"
        "18cb0071";

    for (int i = 0; i < 4000; ++i) {
        auto b = bytes(seed);
        b.resize(rng() % (b.size() + 1));
        for (unsigned k = rng() % 4; k > 0 && !b.empty(); --k) {
            b[rng() % b.size()] = static_cast<char>(rng());
        }
        auto frame = support::tcpPacket("0a000001", "0a000002", "c350", "00b3", "00000001", "00000001", "18", support::hexOf(b));
        packet::PacketParser parser;
        packet::PacketInfo info(1);
        parser.parsePacket(info, frame, dissect::ParseMode::Full);
        expectRangesInside(info, frame.size());
    }
}
