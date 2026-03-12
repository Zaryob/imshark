#include <gtest/gtest.h>

#include <core.h>
#include <dissect/checksum.h>
#include <filter/filter.h>

#include "frame_sweep.h"
#include "support.h"

using support::parse;

namespace {
    // Helper to wrap UDP-Lite in IPv4 + Ethernet
    // IPv4 src=10.0.0.1, dst=10.0.0.2, proto=136
    std::vector<char> makeUdpLitePacket(uint16_t sport, uint16_t dport, uint16_t cov, const std::string &payload, bool badCsum = false) {
        std::vector<uint8_t> frame = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x08, 0x00
        };

        size_t totalUdpLiteLen = 8 + payload.size();
        size_t ipTotalLen = 20 + totalUdpLiteLen;

        std::vector<uint8_t> ip = {
            0x45, 0x00, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
            0x00, 0x01, 0x00, 0x00,
            64, 136, 0x00, 0x00,
            10, 0, 0, 1,
            10, 0, 0, 2
        };
        // IPv4 checksum
        uint32_t csum = 0;
        for (size_t i = 0; i < ip.size(); i += 2) csum += (ip[i] << 8) | ip[i + 1];
        while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
        uint16_t folded = static_cast<uint16_t>(~csum);
        ip[10] = static_cast<uint8_t>(folded >> 8);
        ip[11] = static_cast<uint8_t>(folded & 0xff);

        // UDP-Lite header: sport, dport, cov, csum
        std::vector<uint8_t> udplite = {
            static_cast<uint8_t>(sport >> 8), static_cast<uint8_t>(sport & 0xff),
            static_cast<uint8_t>(dport >> 8), static_cast<uint8_t>(dport & 0xff),
            static_cast<uint8_t>(cov >> 8), static_cast<uint8_t>(cov & 0xff),
            0x00, 0x00
        };
        udplite.insert(udplite.end(), payload.begin(), payload.end());

        // Pseudo header for IPv4: src(4), dst(4), zero(1), proto=136(1), length(2)
        // For UDP-Lite, pseudo header length field contains IP payload length (total UDP-Lite packet length)
        std::vector<uint8_t> pseudo = {
            10, 0, 0, 1,
            10, 0, 0, 2,
            0, 136,
            static_cast<uint8_t>(totalUdpLiteLen >> 8), static_cast<uint8_t>(totalUdpLiteLen & 0xff)
        };

        size_t covBytes = (cov == 0) ? udplite.size() : std::min<size_t>(cov, udplite.size());
        uint32_t ucsum = 0;
        for (size_t i = 0; i < pseudo.size(); i += 2) ucsum += (pseudo[i] << 8) | pseudo[i + 1];
        for (size_t i = 0; i + 1 < covBytes; i += 2) ucsum += (udplite[i] << 8) | udplite[i + 1];
        if (covBytes % 2 != 0) ucsum += static_cast<uint32_t>(udplite[covBytes - 1]) << 8;

        while (ucsum >> 16) ucsum = (ucsum & 0xffff) + (ucsum >> 16);
        uint16_t ufolded = static_cast<uint16_t>(~ucsum);
        if (ufolded == 0) ufolded = 0xffff;
        if (badCsum) ufolded ^= 0x1234;

        udplite[6] = static_cast<uint8_t>(ufolded >> 8);
        udplite[7] = static_cast<uint8_t>(ufolded & 0xff);

        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.insert(frame.end(), udplite.begin(), udplite.end());
        return std::vector<char>(frame.begin(), frame.end());
    }
} // namespace

TEST(UdpLite, FullCoverageValidChecksum) {
    auto pkt = parse(makeUdpLitePacket(10000, 20000, 0, "Hello UDP-Lite!"));
    EXPECT_EQ(pkt.protocol, "UDP-Lite");
    EXPECT_EQ(pkt.src_port, 10000);
    EXPECT_EQ(pkt.dst_port, 20000);
    EXPECT_NE(pkt.info.find("Cov=all"), std::string::npos);

    auto f = filter::Filter::compile("udplite");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}

TEST(UdpLite, PartialCoverageHeaderOnly) {
    // Coverage = 8 (header only covered)
    auto pkt = parse(makeUdpLitePacket(1234, 5678, 8, "Data outside checksum coverage"));
    EXPECT_EQ(pkt.protocol, "UDP-Lite");
    EXPECT_EQ(pkt.src_port, 1234);
    EXPECT_EQ(pkt.dst_port, 5678);
    EXPECT_NE(pkt.info.find("Cov=8"), std::string::npos);
}

TEST(UdpLite, BadChecksum) {
    auto pkt = parse(makeUdpLitePacket(1000, 2000, 0, "test", true));
    EXPECT_EQ(pkt.protocol, "UDP-Lite");
    // Checksum state should be Bad (2)
    uint8_t cstate = (pkt.checksum_state >> 2) & 0x03;
    EXPECT_EQ(cstate, dissect::kChecksumBad);
}

namespace {
    using framesweep::Bytes;

    Bytes liteHeader(uint16_t cov, uint16_t csum, const std::string &payload) {
        Bytes b = {0x04, 0xd2, 0x16, 0x2e, static_cast<uint8_t>(cov >> 8), static_cast<uint8_t>(cov & 0xff),
                   static_cast<uint8_t>(csum >> 8), static_cast<uint8_t>(csum & 0xff)};
        b.insert(b.end(), payload.begin(), payload.end());
        return b;
    }
    packet::PacketInfo liteV4(const Bytes &b) { return framesweep::parseEthernet(framesweep::ethernet(0x0800, framesweep::ipv4Packet(136, b))); }
    uint8_t liteState(const packet::PacketInfo &p) { return dissect::transportChecksumState(p); }
} // namespace

// Python (stdlib) oracle, RFC 3828: the pseudo header holds the length of the WHOLE datagram, the sum covers only
// `cov` bytes. cs(src+dst+b'\0\x88'+len16 + hdr[:6] + b'\0\0' + hdr[8:cov]), 10.0.0.1 -> 10.0.0.2, ports 1234 -> 5678:
//   cov 0, "abcdefgh": 0x3ecf     cov 8, "Data outside coverage": 0xd04f     cov 12, "abcdefgh": 0x0b92
TEST(UdpLite, ChecksumPseudoHeaderCarriesTheFullLength) {
    EXPECT_EQ(liteState(liteV4(liteHeader(0, 0x3ecf, "abcdefgh"))), dissect::kChecksumGood);
    EXPECT_EQ(liteState(liteV4(liteHeader(0, 0x3ed0, "abcdefgh"))), dissect::kChecksumBad);
    // partial coverage (this was a false Bad: the pseudo header took the coverage instead of the full length)
    EXPECT_EQ(liteState(liteV4(liteHeader(8, 0xd04f, "Data outside coverage"))), dissect::kChecksumGood);
    EXPECT_EQ(liteState(liteV4(liteHeader(12, 0x0b92, "abcdefgh"))), dissect::kChecksumGood);
    // a byte after the covered part may change, one inside may not
    Bytes outside = liteHeader(12, 0x0b92, "abcdefgh");
    outside[14] ^= 0xff;
    EXPECT_EQ(liteState(liteV4(outside)), dissect::kChecksumGood);
    Bytes inside = liteHeader(12, 0x0b92, "abcdefgh");
    inside[10] ^= 0xff;
    EXPECT_EQ(liteState(liteV4(inside)), dissect::kChecksumBad);
}

// IPv6 (next header 136): 2001:db8::1 -> 2001:db8::2, cov 12, "abcdefgh": Python cs(src + dst + len32 + 0,0,0,136 + ...) = 0xc41f
TEST(UdpLite, Ipv6PartialCoverage) {
    const Bytes src = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const Bytes dst = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    auto frame = [&](uint16_t csum) {
        return framesweep::parseEthernet(framesweep::ethernet(0x86dd, framesweep::ipv6Packet(136, liteHeader(12, csum, "abcdefgh"), src, dst)));
    };
    EXPECT_EQ(liteState(frame(0xc41f)), dissect::kChecksumGood);
    EXPECT_EQ(liteState(frame(0xc420)), dissect::kChecksumBad);
}

TEST(UdpLite, CoverageBelowTheHeaderIsMalformed) {
    for (uint16_t cov = 1; cov < 8; ++cov) {
        const auto p = liteV4(liteHeader(cov, 0, "abcdefgh"));
        EXPECT_EQ(p.protocol, "UDP-Lite");
        EXPECT_NE(p.info.find("Malformed"), std::string::npos) << cov;
    }
}

TEST(UdpLite, TruncationAndMutationStayInsideTheFrame) {
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(136, liteHeader(12, 0x0b92, "abcdefgh"))), 0x0d1e0001u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(136, liteHeader(0, 0x3ecf, "abcdefgh"))), 0x0d1e0002u);
}

TEST(UdpLite, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"UDP-Lite"});
}
