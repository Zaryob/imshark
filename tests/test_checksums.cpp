// Checksum verification (IPv4 header, TCP, UDP, ICMP, ICMPv6) against checksums computed by a separate, plain
// implementation of RFC 1071 in this file.
#include <gtest/gtest.h>

#include <functional>
#include <map>
#include <random>

#include <core.h>
#include <filter/filter.h>
#include <stats/statistics.h>

#include "support.h"

namespace {
    using Bytes = std::vector<unsigned char>;

    uint16_t internetChecksum(const Bytes &data, const Bytes &pseudo = {}) {
        uint32_t sum = 0;
        Bytes all = pseudo;
        all.insert(all.end(), data.begin(), data.end());
        for (size_t i = 0; i < all.size(); i += 2) sum += (all[i] << 8) | (i + 1 < all.size() ? all[i + 1] : 0);
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        return static_cast<uint16_t>(~sum);
    }
    void put16(Bytes &b, size_t at, unsigned v) { b[at] = static_cast<unsigned char>(v >> 8); b[at + 1] = static_cast<unsigned char>(v & 0xff); }

    const Bytes kSrc4 = {10, 0, 0, 1}, kDst4 = {10, 0, 0, 2};
    const Bytes kSrc6 = {0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, kDst6 = {0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

    Bytes pseudo(const Bytes &src, const Bytes &dst, unsigned proto, size_t length) {
        Bytes p = src;
        p.insert(p.end(), dst.begin(), dst.end());
        if (src.size() == 4) { p.push_back(0); p.push_back(static_cast<unsigned char>(proto)); p.push_back(static_cast<unsigned char>(length >> 8)); p.push_back(static_cast<unsigned char>(length)); }
        else { for (int s: {24, 16, 8, 0}) p.push_back(static_cast<unsigned char>(length >> s)); p.push_back(0); p.push_back(0); p.push_back(0); p.push_back(static_cast<unsigned char>(proto)); }
        return p;
    }

    // Ethernet + IPv4 frame around an L4 segment; the header checksum is correct unless `ipChecksum` says otherwise (-1 = correct)
    std::vector<char> ipv4Frame(unsigned proto, const Bytes &segment, int ipChecksum = -1, size_t snap = 0) {
        Bytes f = {0, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00};
        Bytes ip = {0x45, 0, 0, 0, 0, 1, 0, 0, 64, static_cast<unsigned char>(proto), 0, 0};
        ip.insert(ip.end(), kSrc4.begin(), kSrc4.end());
        ip.insert(ip.end(), kDst4.begin(), kDst4.end());
        put16(ip, 2, 20 + segment.size());
        put16(ip, 10, ipChecksum < 0 ? internetChecksum(ip) : static_cast<unsigned>(ipChecksum));
        f.insert(f.end(), ip.begin(), ip.end());
        f.insert(f.end(), segment.begin(), segment.end());
        if (snap && snap < f.size()) f.resize(snap);
        return std::vector<char>(f.begin(), f.end());
    }
    std::vector<char> ipv6Frame(unsigned proto, const Bytes &segment) {
        Bytes f = {0, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x86, 0xdd};
        Bytes ip = {0x60, 0, 0, 0, 0, 0, static_cast<unsigned char>(proto), 64};
        put16(ip, 4, segment.size());
        ip.insert(ip.end(), kSrc6.begin(), kSrc6.end());
        ip.insert(ip.end(), kDst6.begin(), kDst6.end());
        f.insert(f.end(), ip.begin(), ip.end());
        f.insert(f.end(), segment.begin(), segment.end());
        return std::vector<char>(f.begin(), f.end());
    }

    Bytes tcpSegment(const std::string &payload, const Bytes &src, const Bytes &dst, int checksum = -1) {
        Bytes s = {0xc3, 0x50, 0, 0x50, 0, 0, 0x03, 0xe8, 0, 0, 0, 1, 0x50, 0x18, 0x20, 0, 0, 0, 0, 0};
        s.insert(s.end(), payload.begin(), payload.end());
        put16(s, 16, checksum < 0 ? internetChecksum(s, pseudo(src, dst, 6, s.size())) : static_cast<unsigned>(checksum));
        return s;
    }
    Bytes udpDatagram(const std::string &payload, const Bytes &src, const Bytes &dst, int checksum = -1) {
        Bytes s = {0xc3, 0x50, 0, 0x35, 0, 0, 0, 0};
        put16(s, 4, 8 + payload.size());
        s.insert(s.end(), payload.begin(), payload.end());
        uint16_t c = checksum < 0 ? internetChecksum(s, pseudo(src, dst, 17, s.size())) : static_cast<unsigned>(checksum);
        if (checksum < 0 && c == 0) c = 0xffff;
        put16(s, 6, c);
        return s;
    }
    Bytes icmpMessage(unsigned type, const std::string &payload, const Bytes &src = {}, const Bytes &dst = {}, int checksum = -1) {
        Bytes s = {static_cast<unsigned char>(type), 0, 0, 0, 0x12, 0x34, 0, 1};
        s.insert(s.end(), payload.begin(), payload.end());
        const Bytes ph = src.empty() ? Bytes{} : pseudo(src, dst, 58, s.size());
        put16(s, 2, checksum < 0 ? internetChecksum(s, ph) : static_cast<unsigned>(checksum));
        return s;
    }

    packet::PacketInfo parse(const std::vector<char> &frame) { return support::parse(frame); }

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
}

TEST(Checksum, Ipv4HeaderGoodBadAndOffloaded) {
    const Bytes seg = tcpSegment("hello", kSrc4, kDst4);
    const auto good = parse(ipv4Frame(6, seg));
    EXPECT_TRUE(matches("ip.checksum.status == 1", good));
    EXPECT_NE(find(good.fields, "[Header checksum status: Good]"), nullptr);

    const auto bad = parse(ipv4Frame(6, seg, 0x1234));
    EXPECT_TRUE(matches("ip.checksum.status == 0", bad));
    EXPECT_NE(find(bad.fields, "[Header checksum status: Bad]"), nullptr);
    EXPECT_NE(find(bad.fields, "[Expected checksum: 0x"), nullptr);

    const auto offload = parse(ipv4Frame(6, seg, 0));
    EXPECT_TRUE(matches("ip.checksum.status == 2", offload)) << "a zero header checksum is what offload leaves";
    EXPECT_TRUE(matches("tcp.checksum.status == 1", offload)) << "the TCP checksum is checked independently";
}

TEST(Checksum, TcpOverIpv4) {
    for (const std::string payload: {"", "a", "hello", "an odd number of bytes!"}) {
        const auto p = parse(ipv4Frame(6, tcpSegment(payload, kSrc4, kDst4)));
        EXPECT_TRUE(matches("tcp.checksum.status == 1", p)) << payload.size();
        EXPECT_NE(find(p.fields, "Checksum: 0x"), nullptr);
    }
    const auto bad = parse(ipv4Frame(6, tcpSegment("hello", kSrc4, kDst4, 0xbeef)));
    EXPECT_TRUE(matches("tcp.checksum.status == 0", bad));
    EXPECT_NE(find(bad.fields, "[Checksum Status: Bad]"), nullptr);
    EXPECT_NE(find(bad.fields, "[Expected checksum: 0x"), nullptr);

    // a payload byte changed after the checksum was computed
    auto damaged = ipv4Frame(6, tcpSegment("hello", kSrc4, kDst4));
    damaged.back() ^= 0x20;
    EXPECT_TRUE(matches("tcp.checksum.status == 0", parse(damaged)));
}

TEST(Checksum, TcpOffloadAndTruncatedCaptures) {
    // offload: the field holds the folded, not complemented, pseudo header sum
    Bytes s = tcpSegment("hello", kSrc4, kDst4, 0);
    const Bytes ph = pseudo(kSrc4, kDst4, 6, s.size());
    uint32_t sum = 0;
    for (size_t i = 0; i < ph.size(); i += 2) sum += (ph[i] << 8) | ph[i + 1];
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    put16(s, 16, sum);
    const auto offload = parse(ipv4Frame(6, s));
    EXPECT_TRUE(matches("tcp.checksum.status == 2", offload));
    EXPECT_NE(find(offload.fields, "[Checksum offload: the field holds a partial sum]"), nullptr);
    EXPECT_TRUE(matches("tcp.checksum.status == 2", parse(ipv4Frame(6, tcpSegment("hello", kSrc4, kDst4, 0))))) << "zero is unverified too";

    // snap length: the capture ends inside the segment
    const auto cut = parse(ipv4Frame(6, tcpSegment(std::string(100, 'x'), kSrc4, kDst4), -1, 14 + 20 + 20 + 10));
    EXPECT_TRUE(matches("tcp.checksum.status == 2", cut));
    EXPECT_NE(find(cut.fields, "[The capture ends before the segment does: cannot verify]"), nullptr);
}

TEST(Checksum, UdpOverIpv4AndIpv6) {
    EXPECT_TRUE(matches("udp.checksum.status == 1", parse(ipv4Frame(17, udpDatagram("query", kSrc4, kDst4)))));
    EXPECT_TRUE(matches("udp.checksum.status == 0", parse(ipv4Frame(17, udpDatagram("query", kSrc4, kDst4, 0x1111)))));
    const auto none = parse(ipv4Frame(17, udpDatagram("query", kSrc4, kDst4, 0)));
    EXPECT_TRUE(matches("udp.checksum.status == 3", none)) << "over IPv4 a zero checksum means none was computed";
    EXPECT_NE(find(none.fields, "[Zero checksum: not used (IPv4 allows this)]"), nullptr);

    EXPECT_TRUE(matches("udp.checksum.status == 1", parse(ipv6Frame(17, udpDatagram("query", kSrc6, kDst6)))));
    EXPECT_TRUE(matches("udp.checksum.status == 0", parse(ipv6Frame(17, udpDatagram("query", kSrc6, kDst6, 0)))))
        << "over IPv6 a zero UDP checksum is invalid";
    EXPECT_TRUE(matches("udp.checksum.status == 0", parse(ipv6Frame(17, udpDatagram("query", kSrc6, kDst4, 0)))));
}

TEST(Checksum, IcmpAndIcmpv6UsePseudoHeaderOnlyForV6) {
    EXPECT_TRUE(matches("icmp.checksum.status == 1", parse(ipv4Frame(1, icmpMessage(8, "ping data")))));
    EXPECT_TRUE(matches("icmp.checksum.status == 0", parse(ipv4Frame(1, icmpMessage(8, "ping data", {}, {}, 0x4321)))));
    EXPECT_TRUE(matches("icmpv6.checksum.status == 1", parse(ipv6Frame(58, icmpMessage(128, "ping data", kSrc6, kDst6)))));
    EXPECT_TRUE(matches("icmpv6.checksum.status == 0", parse(ipv6Frame(58, icmpMessage(128, "ping data", {}, {}, 0)))));
    // an ICMPv6 checksum computed without the pseudo header is wrong
    EXPECT_TRUE(matches("icmpv6.checksum.status == 0", parse(ipv6Frame(58, icmpMessage(128, "ping data")))));
}

TEST(Checksum, FieldsExistOnlyForTheirLayer) {
    const auto tcp = parse(ipv4Frame(6, tcpSegment("x", kSrc4, kDst4)));
    EXPECT_FALSE(matches("udp.checksum.status == 1 || icmp.checksum.status == 1", tcp));
    EXPECT_FALSE(matches("ip.checksum.status", parse(ipv6Frame(17, udpDatagram("x", kSrc6, kDst6))))) << "IPv6 has no header checksum";
    EXPECT_FALSE(matches("tcp.checksum.status", parse(support::hex(support::kArpRequest))));
}

TEST(Checksum, ExpertInformationSeparatesBadFromUnverified) {
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    const std::string path = support::writeTemp("checksums.pcap", support::pcapBytes({
        ipv4Frame(6, tcpSegment("good", kSrc4, kDst4)),
        ipv4Frame(6, tcpSegment("bad", kSrc4, kDst4, 0x1234)),
        ipv4Frame(6, tcpSegment("bad two", kSrc4, kDst4, 0x2345), 0x7777),
        ipv4Frame(17, udpDatagram("bad udp", kSrc4, kDst4, 0x3456)),
        ipv4Frame(6, tcpSegment(std::string(100, 'x'), kSrc4, kDst4), -1, 14 + 20 + 20 + 10),
        ipv4Frame(1, icmpMessage(8, "ping", {}, {}, 0x1111)),
    }));
    ASSERT_TRUE(fp.processPcapFile(path, packets, message)) << message;
    std::map<std::string, uint64_t> counts;
    for (const auto &item: stats::expertInfo(packets, nullptr)) counts[item.summary] = item.count;
    EXPECT_EQ(counts["TCP: bad checksum"], 2u);
    EXPECT_EQ(counts["UDP: bad checksum"], 1u);
    EXPECT_EQ(counts["IPv4: bad header checksum"], 1u);
    EXPECT_EQ(counts["ICMP: bad checksum"], 1u);
    EXPECT_EQ(counts["Checksum not verified (capture cut short, or checksum offload)"], 1u);
    for (const auto &item: stats::expertInfo(packets, nullptr)) {
        auto f = filter::Filter::compile(item.filter);
        ASSERT_TRUE(f.ok) << item.filter;
        uint64_t n = 0;
        for (const auto &p: packets) n += f.filter.matches(p);
        EXPECT_EQ(n, item.count) << item.summary;
    }
    // rebuilding the details of a packet gives the same verdict as the loading pass
    packet::PacketInfo d;
    ASSERT_TRUE(core::buildPacketDetails(path, packets[1], d, &packets, &fp.captureInfo()));
    EXPECT_NE(find(d.fields, "[Checksum Status: Bad]"), nullptr);
    std::remove(path.c_str());
}

TEST(Checksum, ReassembledFragmentsAreVerifiedOnce) {
    // an ICMP echo (16 bytes) split into two fragments; the checksum covers the whole message
    const Bytes whole = icmpMessage(8, "01234567");
    auto fragment = [&](size_t offset, size_t length, bool more) {
        Bytes f = {0, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00};
        Bytes ip = {0x45, 0, 0, 0, 0xab, 0xcd, 0, 0, 64, 1, 0, 0};
        ip.insert(ip.end(), kSrc4.begin(), kSrc4.end());
        ip.insert(ip.end(), kDst4.begin(), kDst4.end());
        put16(ip, 2, 20 + length);
        put16(ip, 6, (more ? 0x2000 : 0) | (offset / 8));
        put16(ip, 10, internetChecksum(ip));
        f.insert(f.end(), ip.begin(), ip.end());
        f.insert(f.end(), whole.begin() + offset, whole.begin() + offset + length);
        return std::vector<char>(f.begin(), f.end());
    };
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    const std::string path = support::writeTemp("checksum_frags.pcap", support::pcapBytes({fragment(0, 8, true), fragment(8, 8, false)}));
    ASSERT_TRUE(fp.processPcapFile(path, packets, message)) << message;
    ASSERT_EQ(packets.size(), 2u);
    EXPECT_TRUE(matches("ip.checksum.status == 1", packets[0]));
    EXPECT_TRUE(matches("icmp.checksum.status == 1", packets[1]));
    std::remove(path.c_str());
}

TEST(Checksum, SurviveRandomCorruption) {
    std::mt19937 rng(71);
    const std::vector<std::vector<char>> seeds = {
        ipv4Frame(6, tcpSegment("hello", kSrc4, kDst4)), ipv4Frame(17, udpDatagram("query", kSrc4, kDst4)), ipv4Frame(1, icmpMessage(8, "ping data")),
        ipv6Frame(17, udpDatagram("query", kSrc6, kDst6)), ipv6Frame(58, icmpMessage(128, "ping data", kSrc6, kDst6)), ipv6Frame(6, tcpSegment("hello", kSrc6, kDst6)),
    };
    for (int i = 0; i < 8000; ++i) {
        auto frame = seeds[rng() % seeds.size()];
        frame.resize(14 + rng() % (frame.size() - 13));
        for (unsigned k = rng() % 4; k > 0 && frame.size() > 14; --k) frame[14 + rng() % (frame.size() - 14)] = static_cast<char>(rng());
        packet::PacketParser parser;
        packet::PacketInfo info(1);
        parser.parsePacket(info, frame, dissect::ParseMode::Full);
        std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
            EXPECT_LE(size_t(f.offset) + f.length, frame.size()) << f.text;
            for (const auto &c: f.children) check(c);
        };
        for (const auto &l: info.fields) check(l);
    }
}
