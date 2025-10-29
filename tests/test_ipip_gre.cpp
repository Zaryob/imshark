#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <filter/filter.h>
#include <packet/packet_info.h>
#include <packet/packet_parser.h>

namespace {
    packet::PacketInfo parseEthernet(uint16_t etherType, const std::vector<uint8_t> &payload, bool pad = true) {
        packet::PacketInfo pack;
        pack.link_type = 1; // Ethernet
        std::vector<uint8_t> eth = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // DA
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // SA
            static_cast<uint8_t>(etherType >> 8), static_cast<uint8_t>(etherType & 0xff)
        };
        eth.insert(eth.end(), payload.begin(), payload.end());

        if (pad && eth.size() < 60) {
            eth.resize(60, 0);
        }

        std::vector<char> raw(eth.begin(), eth.end());
        packet::PacketParser parser;
        parser.parsePacket(pack, raw, dissect::ParseMode::Full);
        return pack;
    }

    bool matchFilter(const std::string &expr, const packet::PacketInfo &p) {
        auto r = filter::Filter::compile(expr);
        return r.ok && r.filter.matches(p);
    }

    const packet::Field *findFieldRecursive(const packet::Field &f, const std::string &prefix) {
        if (f.text.rfind(prefix, 0) == 0) return &f;
        for (const auto &c: f.children) {
            if (const auto *res = findFieldRecursive(c, prefix)) return res;
        }
        return nullptr;
    }

    const packet::Field *findLayer(const packet::PacketInfo &p, const std::string &prefix) {
        for (const auto &f: p.fields) {
            if (const auto *res = findFieldRecursive(f, prefix)) return res;
        }
        return nullptr;
    }

    // 20-byte IPv4 header (no options, TTL 64, zero checksum) + payload.
    std::vector<uint8_t> ipv4(uint8_t protocol, const std::vector<uint8_t> &payload,
                              uint8_t sa = 10, uint8_t sb = 1, uint8_t sc = 1, uint8_t sd = 1,
                              uint8_t da = 10, uint8_t db = 2, uint8_t dc = 2, uint8_t dd = 2) {
        const uint16_t total = static_cast<uint16_t>(20 + payload.size());
        std::vector<uint8_t> h = {
            0x45, 0x00, static_cast<uint8_t>(total >> 8), static_cast<uint8_t>(total & 0xff),
            0x00, 0x01, 0x00, 0x00,
            0x40, protocol, 0x00, 0x00,
            sa, sb, sc, sd,
            da, db, dc, dd
        };
        h.insert(h.end(), payload.begin(), payload.end());
        return h;
    }

    // 40-byte IPv6 header (no extension headers, hop limit 64) + payload.
    std::vector<uint8_t> ipv6(uint8_t nextHeader, const std::vector<uint8_t> &payload) {
        const uint16_t plen = static_cast<uint16_t>(payload.size());
        std::vector<uint8_t> h = {
            0x60, 0x00, 0x00, 0x00,
            static_cast<uint8_t>(plen >> 8), static_cast<uint8_t>(plen & 0xff), nextHeader, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2
        };
        h.insert(h.end(), payload.begin(), payload.end());
        return h;
    }

    std::vector<uint8_t> udp(uint16_t src, uint16_t dst, const std::vector<uint8_t> &data) {
        const uint16_t len = static_cast<uint16_t>(8 + data.size());
        std::vector<uint8_t> h = {
            static_cast<uint8_t>(src >> 8), static_cast<uint8_t>(src & 0xff),
            static_cast<uint8_t>(dst >> 8), static_cast<uint8_t>(dst & 0xff),
            static_cast<uint8_t>(len >> 8), static_cast<uint8_t>(len & 0xff),
            0x00, 0x00
        };
        h.insert(h.end(), data.begin(), data.end());
        return h;
    }

    std::vector<uint8_t> udpPayload() { return udp(40000, 50000, {0x11, 0x22, 0x33, 0x44}); }

    // A complete inner Ethernet frame (used by GRE TEB and ERSPAN payloads).
    std::vector<uint8_t> ethFrame(uint16_t type, const std::vector<uint8_t> &payload) {
        std::vector<uint8_t> e = {
            0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
            static_cast<uint8_t>(type >> 8), static_cast<uint8_t>(type & 0xff)
        };
        e.insert(e.end(), payload.begin(), payload.end());
        return e;
    }

    // 4-byte GRE header + `optional` (checksum/key/sequence fields) + payload.
    std::vector<uint8_t> gre(uint16_t flags, uint16_t proto, const std::vector<uint8_t> &optional,
                             const std::vector<uint8_t> &payload) {
        std::vector<uint8_t> g = {
            static_cast<uint8_t>(flags >> 8), static_cast<uint8_t>(flags & 0xff),
            static_cast<uint8_t>(proto >> 8), static_cast<uint8_t>(proto & 0xff)
        };
        g.insert(g.end(), optional.begin(), optional.end());
        g.insert(g.end(), payload.begin(), payload.end());
        return g;
    }
} // namespace

TEST(IpInIpTest, Ipv4InIpv4UnwrapsInnerUdp) {
    const auto inner = ipv4(17, udpPayload(), 10, 1, 1, 1, 10, 2, 2, 2);
    const auto outer = ipv4(4, inner, 192, 0, 2, 1, 192, 0, 2, 2);

    const packet::PacketInfo p = parseEthernet(0x0800, outer);

    EXPECT_EQ(p.protocol, "UDP");
    EXPECT_EQ(p.ip_version, 4);
    EXPECT_EQ(p.source, "10.1.1.1");       // the inner header wins (parsed last)
    EXPECT_EQ(p.destination, "10.2.2.2");
    EXPECT_EQ(p.src_port, 40000);
    EXPECT_EQ(p.dst_port, 50000);
    EXPECT_EQ(p.l2_size, 14u);             // outer IP header, not the inner one

    EXPECT_TRUE(matchFilter("ipip", p));
    EXPECT_TRUE(matchFilter("ip.src == 10.1.1.1", p));
    EXPECT_TRUE(matchFilter("udp.dstport == 50000", p));
    EXPECT_FALSE(matchFilter("gre", p));
}

TEST(IpInIpTest, Ipv6InIpv4UnwrapsInnerUdp) {
    const auto inner = ipv6(17, udpPayload());
    const auto outer = ipv4(41, inner, 192, 0, 2, 1, 192, 0, 2, 2);

    const packet::PacketInfo p = parseEthernet(0x0800, outer);

    EXPECT_EQ(p.protocol, "UDP");
    EXPECT_EQ(p.ip_version, 6);
    EXPECT_EQ(p.source, "2001:db8::1");
    EXPECT_EQ(p.destination, "2001:db8::2");

    EXPECT_TRUE(matchFilter("ipip", p));
    EXPECT_TRUE(matchFilter("ipv6.src == 2001:db8::1", p));
}

TEST(GreTest, BareGreCarriesIpv4) {
    const auto innerIp = ipv4(17, udpPayload(), 10, 1, 1, 1, 10, 2, 2, 2);
    const auto greHdr = gre(0x0000, 0x0800, {}, innerIp);
    const auto outer = ipv4(47, greHdr, 192, 0, 2, 1, 192, 0, 2, 2);

    const packet::PacketInfo p = parseEthernet(0x0800, outer);

    EXPECT_EQ(p.protocol, "UDP");
    EXPECT_EQ(p.source, "10.1.1.1");
    EXPECT_TRUE(findLayer(p, "Generic Routing Encapsulation") != nullptr);
    EXPECT_TRUE(matchFilter("gre", p));
    EXPECT_TRUE(matchFilter("gre.proto == 0x0800", p));
    EXPECT_TRUE(matchFilter("gre.version == 0", p));
    EXPECT_TRUE(matchFilter("gre.flags.key == 0", p));
    EXPECT_TRUE(matchFilter("ip.src == 10.1.1.1", p));
    EXPECT_FALSE(matchFilter("ipip", p));
}

TEST(GreTest, ChecksumKeyAndSequenceFlags) {
    const std::vector<uint8_t> optional = {
        0xab, 0xcd, 0x00, 0x00, // checksum + routing offset
        0x00, 0x00, 0xaa, 0xbb, // key
        0x00, 0x00, 0x00, 0x07  // sequence
    };
    const auto innerIp = ipv4(17, udpPayload(), 10, 1, 1, 1, 10, 2, 2, 2);
    const auto greHdr = gre(0xB000, 0x0800, optional, innerIp); // C | K | S
    const auto outer = ipv4(47, greHdr, 192, 0, 2, 1, 192, 0, 2, 2);

    const packet::PacketInfo p = parseEthernet(0x0800, outer);

    EXPECT_EQ(p.protocol, "UDP");
    EXPECT_TRUE(matchFilter("gre", p));
    EXPECT_TRUE(matchFilter("gre.flags.checksum == 1", p));
    EXPECT_TRUE(matchFilter("gre.flags.key == 1", p));
    EXPECT_TRUE(matchFilter("gre.flags.sequence == 1", p));
    EXPECT_TRUE(matchFilter("gre.key == 0xAABB", p));
    EXPECT_TRUE(matchFilter("gre.sequence_number == 7", p));

    // gre_key aliases ppp_protocol on the shared union storage: PPP must not false-positive
    EXPECT_FALSE(matchFilter("ppp", p));
    EXPECT_FALSE(matchFilter("pppoe", p));
}

TEST(GreTest, TransparentEthernetBridging) {
    const auto innerIp = ipv4(17, udpPayload(), 10, 1, 1, 1, 10, 2, 2, 2);
    const auto innerEth = ethFrame(0x0800, innerIp);
    const auto greHdr = gre(0x0000, 0x6558, {}, innerEth);
    const auto outer = ipv4(47, greHdr, 192, 0, 2, 1, 192, 0, 2, 2);

    const packet::PacketInfo p = parseEthernet(0x0800, outer);

    EXPECT_EQ(p.protocol, "UDP");
    EXPECT_EQ(p.source, "10.1.1.1");
    EXPECT_TRUE(matchFilter("gre", p));
    EXPECT_TRUE(matchFilter("gre.proto == 0x6558", p));
    EXPECT_TRUE(matchFilter("ip.src == 10.1.1.1", p));
}

TEST(GreTest, ErspanTypeIIMirrorsEthernet) {
    // ERSPAN Type II feature header: Ver 1, VLAN 100, Session ID 5.
    const std::vector<uint8_t> erspan = {
        0x10, 0x64,             // Ver=1, VLAN=100
        0x00, 0x05,             // COS/En/T/Session ID = 5
        0x00, 0x00, 0x00, 0x00  // reserved + index
    };
    std::vector<uint8_t> payload = erspan;
    const auto innerIp = ipv4(17, udpPayload(), 10, 1, 1, 1, 10, 2, 2, 2);
    const auto mirrored = ethFrame(0x0800, innerIp);
    payload.insert(payload.end(), mirrored.begin(), mirrored.end());

    const std::vector<uint8_t> seq = {0x00, 0x00, 0x00, 0x01};
    const auto greHdr = gre(0x1000, 0x88BE, seq, payload); // S bit, ERSPAN II
    const auto outer = ipv4(47, greHdr, 192, 0, 2, 1, 192, 0, 2, 2);

    const packet::PacketInfo p = parseEthernet(0x0800, outer);

    EXPECT_EQ(p.protocol, "UDP");
    EXPECT_EQ(p.source, "10.1.1.1");
    EXPECT_TRUE(findLayer(p, "ERSPAN Type II") != nullptr);
    EXPECT_TRUE(matchFilter("gre", p));
    EXPECT_TRUE(matchFilter("gre.proto == 0x88BE", p));
    EXPECT_TRUE(matchFilter("ip.src == 10.1.1.1", p));
}

TEST(GreTest, TruncatedHeadersDoNotCrash) {
    // GRE header shorter than 4 bytes
    const auto p0 = parseEthernet(0x0800, ipv4(47, {0x00, 0x00}, 192, 0, 2, 1, 192, 0, 2, 2));
    EXPECT_TRUE(matchFilter("malformed", p0));

    // Key flag set but the key field is missing
    const auto p1 = parseEthernet(0x0800, ipv4(47, gre(0x2000, 0x0800, {}, {}), 192, 0, 2, 1, 192, 0, 2, 2));
    EXPECT_TRUE(matchFilter("malformed", p1));

    // ERSPAN Type II with fewer than 8 header bytes
    const auto p2 = parseEthernet(0x0800, ipv4(47, gre(0x0000, 0x88BE, {}, {0x00, 0x00}), 192, 0, 2, 1, 192, 0, 2, 2));
    EXPECT_TRUE(matchFilter("malformed", p2));
}
