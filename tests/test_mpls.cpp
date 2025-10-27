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
        for (const auto &c : f.children) {
            if (const auto *res = findFieldRecursive(c, prefix)) return res;
        }
        return nullptr;
    }

    const packet::Field *findLayer(const packet::PacketInfo &p, const std::string &prefix) {
        for (const auto &f : p.fields) {
            if (const auto *res = findFieldRecursive(f, prefix)) return res;
        }
        return nullptr;
    }

    // LSE: Label 20 bits, TC 3 bits, S 1 bit, TTL 8 bits (RFC 3032)
    std::vector<uint8_t> lse(uint32_t label, uint8_t tc, bool bottom, uint8_t ttl) {
        const uint32_t entry = (label << 12) | (static_cast<uint32_t>(tc) << 9) | (bottom ? 0x100u : 0u) | ttl;
        return {static_cast<uint8_t>(entry >> 24), static_cast<uint8_t>(entry >> 16),
                static_cast<uint8_t>(entry >> 8), static_cast<uint8_t>(entry)};
    }

    // IPv4 192.168.1.50 -> 8.8.8.8, UDP 54321 -> 53, 8 bytes payload
    std::vector<uint8_t> ipv4UdpDns() {
        return {
            0x45, 0x00, 0x00, 0x24,
            0xab, 0xcd, 0x00, 0x00,
            0x40, 0x11, 0x00, 0x00,
            192, 168, 1, 50,
            8, 8, 8, 8,
            0xd4, 0x31, 0x00, 0x35,
            0x00, 0x10, 0x00, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
        };
    }

    // IPv6 2001:db8::1 -> 2001:db8::2, UDP 4660 -> 4661, 8 bytes payload
    std::vector<uint8_t> ipv6Udp() {
        return {
            0x60, 0x00, 0x00, 0x00,
            0x00, 0x08, 0x11, 0x40,
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
            0x12, 0x34, 0x12, 0x35,
            0x00, 0x08, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00
        };
    }
} // namespace

TEST(MplsTest, SingleLabelUnwrapsToIpv4Udp) {
    std::vector<uint8_t> payload = lse(100, 0, true, 64);
    const auto ip = ipv4UdpDns();
    payload.insert(payload.end(), ip.begin(), ip.end());

    packet::PacketInfo p = parseEthernet(0x8847, payload);

    EXPECT_EQ(p.ether_type, 0x8847);
    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_EQ(p.ip_version, 4);
    EXPECT_EQ(p.source, "192.168.1.50");
    EXPECT_EQ(p.destination, "8.8.8.8");
    EXPECT_EQ(p.src_port, 54321);
    EXPECT_EQ(p.dst_port, 53);
    EXPECT_EQ(p.l2_size, 18u); // 14 Ethernet + 4 MPLS

    EXPECT_TRUE(findLayer(p, "MultiProtocol Label Switching Header") != nullptr);
    EXPECT_TRUE(findLayer(p, "Internet Protocol Version 4") != nullptr);

    EXPECT_TRUE(matchFilter("mpls", p));
    EXPECT_TRUE(matchFilter("mpls.label == 100", p));
    EXPECT_TRUE(matchFilter("mpls.exp == 0", p));
    EXPECT_TRUE(matchFilter("mpls.ttl == 64", p));
    EXPECT_TRUE(matchFilter("mpls.bottom_of_stack == 1", p));
    EXPECT_TRUE(matchFilter("ip.src == 192.168.1.50", p));
    EXPECT_TRUE(matchFilter("ip.dst == 8.8.8.8", p));
    EXPECT_TRUE(matchFilter("udp.dstport == 53", p));

    // mpls_lse0 aliases the PPPoE fields: no PPP/PPPoE false positive on the same union storage
    EXPECT_FALSE(matchFilter("ppp", p));
    EXPECT_FALSE(matchFilter("pppoe", p));
}

TEST(MplsTest, MultiLabelStackShowsBothLabels) {
    std::vector<uint8_t> payload = lse(200, 3, false, 250);
    const auto lse1 = lse(300, 0, true, 63);
    payload.insert(payload.end(), lse1.begin(), lse1.end());
    const auto ip = ipv4UdpDns();
    payload.insert(payload.end(), ip.begin(), ip.end());

    packet::PacketInfo p = parseEthernet(0x8847, payload);

    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_EQ(p.l2_size, 22u); // 14 Ethernet + 8 MPLS

    EXPECT_TRUE(matchFilter("mpls.label == 200", p));
    EXPECT_TRUE(matchFilter("mpls.exp == 3", p));
    EXPECT_TRUE(matchFilter("mpls.ttl == 250", p));
    EXPECT_TRUE(matchFilter("mpls.bottom_of_stack == 0", p));
    EXPECT_TRUE(matchFilter("mpls.label1 == 300", p));
    EXPECT_TRUE(matchFilter("ip.src == 192.168.1.50", p));

    // mpls_lse1 aliases ppp_protocol: the second label must not leak into the PPP filters
    EXPECT_FALSE(matchFilter("ppp", p));
    EXPECT_FALSE(matchFilter("pppoe", p));
}

TEST(MplsTest, MultiLabelSummaryWhenNoInnerPayload) {
    std::vector<uint8_t> payload = lse(200, 3, false, 250);
    const auto lse1 = lse(300, 0, true, 63);
    payload.insert(payload.end(), lse1.begin(), lse1.end());

    packet::PacketInfo p = parseEthernet(0x8847, payload);

    EXPECT_EQ(p.protocol, "MPLS");
    EXPECT_NE(p.info.find("MPLS Labels: 200, 300"), std::string::npos);
    EXPECT_TRUE(matchFilter("mpls.label1 == 300", p));
}

TEST(MplsTest, ReservedLabelNames) {
    std::vector<uint8_t> payload = lse(0, 0, true, 64); // IPv4 explicit NULL
    const auto ip = ipv4UdpDns();
    payload.insert(payload.end(), ip.begin(), ip.end());

    packet::PacketInfo p = parseEthernet(0x8847, payload);

    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_EQ(p.l2_size, 18u);
    EXPECT_TRUE(findLayer(p, "MPLS Label: 0 (IPv4 explicit NULL)") != nullptr);
    EXPECT_TRUE(matchFilter("mpls.label == 0", p));
}

TEST(MplsTest, Ipv6InnerPayload) {
    std::vector<uint8_t> payload = lse(2, 0, true, 64); // IPv6 explicit NULL
    const auto ip6 = ipv6Udp();
    payload.insert(payload.end(), ip6.begin(), ip6.end());

    packet::PacketInfo p = parseEthernet(0x8847, payload);

    EXPECT_EQ(p.protocol, "UDP");
    EXPECT_EQ(p.ip_version, 6);
    EXPECT_EQ(p.source, "2001:db8::1");
    EXPECT_EQ(p.destination, "2001:db8::2");
    EXPECT_EQ(p.l2_size, 18u);

    EXPECT_TRUE(findLayer(p, "MPLS Label: 2 (IPv6 explicit NULL)") != nullptr);
    EXPECT_TRUE(findLayer(p, "Internet Protocol Version 6") != nullptr);
    EXPECT_TRUE(matchFilter("mpls", p));
    EXPECT_TRUE(matchFilter("ipv6.src == 2001:db8::1", p));
    EXPECT_FALSE(matchFilter("ppp", p));
    EXPECT_FALSE(matchFilter("pppoe", p));
}

TEST(MplsTest, UnwrappedEthernetWithoutControlWord) {
    // First nibble of the inner DA is not 0/4/6: the stack is followed by a bare Ethernet frame
    std::vector<uint8_t> payload = lse(100, 0, true, 64);
    const std::vector<uint8_t> eth = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // DA
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xcc, // SA
        0x08, 0x00                          // IPv4
    };
    payload.insert(payload.end(), eth.begin(), eth.end());
    const auto ip = ipv4UdpDns();
    payload.insert(payload.end(), ip.begin(), ip.end());

    packet::PacketInfo p = parseEthernet(0x8847, payload);

    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_EQ(p.l2_size, 32u); // 14 + 4 MPLS + 14 inner Ethernet
    EXPECT_EQ(p.source, "192.168.1.50");
    EXPECT_TRUE(matchFilter("mpls", p));
    EXPECT_TRUE(matchFilter("ip.src == 192.168.1.50", p));
}

TEST(MplsTest, PseudowireControlWordBeforeEthernet) {
    std::vector<uint8_t> payload = lse(100, 0, true, 64);
    const std::vector<uint8_t> cwEth = {
        0x00, 0x00, 0x00, 0x00,             // pseudowire control word (RFC 4385)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x66, // DA
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xcc, // SA
        0x08, 0x00                          // IPv4
    };
    payload.insert(payload.end(), cwEth.begin(), cwEth.end());
    const auto ip = ipv4UdpDns();
    payload.insert(payload.end(), ip.begin(), ip.end());

    packet::PacketInfo p = parseEthernet(0x8847, payload);

    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_EQ(p.l2_size, 36u); // 14 + 4 MPLS + 4 CW + 14 inner Ethernet
    EXPECT_TRUE(findLayer(p, "Pseudowire Control Word") != nullptr);
    EXPECT_TRUE(matchFilter("mpls", p));
    EXPECT_TRUE(matchFilter("ip.src == 192.168.1.50", p));
}

TEST(MplsTest, TruncatedAndTooDeepStacksDoNotCrash) {
    // Header shorter than one LSE
    std::vector<uint8_t> tiny = lse(100, 0, true, 64);
    tiny.resize(2);
    packet::PacketInfo p1 = parseEthernet(0x8847, tiny, false);
    EXPECT_TRUE(matchFilter("malformed", p1));

    // Second LSE cut in half: bottom of stack never reached
    std::vector<uint8_t> trunc = lse(100, 0, false, 64);
    trunc.push_back(0x00);
    trunc.push_back(0x00);
    packet::PacketInfo p2 = parseEthernet(0x8847, trunc, false);
    EXPECT_TRUE(matchFilter("malformed", p2));

    // 17 labels without bottom of stack exceeds the depth limit
    std::vector<uint8_t> deep;
    for (int i = 0; i < 17; ++i) {
        const auto entry = lse(static_cast<uint32_t>(i + 1), 0, false, 64);
        deep.insert(deep.end(), entry.begin(), entry.end());
    }
    packet::PacketInfo p3 = parseEthernet(0x8847, deep, false);
    EXPECT_TRUE(matchFilter("malformed", p3));
    EXPECT_FALSE(matchFilter("ppp", p3));
    EXPECT_FALSE(matchFilter("pppoe", p3));
}
