#include <gtest/gtest.h>

#include <cstring>
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

    packet::PacketInfo parseRawPpp(const std::vector<uint8_t> &payload) {
        packet::PacketInfo pack;
        pack.link_type = 9; // LINKTYPE_PPP
        std::vector<char> raw(payload.begin(), payload.end());
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
} // namespace

TEST(PppoePppTest, PppoeActiveDiscoveryInitiation) {
    // PPPoE Discovery (PADI)
    // EtherType 0x8863
    // Header (6 bytes): Ver 1, Type 1, Code 0x09 (PADI), Session ID 0x0000, Length 12
    // Tag 1: Service-Name (0x0101, len 0)
    // Tag 2: Host-Uniq (0x0103, len 4, val 0x12345678)
    std::vector<uint8_t> payload = {
        0x11, 0x09, 0x00, 0x00, 0x00, 0x0c,
        0x01, 0x01, 0x00, 0x00,             // Service-Name
        0x01, 0x03, 0x00, 0x04, 0x12, 0x34, 0x56, 0x78 // Host-Uniq
    };

    packet::PacketInfo p = parseEthernet(0x8863, payload);

    EXPECT_EQ(p.protocol, "PPPoED");
    EXPECT_NE(p.info.find("PADI"), std::string::npos);
    EXPECT_NE(p.info.find("Session ID: 0x0000"), std::string::npos);

    EXPECT_TRUE(findLayer(p, "PPP-over-Ethernet Discovery") != nullptr);

    EXPECT_TRUE(matchFilter("pppoe", p));
    EXPECT_TRUE(matchFilter("pppoed", p));
    EXPECT_FALSE(matchFilter("pppoes", p));
    EXPECT_TRUE(matchFilter("pppoe.code == 0x09", p));
    EXPECT_TRUE(matchFilter("pppoe.session_id == 0", p));
    EXPECT_FALSE(matchFilter("ppp", p));
}

TEST(PppoePppTest, PppoeActiveDiscoveryOfferWithNames) {
    // PPPoE Discovery (PADO)
    // EtherType 0x8863
    // Header (6 bytes): Ver 1, Type 1, Code 0x07 (PADO), Session ID 0x0000, Length 24
    // Tag 1: AC-Name (0x0102, len 6, "dsl-ac")
    // Tag 2: Service-Name (0x0101, len 4, "fast")
    // Tag 3: AC-Cookie (0x0104, len 2, "ok")
    std::vector<uint8_t> payload = {
        0x11, 0x07, 0x00, 0x00, 0x00, 0x16,
        0x01, 0x02, 0x00, 0x06, 'd', 's', 'l', '-', 'a', 'c',
        0x01, 0x01, 0x00, 0x04, 'f', 'a', 's', 't',
        0x01, 0x04, 0x00, 0x02, 'o', 'k'
    };

    packet::PacketInfo p = parseEthernet(0x8863, payload);

    EXPECT_EQ(p.protocol, "PPPoED");
    EXPECT_NE(p.info.find("PADO"), std::string::npos);
    EXPECT_NE(p.info.find("dsl-ac"), std::string::npos);
    EXPECT_NE(p.info.find("fast"), std::string::npos);

    EXPECT_TRUE(matchFilter("pppoe", p));
    EXPECT_TRUE(matchFilter("pppoed", p));
    EXPECT_TRUE(matchFilter("pppoe.code == 0x07", p));
    EXPECT_TRUE(matchFilter("pppoe.ac_name == \"dsl-ac\"", p));
    EXPECT_TRUE(matchFilter("pppoe.service_name == \"fast\"", p));
}

TEST(PppoePppTest, PppoeSessionLcpConfiguration) {
    // PPPoE Session (0x8864)
    // Header (6 bytes): Ver 1, Type 1, Code 0x00 (Session), Session ID 0x1234, Length 20 (2 PPP + 18 LCP)
    // PPP Protocol: 0xc021 (LCP)
    // LCP (18 bytes):
    // Code 1 (Config-Req), ID 1, Length 18
    // Option 1: MRU (len 4, val 1492) -> 0x01, 0x04, 0x05, 0xd4
    // Option 3: Auth Protocol (len 4, val 0xc223 CHAP) -> 0x03, 0x04, 0xc2, 0x23
    // Option 5: Magic Number (len 6, val 0xaabbccdd) -> 0x05, 0x06, 0xaa, 0xbb, 0xcc, 0xdd
    std::vector<uint8_t> payload = {
        0x11, 0x00, 0x12, 0x34, 0x00, 0x14, // PPPoE
        0xc0, 0x21,                         // PPP: LCP
        0x01, 0x01, 0x00, 0x12,             // LCP: Config-Req, id=1, len=18
        0x01, 0x04, 0x05, 0xd4,             // MRU: 1492
        0x03, 0x04, 0xc2, 0x23,             // Auth: CHAP
        0x05, 0x06, 0xaa, 0xbb, 0xcc, 0xdd  // Magic Number
    };

    packet::PacketInfo p = parseEthernet(0x8864, payload);

    EXPECT_EQ(p.protocol, "LCP");
    EXPECT_NE(p.info.find("Configuration Request"), std::string::npos);
    EXPECT_NE(p.info.find("id=1"), std::string::npos);

    EXPECT_TRUE(findLayer(p, "PPP-over-Ethernet Session") != nullptr);
    EXPECT_TRUE(findLayer(p, "Point-to-Point Protocol") != nullptr);
    EXPECT_TRUE(findLayer(p, "LCP, Configuration Request") != nullptr);

    EXPECT_TRUE(matchFilter("pppoe", p));
    EXPECT_TRUE(matchFilter("pppoes", p));
    EXPECT_FALSE(matchFilter("pppoed", p));
    EXPECT_TRUE(matchFilter("pppoe.code == 0", p));
    EXPECT_TRUE(matchFilter("pppoe.session_id == 0x1234", p));
    EXPECT_TRUE(matchFilter("ppp", p));
    EXPECT_TRUE(matchFilter("ppp.protocol == 0xc021", p));
    EXPECT_TRUE(matchFilter("ppp.lcp.code == 1", p));
}

TEST(PppoePppTest, PppoeSessionIpcpConfiguration) {
    // PPPoE Session (0x8864)
    // PPP Protocol: 0x8021 (IPCP)
    // IPCP: Code 2 (Config-Ack), ID 5, Length 16
    // Option 3: IP Address (len 6, val 10.20.30.40) -> 0x03, 0x06, 10, 20, 30, 40
    // Option 129: Primary DNS (len 6, val 1.1.1.1) -> 0x81, 0x06, 1, 1, 1, 1
    std::vector<uint8_t> payload = {
        0x11, 0x00, 0x00, 0x07, 0x00, 0x12, // PPPoE: Session 7, len 18
        0x80, 0x21,                         // PPP: IPCP
        0x02, 0x05, 0x00, 0x10,             // IPCP: Config-Ack, id=5, len=16
        0x03, 0x06, 10, 20, 30, 40,         // IP: 10.20.30.40
        0x81, 0x06, 1, 1, 1, 1              // DNS: 1.1.1.1
    };

    packet::PacketInfo p = parseEthernet(0x8864, payload);

    EXPECT_EQ(p.protocol, "IPCP");
    EXPECT_NE(p.info.find("Configuration Ack"), std::string::npos);

    EXPECT_TRUE(matchFilter("pppoe", p));
    EXPECT_TRUE(matchFilter("pppoes", p));
    EXPECT_TRUE(matchFilter("ppp", p));
    EXPECT_TRUE(matchFilter("ppp.protocol == 0x8021", p));
    EXPECT_TRUE(matchFilter("ppp.ipcp.code == 2", p));
}

TEST(PppoePppTest, PppoeSessionUnwrapsToIpv4Udp) {
    // PPPoE Session (0x8864) -> PPP IPv4 (0x0021) -> IPv4 -> UDP -> DNS
    std::vector<uint8_t> payload = {
        0x11, 0x00, 0x00, 0x2a, 0x00, 0x26, // PPPoE: Session 42, len 38 (2 PPP + 20 IP + 8 UDP + 8 data)
        0x00, 0x21,                         // PPP: IPv4
        // IPv4 Header (20 bytes): 192.168.1.50 -> 8.8.8.8, Protocol 17 (UDP)
        0x45, 0x00, 0x00, 0x24,
        0xab, 0xcd, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        192, 168, 1, 50,
        8, 8, 8, 8,
        // UDP Header (8 bytes): 54321 -> 53
        0xd4, 0x31, 0x00, 0x35,
        0x00, 0x10, 0x00, 0x00,
        // Data (8 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    packet::PacketInfo p = parseEthernet(0x8864, payload);

    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_EQ(p.ip_version, 4);
    EXPECT_EQ(p.source, "192.168.1.50");
    EXPECT_EQ(p.destination, "8.8.8.8");
    EXPECT_EQ(p.src_port, 54321);
    EXPECT_EQ(p.dst_port, 53);
    EXPECT_EQ(p.l2_size, 22u); // 14 Ethernet + 6 PPPoE + 2 PPP

    EXPECT_TRUE(findLayer(p, "PPP-over-Ethernet Session") != nullptr);
    EXPECT_TRUE(findLayer(p, "Point-to-Point Protocol") != nullptr);
    EXPECT_TRUE(findLayer(p, "Internet Protocol Version 4") != nullptr);

    EXPECT_TRUE(matchFilter("pppoe", p));
    EXPECT_TRUE(matchFilter("pppoes", p));
    EXPECT_TRUE(matchFilter("pppoe.session_id == 42", p));
    EXPECT_TRUE(matchFilter("ppp", p));
    EXPECT_TRUE(matchFilter("ppp.protocol == 0x0021", p));
    EXPECT_TRUE(matchFilter("ip.src == 192.168.1.50", p));
    EXPECT_TRUE(matchFilter("ip.dst == 8.8.8.8", p));
    EXPECT_TRUE(matchFilter("udp.dstport == 53", p));
}

TEST(PppoePppTest, RawPppLinkTypeWithIpv4) {
    // LinkType 9 (Raw PPP): 2 bytes PPP header + IPv4 + UDP
    std::vector<uint8_t> frame = {
        0x00, 0x21, // PPP: IPv4
        // IPv4 Header (20 bytes)
        0x45, 0x00, 0x00, 0x20,
        0x12, 0x34, 0x00, 0x00,
        0x40, 0x11, 0x00, 0x00,
        172, 16, 0, 1,
        172, 16, 0, 2,
        // UDP Header (8 bytes)
        0x04, 0xd2, 0x04, 0xd2, // 1234 -> 1234
        0x00, 0x0c, 0x00, 0x00,
        // Payload (4 bytes)
        't', 'e', 's', 't'
    };

    packet::PacketInfo p = parseRawPpp(frame);

    EXPECT_EQ(p.ip_version, 4);
    EXPECT_EQ(p.source, "172.16.0.1");
    EXPECT_EQ(p.destination, "172.16.0.2");
    EXPECT_TRUE(matchFilter("ppp", p));
    EXPECT_TRUE(matchFilter("ppp.protocol == 0x0021", p));
    EXPECT_TRUE(matchFilter("ip.src == 172.16.0.1", p));
}

TEST(PppoePppTest, TruncatedHeadersDoNotCrash) {
    // Truncated PPPoE (< 6 bytes)
    std::vector<uint8_t> shortPppoe = { 0x11, 0x00, 0x00, 0x01 };
    packet::PacketInfo p1 = parseEthernet(0x8864, shortPppoe, false);
    EXPECT_TRUE(matchFilter("malformed", p1));

    // Truncated PPP protocol field (< 2 bytes)
    std::vector<uint8_t> shortPpp = { 0x00 };
    packet::PacketInfo p2 = parseRawPpp(shortPpp);
    EXPECT_TRUE(matchFilter("malformed", p2));
}
