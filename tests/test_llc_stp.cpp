#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include <filter/filter.h>
#include <packet/packet_info.h>
#include <packet/packet_parser.h>

namespace {
    packet::PacketInfo parse8023(const std::vector<uint8_t> &llcPayload) {
        packet::PacketInfo pack;
        pack.link_type = 1; // Ethernet
        uint16_t lengthField = static_cast<uint16_t>(llcPayload.size());
        // 802.3 MAC header: 6 DA + 6 SA + 2 Length
        std::vector<uint8_t> eth = {
            0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, // STP Multicast DA
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // SA
            static_cast<uint8_t>(lengthField >> 8), static_cast<uint8_t>(lengthField & 0xff)
        };
        eth.insert(eth.end(), llcPayload.begin(), llcPayload.end());

        // Pad to minimum Ethernet frame size if necessary
        if (eth.size() < 60) {
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
} // namespace

TEST(LlcStpTest, StpConfigurationBpdu) {
    // 3 bytes LLC (DSAP 0x42, SSAP 0x42, Ctrl 0x03)
    // 35 bytes STP Config BPDU
    std::vector<uint8_t> payload = {
        0x42, 0x42, 0x03,                   // LLC: STP
        0x00, 0x00,                         // Protocol ID: 0 (Spanning Tree)
        0x00,                               // Version: 0 (STP)
        0x00,                               // BPDU Type: 0x00 (Config)
        0x01,                               // Flags: Topology Change
        0x80, 0x00,                         // Root Priority: 32768
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, // Root MAC
        0x00, 0x00, 0x4e, 0x20,             // Root Path Cost: 20000
        0x80, 0x00,                         // Bridge Priority: 32768
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Bridge MAC
        0x80, 0x02,                         // Port ID: 0x8002
        0x01, 0x00,                         // Message Age: 1.0s (256/256)
        0x14, 0x00,                         // Max Age: 20.0s (5120/256)
        0x02, 0x00,                         // Hello Time: 2.0s (512/256)
        0x0f, 0x00                          // Forward Delay: 15.0s (3840/256)
    };

    packet::PacketInfo p = parse8023(payload);

    EXPECT_EQ(p.protocol, "STP");
    EXPECT_NE(p.info.find("Conf. Root = 32768 / 00:01:02:03:04:05"), std::string::npos);
    EXPECT_NE(p.info.find("Cost = 20000"), std::string::npos);
    EXPECT_NE(p.info.find("Port = 0x8002"), std::string::npos);

    EXPECT_TRUE(findLayer(p, "Logical-Link Control") != nullptr);
    EXPECT_TRUE(findLayer(p, "Spanning Tree Protocol") != nullptr);

    EXPECT_TRUE(matchFilter("llc", p));
    EXPECT_TRUE(matchFilter("llc.dsap == 0x42", p));
    EXPECT_TRUE(matchFilter("llc.ssap == 0x42", p));
    EXPECT_TRUE(matchFilter("llc.control == 0x03", p));

    EXPECT_TRUE(matchFilter("stp", p));
    EXPECT_TRUE(matchFilter("stp.protocol == 0", p));
    EXPECT_TRUE(matchFilter("stp.version == 0", p));
    EXPECT_TRUE(matchFilter("stp.bpdu.type == 0", p));
    EXPECT_TRUE(matchFilter("stp.flags == 1", p));
    EXPECT_TRUE(matchFilter("stp.flags.tc == 1", p));
    EXPECT_TRUE(matchFilter("stp.flags.tc_ack == 0", p));
    EXPECT_TRUE(matchFilter("stp.root.cost == 20000", p));
    EXPECT_TRUE(matchFilter("stp.port == 0x8002", p));
    EXPECT_TRUE(matchFilter("stp.root.id == \"32768 / 00:01:02:03:04:05\"", p));
    EXPECT_TRUE(matchFilter("stp.bridge.id == \"32768 / 00:11:22:33:44:55\"", p));

    EXPECT_TRUE(matchFilter("eth.len == 38", p));
    EXPECT_FALSE(matchFilter("eth.type", p));
}

TEST(LlcStpTest, RstpBpdu) {
    // 3 bytes LLC + 36 bytes RSTP BPDU
    std::vector<uint8_t> payload = {
        0x42, 0x42, 0x03,                   // LLC
        0x00, 0x00,                         // Protocol ID: 0
        0x02,                               // Version: 2 (RSTP)
        0x02,                               // BPDU Type: 0x02 (RST)
        0x7c,                               // Flags: Agree(0x40)|Fwd(0x20)|Learn(0x10)|Role Desig(0x0c)
        0x80, 0x00,                         // Root Priority
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Root MAC
        0x00, 0x00, 0x00, 0x00,             // Root Path Cost: 0
        0x80, 0x00,                         // Bridge Priority
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Bridge MAC
        0x80, 0x01,                         // Port ID
        0x00, 0x00,                         // Message Age: 0
        0x14, 0x00,                         // Max Age: 20s
        0x02, 0x00,                         // Hello Time: 2s
        0x0f, 0x00,                         // Forward Delay: 15s
        0x00                                // Version 1 Length: 0
    };

    packet::PacketInfo p = parse8023(payload);

    EXPECT_EQ(p.protocol, "RSTP");
    EXPECT_NE(p.info.find("RST. Root = 32768 / aa:bb:cc:dd:ee:ff"), std::string::npos);
    EXPECT_NE(p.info.find("Cost = 0"), std::string::npos);

    EXPECT_TRUE(findLayer(p, "Rapid Spanning Tree Protocol") != nullptr);

    EXPECT_TRUE(matchFilter("stp", p));
    EXPECT_TRUE(matchFilter("stp.version == 2", p));
    EXPECT_TRUE(matchFilter("stp.bpdu.type == 2", p));
    EXPECT_TRUE(matchFilter("stp.flags.agreement == 1", p));
    EXPECT_TRUE(matchFilter("stp.flags.forwarding == 1", p));
    EXPECT_TRUE(matchFilter("stp.flags.learning == 1", p));
    EXPECT_TRUE(matchFilter("stp.flags.port_role == 3", p)); // Designated
    EXPECT_TRUE(matchFilter("stp.flags.proposal == 0", p));
    EXPECT_TRUE(matchFilter("stp.flags.tc == 0", p));
}

TEST(LlcStpTest, StpTopologyChangeNotification) {
    // 3 bytes LLC + 4 bytes STP TCN
    std::vector<uint8_t> payload = {
        0x42, 0x42, 0x03, // LLC
        0x00, 0x00,       // Protocol ID: 0
        0x00,             // Version: 0
        0x80              // BPDU Type: 0x80 (TCN)
    };

    packet::PacketInfo p = parse8023(payload);

    EXPECT_EQ(p.protocol, "STP");
    EXPECT_EQ(p.info, "Topology Change Notification");

    EXPECT_TRUE(matchFilter("stp", p));
    EXPECT_TRUE(matchFilter("stp.bpdu.type == 0x80", p));
}

TEST(LlcStpTest, LlcSnapWithIpv4Udp) {
    // LLC/SNAP header (8 bytes):
    // DSAP 0xAA, SSAP 0xAA, Ctrl 0x03, OUI 0x000000, EtherType 0x0800
    std::vector<uint8_t> payload = {
        0xaa, 0xaa, 0x03,
        0x00, 0x00, 0x00,
        0x08, 0x00,
        // IPv4 Header (20 bytes)
        0x45, 0x00, 0x00, 0x24, // IPv4, IHL 5, Total Len 36
        0x12, 0x34, 0x00, 0x00, // ID, flags/frag
        0x40, 0x11, 0x00, 0x00, // TTL 64, Protocol UDP (17), checksum 0
        0x0a, 0x00, 0x00, 0x01, // Src: 10.0.0.1
        0x0a, 0x00, 0x00, 0x02, // Dst: 10.0.0.2
        // UDP Header (8 bytes)
        0x1f, 0x90, 0x00, 0x35, // Src port 8080, Dst port 53 (DNS)
        0x00, 0x10, 0x00, 0x00, // Len 16, Checksum
        // UDP payload (8 bytes)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };

    packet::PacketInfo p = parse8023(payload);

    EXPECT_EQ(p.protocol, "DNS"); // port 53 is DNS
    EXPECT_EQ(p.ip_version, 4);
    EXPECT_EQ(p.src_port, 8080);
    EXPECT_EQ(p.dst_port, 53);

    EXPECT_TRUE(findLayer(p, "Logical-Link Control") != nullptr);
    EXPECT_TRUE(findLayer(p, "Subnetwork Access Protocol (SNAP)") != nullptr);
    EXPECT_TRUE(findLayer(p, "Internet Protocol Version 4") != nullptr);

    EXPECT_TRUE(matchFilter("llc", p));
    EXPECT_TRUE(matchFilter("snap", p));
    EXPECT_TRUE(matchFilter("snap.oui == 0", p));
    EXPECT_TRUE(matchFilter("snap.type == 0x0800", p));
    EXPECT_TRUE(matchFilter("ip.src == 10.0.0.1", p));
    EXPECT_TRUE(matchFilter("ip.dst == 10.0.0.2", p));
    EXPECT_TRUE(matchFilter("udp.srcport == 8080", p));
    EXPECT_TRUE(matchFilter("udp.dstport == 53", p));
}

TEST(LlcStpTest, PureLlcNonSnap) {
    // LLC with DSAP = 0xE0, SSAP = 0xE0 (Novell NetWare IPX)
    std::vector<uint8_t> payload = {
        0xe0, 0xe0, 0x03,
        0x01, 0x02, 0x03, 0x04
    };

    packet::PacketInfo p = parse8023(payload);

    EXPECT_EQ(p.protocol, "LLC");
    EXPECT_NE(p.info.find("Novell NetWare IPX"), std::string::npos);

    EXPECT_TRUE(matchFilter("llc", p));
    EXPECT_TRUE(matchFilter("llc.dsap == 0xe0", p));
    EXPECT_TRUE(matchFilter("llc.ssap == 0xe0", p));
    EXPECT_TRUE(matchFilter("llc.control == 0x03", p));
    EXPECT_FALSE(matchFilter("snap", p));
    EXPECT_FALSE(matchFilter("stp", p));
}

TEST(LlcStpTest, TruncatedLlcAndStp) {
    // Truncated LLC (< 3 bytes)
    std::vector<uint8_t> shortLlc = { 0x42, 0x42 };
    packet::PacketInfo p1 = parse8023(shortLlc);
    EXPECT_TRUE(matchFilter("malformed", p1));

    // Truncated STP BPDU (< 35 bytes for Config BPDU)
    std::vector<uint8_t> shortStp = {
        0x42, 0x42, 0x03,
        0x00, 0x00, 0x00, 0x00 // only 4 bytes of STP
    };
    packet::PacketInfo p2 = parse8023(shortStp);
    EXPECT_TRUE(matchFilter("malformed", p2));
}
