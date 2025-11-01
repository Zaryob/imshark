#include <gtest/gtest.h>

#include <cstdint>
#include <string>
#include <vector>

#include <packet/packet_info.h>
#include <packet/packet_parser.h>
#include <stats/statistics.h>

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
        if (pad && eth.size() < 60) eth.resize(60, 0);

        std::vector<char> raw(eth.begin(), eth.end());
        packet::PacketParser parser;
        parser.parsePacket(pack, raw, dissect::ParseMode::Full);
        return pack;
    }

    packet::PacketInfo parseEthernetFrame(const std::vector<uint8_t> &frame) {
        packet::PacketInfo pack;
        pack.link_type = 1;
        std::vector<char> raw(frame.begin(), frame.end());
        packet::PacketParser parser;
        parser.parsePacket(pack, raw, dissect::ParseMode::Full);
        return pack;
    }

    std::vector<uint8_t> ipv4(uint8_t protocol, const std::vector<uint8_t> &payload) {
        const uint16_t total = static_cast<uint16_t>(20 + payload.size());
        std::vector<uint8_t> h = {
            0x45, 0x00, static_cast<uint8_t>(total >> 8), static_cast<uint8_t>(total & 0xff),
            0x00, 0x01, 0x00, 0x00,
            0x40, protocol, 0x00, 0x00,
            10, 1, 1, 1,
            10, 2, 2, 2
        };
        h.insert(h.end(), payload.begin(), payload.end());
        return h;
    }

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

    std::vector<uint8_t> dnsQuery() {
        return {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    }

    const stats::HierarchyNode *childOf(const stats::HierarchyNode &n, const std::string &name) {
        for (const auto &ch: n.children) if (ch.name == name) return &ch;
        return nullptr;
    }

    const stats::HierarchyNode *descend(const stats::HierarchyNode &root, const std::vector<std::string> &path) {
        const stats::HierarchyNode *node = &root;
        for (const auto &name: path) {
            node = childOf(*node, name);
            if (!node) return nullptr;
        }
        return node;
    }

    void expectContains(const stats::HierarchyNode &root, const std::vector<std::string> &path) {
        const stats::HierarchyNode *node = descend(root, path);
        ASSERT_NE(node, nullptr) << "missing chain node";
        std::string joined;
        for (const auto &p: path) joined += " > " + p;
        SCOPED_TRACE(joined);
        EXPECT_GE(node->packets, 1u);
    }

    stats::HierarchyNode hierarchyOf(const packet::PacketInfo &p) {
        return stats::protocolHierarchy({p}, nullptr);
    }
} // namespace

TEST(Hierarchy, EthernetIpv4UdpDns) {
    const auto p = parseEthernet(0x0800, ipv4(17, udp(40000, 53, dnsQuery())));
    const auto root = hierarchyOf(p);
    expectContains(root, {"Ethernet", "Internet Protocol Version 4", "User Datagram Protocol", "Domain Name System"});
    EXPECT_EQ(descend(root, {"Ethernet", "Internet Protocol Version 4", "User Datagram Protocol", "Domain Name System"})->packets, 1u);
}

TEST(Hierarchy, Ipv4InIpv4ShowsTunnelNode) {
    const auto p = parseEthernet(0x0800, ipv4(4, ipv4(17, udp(40000, 50000, {1, 2, 3, 4}))));
    const auto root = hierarchyOf(p);
    expectContains(root, {"Ethernet", "Internet Protocol Version 4", "IP-in-IP", "User Datagram Protocol"});
    EXPECT_EQ(descend(root, {"Ethernet", "Internet Protocol Version 4"})->children.size(), 1u) << "no spurious sibling next to IP-in-IP";
}

TEST(Hierarchy, Ipv6InIpv4Tunnel) {
    const auto p = parseEthernet(0x0800, ipv4(41, ipv6(17, udp(40000, 50000, {1, 2, 3, 4}))));
    const auto root = hierarchyOf(p);
    expectContains(root, {"Ethernet", "Internet Protocol Version 6", "IP-in-IP", "User Datagram Protocol"});
}

TEST(Hierarchy, GreCarriesInnerEthernetAndIp) {
    // GRE (proto 0x6558, transparent Ethernet bridging) -> IPv4 -> UDP.
    std::vector<uint8_t> greHeader = {0x00, 0x00, 0x65, 0x58};
    std::vector<uint8_t> innerEth = {
        0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb,
        0x08, 0x00
    };
    const auto innerIp = ipv4(17, udp(40000, 50000, {1, 2, 3, 4}));
    innerEth.insert(innerEth.end(), innerIp.begin(), innerIp.end());
    std::vector<uint8_t> payload = greHeader;
    payload.insert(payload.end(), innerEth.begin(), innerEth.end());

    const auto p = parseEthernet(0x0800, ipv4(47, payload));
    const auto root = hierarchyOf(p);
    expectContains(root, {"Ethernet", "Internet Protocol Version 4", "GRE", "User Datagram Protocol"});
}

TEST(Hierarchy, MplsShowsLabelStackBeforeInnerIp) {
    const uint32_t lse = (100u << 12) | (1u << 8) | 64u; // label 100, bottom of stack, TTL 64
    std::vector<uint8_t> mpls = {
        static_cast<uint8_t>(lse >> 24), static_cast<uint8_t>((lse >> 16) & 0xff),
        static_cast<uint8_t>((lse >> 8) & 0xff), static_cast<uint8_t>(lse & 0xff)
    };
    const auto innerIp = ipv4(17, udp(40000, 53, dnsQuery()));
    mpls.insert(mpls.end(), innerIp.begin(), innerIp.end());

    const auto p = parseEthernet(0x8847, mpls);
    const auto root = hierarchyOf(p);
    expectContains(root, {"Ethernet", "MultiProtocol Label Switching", "Internet Protocol Version 4", "User Datagram Protocol", "Domain Name System"});
}

TEST(Hierarchy, PppoeSessionToPppToIpv4) {
    // PPPoE Session (6 bytes) + PPP protocol 0x0021 (2 bytes) + IPv4/UDP.
    std::vector<uint8_t> pppoe = {0x11, 0x00, 0x00, 0x01}; // ver/type 1/1, code 0, session id 1
    const auto innerIp = ipv4(17, udp(40000, 53, dnsQuery()));
    const uint16_t pppPayloadLen = static_cast<uint16_t>(2 + innerIp.size());
    pppoe.push_back(static_cast<uint8_t>(pppPayloadLen >> 8));
    pppoe.push_back(static_cast<uint8_t>(pppPayloadLen & 0xff));
    pppoe.push_back(0x00); // PPP protocol high byte
    pppoe.push_back(0x21); // PPP protocol low byte: IPv4
    pppoe.insert(pppoe.end(), innerIp.begin(), innerIp.end());

    const auto p = parseEthernet(0x8864, pppoe);
    const auto root = hierarchyOf(p);
    expectContains(root, {"Ethernet", "PPPoE Session", "Internet Protocol Version 4", "User Datagram Protocol", "Domain Name System"});
}

TEST(Hierarchy, LldpIsLinkedDirectlyUnderEthernet) {
    std::vector<uint8_t> du = {
        0x02, 0x07, 4, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Chassis ID (MAC)
        0x04, 0x05, 5, 'e', 't', 'h', '0',                   // Port ID
        0x06, 0x02, 0x00, 0x78,                              // TTL 120
        0x00, 0x00                                           // End
    };
    const auto p = parseEthernet(0x88CC, du);
    const auto root = hierarchyOf(p);
    expectContains(root, {"Ethernet", "Link Layer Discovery Protocol"});
    EXPECT_EQ(descend(root, {"Ethernet"})->children.size(), 1u) << "no Data node under LLDP";
}

TEST(Hierarchy, LacpIsLinkedDirectlyUnderEthernet) {
    std::vector<uint8_t> lacp = {
        0x01, 0x01, // subtype LACP, version 1
        0x01, 0x16, // Actor TLV, length 22
        0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x00, 0x01, 0x00, 0xff, 0x00, 0x04, 0x3d, 0x00, 0x00, 0x00,
        0x00, 0x00 // Terminator
    };
    const auto p = parseEthernet(0x8809, lacp);
    const auto root = hierarchyOf(p);
    expectContains(root, {"Ethernet", "Slow Protocols"});
    EXPECT_EQ(descend(root, {"Ethernet"})->children.size(), 1u);
}

TEST(Hierarchy, PauseAndPfcAreMacControl) {
    std::vector<uint8_t> pause = {0x00, 0x01, 0x00, 0x10, 0, 0, 0, 0, 0, 0, 0, 0};
    for (uint16_t opcode: {static_cast<uint16_t>(0x0001), static_cast<uint16_t>(0x0101)}) {
        std::vector<uint8_t> frame = pause;
        frame[0] = static_cast<uint8_t>(opcode >> 8);
        frame[1] = static_cast<uint8_t>(opcode & 0xff);
        const auto p = parseEthernet(0x8808, frame);
        const auto root = hierarchyOf(p);
        expectContains(root, {"Ethernet", "Ethernet MAC Control"});
    }
}

TEST(Hierarchy, Ieee8023StpIsSpanningTreeUnderEthernet) {
    std::vector<uint8_t> llc = {
        0x42, 0x42, 0x03,                   // LLC: STP DSAP/SSAP/control
        0x00, 0x00, 0x00, 0x00,             // protocol id, version, BPDU type
        0x01,                               // flags
        0x80, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
        0x00, 0x00, 0x4e, 0x20,
        0x80, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x80, 0x02,
        0x01, 0x00, 0x14, 0x00, 0x02, 0x00, 0x0f, 0x00
    };
    std::vector<uint8_t> frame = {
        0x01, 0x80, 0xc2, 0x00, 0x00, 0x00, // STP multicast DA
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // SA
        static_cast<uint8_t>(llc.size() >> 8), static_cast<uint8_t>(llc.size() & 0xff) // 802.3 length
    };
    frame.insert(frame.end(), llc.begin(), llc.end());
    if (frame.size() < 60) frame.resize(60, 0);

    const auto p = parseEthernetFrame(frame);
    const auto root = hierarchyOf(p);
    expectContains(root, {"Ethernet", "Spanning Tree Protocol"});
    EXPECT_EQ(descend(root, {"Ethernet"})->children.size(), 1u) << "no Data node next to STP";
}

TEST(Hierarchy, TruncatedEncapsulationsNeverCrash) {
    const uint32_t lse = (100u << 12) | (1u << 8) | 64u;
    const std::vector<std::vector<uint8_t>> payloads = {
        {0x00},                                     // PPPoE too short
        {0x45},                                     // GRE too short as IPv4 payload
        {static_cast<uint8_t>(lse >> 24), static_cast<uint8_t>((lse >> 16) & 0xff)}, // partial MPLS LSE
        {},                                         // empty LLDP
        {0x01},                                     // LACP subtype only
        {0x88, 0xCC},                               // unknown/truncated
    };
    const std::vector<uint16_t> types = {0x8864, 0x0800, 0x8847, 0x88CC, 0x8809, 0x0800};
    for (size_t i = 0; i < payloads.size(); ++i) {
        const auto p = parseEthernet(types[i], payloads[i], false);
        const auto root = hierarchyOf(p);   // must not crash, must keep Frame root
        EXPECT_EQ(root.name, "Frame");
        EXPECT_EQ(root.packets, 1u);
    }
}

