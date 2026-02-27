#include <gtest/gtest.h>

#include <functional>
#include <map>
#include <numeric>

#include <core.h>
#include <filter/filter.h>
#include <stats/statistics.h>

namespace {
    struct Sample {
        std::vector<packet::PacketInfo> packets;
        Sample() {
            core::FileProcessor fp;
            std::string message;
            fp.processPcapFile(IMSHARK_TEST_DATA_DIR "/sample.pcap", packets, message);
        }
    };

    std::vector<int> numbersMatching(const std::vector<packet::PacketInfo> &packets, const std::string &expr) {
        auto r = filter::Filter::compile(expr);
        EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
        std::vector<int> out;
        for (const auto &p: packets) if (r.filter.matches(p)) out.push_back(p.number);
        return out;
    }
} // namespace

TEST(Stats, IpEndpointsAddUpConsistently) {
    Sample s;
    const auto eps = stats::endpoints(s.packets, nullptr, stats::AddressKind::Ipv4);
    ASSERT_FALSE(eps.empty());
    uint64_t packets = 0, tx = 0, rx = 0;
    for (const auto &e: eps) {
        EXPECT_EQ(e.packets, e.txPackets + e.rxPackets);
        EXPECT_EQ(e.bytes, e.txBytes + e.rxBytes);
        packets += e.packets; tx += e.txPackets; rx += e.rxPackets;
    }
    uint64_t ipv4 = 0;
    for (const auto &p: s.packets) ipv4 += p.ip_version == 4;
    EXPECT_EQ(tx, ipv4) << "every IPv4 packet has exactly one sender";
    EXPECT_EQ(rx, ipv4) << "and one receiver";
    EXPECT_EQ(packets, 2 * ipv4);
    for (size_t i = 1; i < eps.size(); ++i) EXPECT_GE(eps[i - 1].bytes, eps[i].bytes) << "sorted by bytes";

    const auto v6 = stats::endpoints(s.packets, nullptr, stats::AddressKind::Ipv6);
    ASSERT_EQ(v6.size(), 2u);
    EXPECT_EQ(v6[0].packets, 1u);
}

TEST(Stats, TcpConversationsMatchTheHandshakeInTheSample) {
    Sample s;
    const auto convs = stats::conversations(s.packets, nullptr, stats::AddressKind::Tcp);
    const stats::Conversation *web = nullptr, *smtp = nullptr;
    for (const auto &c: convs) {
        if (c.portB == 80 || c.portA == 80) web = &c;
        if (c.portB == 25 || c.portA == 25) smtp = &c;
    }
    ASSERT_NE(web, nullptr);
    ASSERT_NE(smtp, nullptr);
    EXPECT_EQ(web->packets, 5u);
    EXPECT_EQ(web->addressA, "10.0.0.1") << "A is the sender of the first packet (the SYN)";
    EXPECT_EQ(web->portB, 80);
    EXPECT_EQ(web->packetsAtoB, 3u);
    EXPECT_EQ(web->packetsBtoA, 2u);
    EXPECT_EQ(web->packets, web->packetsAtoB + web->packetsBtoA);
    EXPECT_EQ(web->bytes, web->bytesAtoB + web->bytesBtoA);
    EXPECT_EQ(web->firstPacket, 7);
    EXPECT_GT(web->duration, 0.0);
    EXPECT_EQ(smtp->packets, 1u);
}

TEST(Stats, ConversationFiltersSelectExactlyTheirPackets) {
    Sample s;
    for (auto kind: {stats::AddressKind::Ipv4, stats::AddressKind::Ipv6, stats::AddressKind::Tcp, stats::AddressKind::Udp}) {
        SCOPED_TRACE(stats::kindName(kind));
        for (const auto &c: stats::conversations(s.packets, nullptr, kind)) {
            const auto matched = numbersMatching(s.packets, stats::conversationFilter(c, kind));
            EXPECT_EQ(matched.size(), c.packets) << stats::conversationFilter(c, kind);
        }
        for (const auto &e: stats::endpoints(s.packets, nullptr, kind)) {
            const auto matched = numbersMatching(s.packets, stats::endpointFilter(e, kind));
            EXPECT_EQ(matched.size(), e.packets) << stats::endpointFilter(e, kind);
        }
    }
}

TEST(Stats, SubsetLimitsWhatIsCounted) {
    Sample s;
    std::vector<uint32_t> tcpOnly;
    for (size_t i = 0; i < s.packets.size(); ++i) if (s.packets[i].ip_protocol == 6 && s.packets[i].ip_version) tcpOnly.push_back(static_cast<uint32_t>(i));
    EXPECT_TRUE(stats::conversations(s.packets, &tcpOnly, stats::AddressKind::Udp).empty());
    EXPECT_EQ(stats::conversations(s.packets, &tcpOnly, stats::AddressKind::Tcp).size(), stats::conversations(s.packets, nullptr, stats::AddressKind::Tcp).size());
    std::vector<uint32_t> none;
    EXPECT_TRUE(stats::endpoints(s.packets, &none, stats::AddressKind::Ipv4).empty());
    EXPECT_EQ(stats::protocolHierarchy(s.packets, &none).packets, 0u);
    std::vector<uint32_t> outOfRange = {9999};
    EXPECT_TRUE(stats::endpoints(s.packets, &outOfRange, stats::AddressKind::Ipv4).empty()) << "stale indices are ignored";
}

TEST(Stats, ProtocolHierarchy) {
    Sample s;
    const auto root = stats::protocolHierarchy(s.packets, nullptr);
    EXPECT_EQ(root.name, "Frame");
    EXPECT_EQ(root.packets, s.packets.size());
    uint64_t bytes = 0;
    for (const auto &p: s.packets) bytes += p.frame_length;
    EXPECT_EQ(root.bytes, bytes);

    auto child = [](const stats::HierarchyNode &n, const std::string &name) -> const stats::HierarchyNode * {
        for (const auto &c: n.children) if (c.name == name) return &c;
        return nullptr;
    };
    const auto *eth = child(root, "Ethernet");
    ASSERT_NE(eth, nullptr);
    EXPECT_EQ(eth->packets, 16u);
    const auto *ip4 = child(*eth, "Internet Protocol Version 4");
    const auto *arp = child(*eth, "Address Resolution Protocol");
    ASSERT_NE(ip4, nullptr);
    ASSERT_NE(arp, nullptr);
    EXPECT_EQ(arp->packets, 2u);
    const auto *tcp = child(*ip4, "Transmission Control Protocol");
    const auto *udp = child(*ip4, "User Datagram Protocol");
    ASSERT_NE(tcp, nullptr);
    ASSERT_NE(udp, nullptr);
    EXPECT_NE(child(*tcp, "Simple Mail Transfer Protocol"), nullptr);
    EXPECT_NE(child(*udp, "Domain Name System"), nullptr);
    // children never exceed their parent, and are sorted by bytes
    std::function<void(const stats::HierarchyNode &)> check = [&](const stats::HierarchyNode &n) {
        uint64_t sumPackets = 0;
        for (size_t i = 0; i < n.children.size(); ++i) {
            sumPackets += n.children[i].packets;
            if (i) EXPECT_GE(n.children[i - 1].bytes, n.children[i].bytes);
            check(n.children[i]);
        }
        EXPECT_LE(sumPackets, n.packets + 0) << n.name;
    };
    check(root);
}

TEST(Stats, EmptyCaptureIsHandled) {
    std::vector<packet::PacketInfo> none;
    EXPECT_TRUE(stats::endpoints(none, nullptr, stats::AddressKind::Tcp).empty());
    EXPECT_TRUE(stats::conversations(none, nullptr, stats::AddressKind::Ipv6).empty());
    const auto root = stats::protocolHierarchy(none, nullptr);
    EXPECT_EQ(root.packets, 0u);
    EXPECT_TRUE(root.children.empty());
}

TEST(Stats, ExpertInfoCountsWhatTheFiltersFind) {
    Sample s;
    const auto items = stats::expertInfo(s.packets, nullptr);
    auto count = [&](const std::string &filterText) -> uint64_t {
        for (const auto &i: items) if (i.filter == filterText) return i.count;
        return 0;
    };
    EXPECT_EQ(count("malformed"), 1u) << "the truncated TCP packet of the sample";
    EXPECT_EQ(count("tcp.flags.syn && !tcp.flags.ack"), 1u);
    EXPECT_EQ(count("tcp.flags.fin"), 1u);
    EXPECT_EQ(count("tcp.flags.rst"), 0u) << "items that do not occur are not listed";
    for (size_t i = 1; i < items.size(); ++i) EXPECT_GE(items[i - 1].severity, items[i].severity) << "most severe first";
    EXPECT_EQ(items.front().severity, stats::Severity::Error);

    // every item's filter selects exactly `count` packets
    for (const auto &item: items) {
        auto f = filter::Filter::compile(item.filter);
        ASSERT_TRUE(f.ok);
        uint64_t n = 0;
        for (const auto &p: s.packets) n += f.filter.matches(p);
        EXPECT_EQ(n, item.count) << item.summary;
    }

    std::vector<uint32_t> udpOnly = {4, 5, 12, 13};
    for (const auto &item: stats::expertInfo(s.packets, &udpOnly)) {
        // the generated sample has all-zero checksums: IPv4 ones are unverified/unused, IPv6 UDP with a zero checksum is invalid
        if (item.summary.find("hecksum") == std::string::npos) ADD_FAILURE() << item.summary << ": nothing else is noteworthy in the UDP packets";
    }
    EXPECT_TRUE(stats::expertInfo({}, nullptr).empty());
}

TEST(Stats, GeneralizedAddressKindsProduceExpectedFiltersAndEndpoints) {
    Sample s;
    // Ethernet endpoints & conversations
    const auto ethEps = stats::endpoints(s.packets, nullptr, stats::AddressKind::Ethernet);
    ASSERT_FALSE(ethEps.empty());
    for (const auto &ep: ethEps) {
        EXPECT_FALSE(ep.address.empty());
        auto filterStr = stats::endpointFilter(ep, stats::AddressKind::Ethernet);
        EXPECT_NE(filterStr.find("eth.addr =="), std::string::npos);
        auto compiled = filter::Filter::compile(filterStr);
        EXPECT_TRUE(compiled.ok) << "Ethernet endpoint filter compile failed: " << filterStr;
    }

    const auto ethConvs = stats::conversations(s.packets, nullptr, stats::AddressKind::Ethernet);
    ASSERT_FALSE(ethConvs.empty());
    auto ethConvFilter = stats::conversationFilter(ethConvs.front(), stats::AddressKind::Ethernet);
    EXPECT_NE(ethConvFilter.find("eth.addr =="), std::string::npos);
    EXPECT_TRUE(filter::Filter::compile(ethConvFilter).ok);

    // Synthetic packet for SCTP, WLAN, BT, and USB
    packet::PacketInfo p;
    p.number = 1;
    p.length = 64;
    p.frame_length = 64;
    p.ip_version = 4;
    p.source = "192.168.1.10";
    p.destination = "192.168.1.20";
    p.protocol = "SCTP";
    p.ip_protocol = 132;
    p.src_port = 3868;
    p.dst_port = 3868;

    std::vector<packet::PacketInfo> synthetic = {p};

    // SCTP
    auto sctpEps = stats::endpoints(synthetic, nullptr, stats::AddressKind::Sctp);
    ASSERT_EQ(sctpEps.size(), 2u);
    auto sctpConvs = stats::conversations(synthetic, nullptr, stats::AddressKind::Sctp);
    ASSERT_EQ(sctpConvs.size(), 1u);
    EXPECT_TRUE(filter::Filter::compile(stats::conversationFilter(sctpConvs.front(), stats::AddressKind::Sctp)).ok);

    // WLAN synthetic packet
    packet::PacketInfo pWlan;
    pWlan.number = 2;
    pWlan.frame_length = 64;
    pWlan.link_type = 105;
    pWlan.protocol = "802.11";
    pWlan.source = "00:11:22:33:44:55";
    pWlan.destination = "aa:bb:cc:dd:ee:ff";
    std::vector<packet::PacketInfo> synWlan = {pWlan};

    auto wlanEps = stats::endpoints(synWlan, nullptr, stats::AddressKind::Wlan);
    ASSERT_EQ(wlanEps.size(), 2u);
    auto wlanConvs = stats::conversations(synWlan, nullptr, stats::AddressKind::Wlan);
    ASSERT_EQ(wlanConvs.size(), 1u);
    EXPECT_TRUE(filter::Filter::compile(stats::conversationFilter(wlanConvs.front(), stats::AddressKind::Wlan)).ok);

    // Bluetooth synthetic packet
    packet::PacketInfo pBt;
    pBt.number = 3;
    pBt.frame_length = 64;
    pBt.link_type = 187;
    pBt.protocol = "HCI";
    pBt.source = "0x0001";
    pBt.destination = "0x0001";
    std::vector<packet::PacketInfo> synBt = {pBt};

    auto btEps = stats::endpoints(synBt, nullptr, stats::AddressKind::Bluetooth);
    ASSERT_EQ(btEps.size(), 1u);
    auto btConvs = stats::conversations(synBt, nullptr, stats::AddressKind::Bluetooth);
    ASSERT_EQ(btConvs.size(), 1u);
    EXPECT_TRUE(filter::Filter::compile(stats::conversationFilter(btConvs.front(), stats::AddressKind::Bluetooth)).ok);

    // USB synthetic packet
    packet::PacketInfo pUsb;
    pUsb.number = 4;
    pUsb.frame_length = 64;
    pUsb.link_type = 189;
    pUsb.protocol = "USB";
    pUsb.source = "1.2.0";
    pUsb.destination = "host";
    std::vector<packet::PacketInfo> synUsb = {pUsb};

    auto usbEps = stats::endpoints(synUsb, nullptr, stats::AddressKind::Usb);
    ASSERT_EQ(usbEps.size(), 2u);
    auto usbConvs = stats::conversations(synUsb, nullptr, stats::AddressKind::Usb);
    ASSERT_EQ(usbConvs.size(), 1u);
    EXPECT_TRUE(filter::Filter::compile(stats::conversationFilter(usbConvs.front(), stats::AddressKind::Usb)).ok);
}
