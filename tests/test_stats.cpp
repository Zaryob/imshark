#include <gtest/gtest.h>

#include <functional>
#include <map>
#include <numeric>
#include <set>

#include <core.h>
#include <dissect/session.h>
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

// ---- B8: addresses of parsed Ethernet, Bluetooth and USB packets (not hand-filled summaries)

#include "frame_sweep.h"

namespace {
    std::vector<packet::PacketInfo> parseSequence(uint32_t linkType, const std::vector<framesweep::Bytes> &frames) {
        packet::PacketParser parser;
        std::vector<packet::PacketInfo> out;
        int number = 1;
        for (const auto &f: frames) {
            packet::PacketInfo pack(number++);
            pack.link_type = linkType;
            std::vector<char> raw(f.begin(), f.end());
            parser.parsePacket(pack, raw, dissect::ParseMode::Summary);
            pack.frame_length = pack.captured_length = static_cast<uint32_t>(f.size());
            out.push_back(std::move(pack));
        }
        return out;
    }

    size_t countMatches(const std::vector<packet::PacketInfo> &packets, const std::string &text) {
        const auto f = filter::Filter::compile(text);
        EXPECT_TRUE(f.ok) << text;
        size_t n = 0;
        for (const auto &p: packets) n += f.ok && f.filter.matches(p);
        return n;
    }

    std::set<std::string> addresses(const std::vector<stats::Endpoint> &eps) {
        std::set<std::string> out;
        for (const auto &e: eps) out.insert(e.address);
        return out;
    }
} // namespace

TEST(Stats, BluetoothEndpointsOfParsedPackets) {
    using framesweep::Bytes;
    // HCI command, ACL TX and ACL RX of one connection (handle 0x0040), Linux monitor pseudo header (adapter 0)
    const Bytes cmd = {0, 0, 0, 2, 0x0c, 0x20, 0x00};
    const Bytes acl = {0x40, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x02, 0x00, 0x02};
    auto mon = [&](uint8_t opcode) { Bytes b = {0, 0, 0, opcode}; b.insert(b.end(), acl.begin(), acl.end()); return b; };
    const auto packets = parseSequence(254, {cmd, mon(4), mon(5)});

    const auto eps = stats::endpoints(packets, nullptr, stats::AddressKind::Bluetooth);
    EXPECT_EQ(addresses(eps), (std::set<std::string>{"host", "hci0", "0x0040"}));
    const auto convs = stats::conversations(packets, nullptr, stats::AddressKind::Bluetooth);
    ASSERT_EQ(convs.size(), 2u);   // host <-> hci0 (the command) and host <-> 0x0040 (both ACL directions)

    for (const auto &e: eps) {
        const auto text = stats::endpointFilter(e, stats::AddressKind::Bluetooth);
        if (e.address == "0x0040") {
            EXPECT_EQ(text, "bt.handle == \"0x0040\"");
            EXPECT_EQ(countMatches(packets, text), 2u);
        } else if (e.address == "hci0") {
            EXPECT_EQ(text, "bt.addr == \"hci0\"");
            EXPECT_EQ(countMatches(packets, text), 1u);
        } else {
            EXPECT_EQ(text, "bt.addr == \"host\"");
            EXPECT_EQ(countMatches(packets, text), 3u);
        }
    }
    for (const auto &c: convs) {
        const auto text = stats::conversationFilter(c, stats::AddressKind::Bluetooth);
        EXPECT_NE(text.find("&&"), std::string::npos) << "both addresses: " << text;
        EXPECT_EQ(countMatches(packets, text), c.packets) << text;
    }
    // the generic fields do not match anything but Bluetooth packets
    EXPECT_EQ(countMatches(parseSequence(1, {framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(1, 2, {1})))}),
                           "bt.handle == \"0x0040\" || bt.addr == \"10.0.0.1\" || bt.handle"), 0u);
}

TEST(Stats, UsbEndpointsOfParsedPackets) {
    using framesweep::Bytes;
    auto urb = [](char event, uint8_t xfer, uint8_t endpoint, uint8_t device) {
        Bytes b = {1, 0, 0, 0, 0, 0, 0, 0, static_cast<uint8_t>(event), xfer, endpoint, device, 1, 0, '-', '<'};
        b.resize(48, 0);
        return b;
    };
    const auto packets = parseSequence(189, {urb('S', 3, 0x02, 3), urb('C', 3, 0x02, 3), urb('S', 3, 0x81, 4), urb('C', 3, 0x81, 4)});

    const auto eps = stats::endpoints(packets, nullptr, stats::AddressKind::Usb);
    EXPECT_EQ(addresses(eps), (std::set<std::string>{"host", "1.3", "1.4"}));
    for (const auto &e: eps) {
        const auto text = stats::endpointFilter(e, stats::AddressKind::Usb);
        if (e.address == "host") EXPECT_EQ(text, "usb");
        else EXPECT_EQ(text, "usb.device == \"" + e.address + "\"");
        EXPECT_EQ(countMatches(packets, text), e.address == "host" ? 4u : 2u) << text;
    }
    const auto convs = stats::conversations(packets, nullptr, stats::AddressKind::Usb);
    ASSERT_EQ(convs.size(), 2u);
    for (const auto &c: convs) {
        const auto text = stats::conversationFilter(c, stats::AddressKind::Usb);
        EXPECT_NE(text, "usb");
        EXPECT_NE(text.find("usb.device == \"1."), std::string::npos) << text;
        EXPECT_EQ(countMatches(packets, text), 2u) << text;
    }
    // the filter fields are gated: an IP packet never matches them, even when it has an address of the same text
    const auto ip = parseSequence(1, {framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(1, 2, {1})))});
    EXPECT_EQ(countMatches(ip, "usb.device"), 0u);
    EXPECT_EQ(countMatches(ip, "usb.device == \"10.0.0.1\""), 0u);
    EXPECT_EQ(countMatches(ip, "usb.device == \"host\""), 0u);
}

TEST(Stats, EthernetTabListsMacAddressesNotIpStrings) {
    using framesweep::Bytes;
    const auto ipFrame = framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(1000, 2000, {1, 2})));
    const auto otherFrame = framesweep::ethernet(0x88B5, {1, 2, 3, 4});   // an experimental EtherType: no IP layer replaces the MACs
    const auto packets = parseSequence(1, {ipFrame, otherFrame});
    ASSERT_EQ(packets[0].source, "10.0.0.1");
    ASSERT_EQ(packets[1].source, "66:77:88:99:aa:bb");

    const auto eps = stats::endpoints(packets, nullptr, stats::AddressKind::Ethernet);
    ASSERT_EQ(eps.size(), 2u);
    for (const auto &e: eps) {
        EXPECT_TRUE(packet::isMacAddress(e.address)) << e.address;
        EXPECT_EQ(countMatches(packets, stats::endpointFilter(e, stats::AddressKind::Ethernet)), 1u);
    }
    EXPECT_EQ(addresses(eps), (std::set<std::string>{"66:77:88:99:aa:bb", "00:11:22:33:44:55"}));
    // IP frames show up in the IP tabs, and the eth.* fields do not pretend that an IP string is a MAC
    EXPECT_EQ(stats::endpoints(packets, nullptr, stats::AddressKind::Ipv4).size(), 2u);
    EXPECT_EQ(countMatches(packets, "eth.addr == \"10.0.0.1\""), 0u);
    EXPECT_EQ(countMatches(packets, "eth.src == \"66:77:88:99:aa:bb\""), 1u);
}

TEST(Stats, TheLoadPassRecordsTheMacAddressesOfEveryEthernetFrame) {
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(fp.processPcapFile(IMSHARK_TEST_DATA_DIR "/sample.pcap", packets, message));
    const auto &macs = fp.sessions().ethernetAddresses();
    size_t ethernet = 0, ip = 0;
    for (const auto &p: packets) {
        if (p.link_type != 1) continue;
        ++ethernet;
        ip += p.ip_version != 0;
        ASSERT_NE(macs.find(static_cast<uint32_t>(p.number)), nullptr) << p.number;
        // frames the summary still holds MACs for agree with the table
        if (packet::isMacAddress(p.source)) EXPECT_EQ(packet::EthernetAddressTable::format(macs.find(static_cast<uint32_t>(p.number))->source), p.source);
    }
    EXPECT_EQ(macs.size(), ethernet);
    ASSERT_GT(ip, 0u) << "the sample has IP frames";
    // Replay never adds to the table: dissecting a packet again for its details leaves it as it was
    packet::PacketInfo details;
    ASSERT_TRUE(core::buildPacketDetails(IMSHARK_TEST_DATA_DIR "/sample.pcap", packets[0], details, &packets, &fp.captureInfo(), nullptr, &fp.sessions()));
    EXPECT_EQ(fp.sessions().ethernetAddresses().size(), ethernet);
}

TEST(Stats, EthernetAddressTableBoundsAndOrder) {
    const uint8_t a[6] = {1, 2, 3, 4, 5, 6}, b[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    packet::EthernetAddressTable t;
    EXPECT_TRUE(t.add(5, a, b, 2));
    EXPECT_FALSE(t.add(5, a, b, 2)) << "a packet is recorded once";
    EXPECT_FALSE(t.add(4, a, b, 2)) << "numbers increase";
    EXPECT_TRUE(t.add(9, b, a, 2));
    EXPECT_FALSE(t.add(10, a, b, 2)) << "beyond the cap";
    ASSERT_NE(t.find(9), nullptr);
    EXPECT_EQ(packet::EthernetAddressTable::format(t.find(9)->source), "aa:bb:cc:dd:ee:ff");
    EXPECT_EQ(t.find(6), nullptr);
    EXPECT_EQ(t.find(10), nullptr);
    EXPECT_EQ(t.find(0), nullptr);

    // a table that is full stops recording and says so; the tables are frozen after the load
    dissect::SessionTables tables(sizeof(packet::EthernetAddressTable::Entry) * 2);
    EXPECT_TRUE(tables.addEthernetAddresses(1, a, b));
    EXPECT_TRUE(tables.addEthernetAddresses(2, a, b));
    EXPECT_FALSE(tables.addEthernetAddresses(3, a, b));
    EXPECT_TRUE(tables.isTableStateLost("ethernet"));
    tables.clear();
    tables.freeze();
    EXPECT_FALSE(tables.addEthernetAddresses(1, a, b));
    EXPECT_TRUE(tables.ethernetAddresses().empty());
}
