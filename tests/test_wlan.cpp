#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include <dissect/checksum.h>
#include <filter/filter.h>
#include <packet/packet_info.h>
#include <packet/packet_parser.h>

namespace {
    packet::PacketInfo parse80211(const std::vector<uint8_t> &data, dissect::ParseMode mode = dissect::ParseMode::Full) {
        packet::PacketInfo pack;
        pack.link_type = 105; // IEEE 802.11
        std::vector<char> raw(data.begin(), data.end());
        packet::PacketParser parser;
        parser.parsePacket(pack, raw, mode);
        return pack;
    }

    bool matchFilter(const std::string &expr, const packet::PacketInfo &p) {
        auto r = filter::Filter::compile(expr);
        return r.ok && r.filter.matches(p);
    }

    const packet::Field *findLayer(const packet::PacketInfo &p, const std::string &prefix) {
        for (const auto &f : p.fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
        }
        return nullptr;
    }
} // namespace

TEST(Wlan, BeaconFrameDecodesFieldsAndFilters) {
    // Beacon frame
    // Frame Control: Subtype 8 (Beacon), Type 0 (Mgmt), Flags 0x00 -> 0x80, 0x00
    // Duration: 0x00, 0x00
    // DA: ff:ff:ff:ff:ff:ff
    // SA: 00:11:22:33:44:55
    // BSSID: 00:11:22:33:44:55
    // SeqCtrl: 0x10, 0x00 (Seq 1, Frag 0)
    // Fixed: Timestamp (8B), Interval (100 TU = 0x64, 0x00), Capability (0x31, 0x04)
    // IE 0: SSID "TestWlan"
    // IE 3: DS Channel 6
    std::vector<uint8_t> frame = {
        0x80, 0x00,                         // FC
        0x00, 0x00,                         // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // DA
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // SA
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // BSSID
        0x10, 0x00,                         // SeqCtrl
        // Fixed parameters
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Timestamp
        0x64, 0x00,                         // Beacon Interval
        0x31, 0x04,                         // Capability
        // IE 0: SSID
        0x00, 0x08, 'T', 'e', 's', 't', 'W', 'l', 'a', 'n',
        // IE 3: DS Channel
        0x03, 0x01, 0x06
    };

    auto pack = parse80211(frame);
    EXPECT_EQ(pack.protocol, "802.11");
    EXPECT_NE(pack.info.find("TestWlan"), std::string::npos);
    EXPECT_NE(pack.info.find("Channel: 6"), std::string::npos);
    EXPECT_EQ(pack.destination, "ff:ff:ff:ff:ff:ff");
    EXPECT_EQ(pack.source, "00:11:22:33:44:55");
    EXPECT_EQ(pack.wlan_seq, 1u);

    // Filters
    EXPECT_TRUE(matchFilter("wlan", pack));
    EXPECT_TRUE(matchFilter("wlan.fc.type == 0", pack));
    EXPECT_TRUE(matchFilter("wlan.fc.subtype == 8", pack));
    EXPECT_TRUE(matchFilter("wlan.fc.protected == 0", pack));
    EXPECT_TRUE(matchFilter("wlan.seq == 1", pack));
    EXPECT_TRUE(matchFilter("wlan.ssid == \"TestWlan\"", pack));
    EXPECT_TRUE(matchFilter("wlan.bssid == \"00:11:22:33:44:55\"", pack));
    EXPECT_TRUE(matchFilter("wlan.sa == \"00:11:22:33:44:55\"", pack));
    EXPECT_TRUE(matchFilter("wlan.da == \"ff:ff:ff:ff:ff:ff\"", pack));

    // Field tree
    ASSERT_GE(pack.fields.size(), 2u);
    const auto *wlanLayer = findLayer(pack, "IEEE 802.11 Beacon frame");
    ASSERT_NE(wlanLayer, nullptr);
    const auto *bodyLayer = findLayer(pack, "Management Frame Body");
    ASSERT_NE(bodyLayer, nullptr);
}

TEST(Wlan, ProbeRequestAndControlFrames) {
    // Probe Request (Broadcast SSID)
    std::vector<uint8_t> probeReq = {
        0x40, 0x00,                         // FC (Subtype 4)
        0x00, 0x00,                         // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // DA
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // SA
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // BSSID
        0x20, 0x00,                         // SeqCtrl (Seq 2)
        0x00, 0x00                          // IE 0: Wildcard SSID (len 0)
    };
    auto pProbe = parse80211(probeReq);
    EXPECT_EQ(pProbe.protocol, "802.11");
    EXPECT_NE(pProbe.info.find("Probe Request"), std::string::npos);
    EXPECT_NE(pProbe.info.find("<Broadcast>"), std::string::npos);
    EXPECT_TRUE(matchFilter("wlan.fc.subtype == 4", pProbe));
    EXPECT_TRUE(matchFilter("wlan.seq == 2", pProbe));

    // Control frame: ACK (10 bytes)
    std::vector<uint8_t> ack = {
        0xd4, 0x00,                         // FC: Subtype 13 ACK, Type 1 Control
        0x00, 0x00,                         // Duration
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55  // RA
    };
    auto pAck = parse80211(ack);
    EXPECT_EQ(pAck.protocol, "802.11");
    EXPECT_NE(pAck.info.find("Acknowledgement"), std::string::npos);
    EXPECT_EQ(pAck.destination, "00:11:22:33:44:55");
    EXPECT_TRUE(matchFilter("wlan.fc.type == 1", pAck));
    EXPECT_TRUE(matchFilter("wlan.fc.subtype == 13", pAck));

    // Control frame: CTS (10 bytes)
    std::vector<uint8_t> cts = {
        0xc4, 0x00,                         // FC: Subtype 12 CTS
        0x50, 0x00,                         // Duration
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55  // RA
    };
    auto pCts = parse80211(cts);
    EXPECT_NE(pCts.info.find("Clear to Send"), std::string::npos);
    EXPECT_TRUE(matchFilter("wlan.fc.subtype == 12", pCts));

    // Control frame: RTS (16 bytes)
    std::vector<uint8_t> rts = {
        0xb4, 0x00,                         // FC: Subtype 11 RTS
        0x60, 0x00,                         // Duration
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // RA
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff  // TA
    };
    auto pRts = parse80211(rts);
    EXPECT_NE(pRts.info.find("Request to Send"), std::string::npos);
    EXPECT_EQ(pRts.destination, "00:11:22:33:44:55");
    EXPECT_EQ(pRts.source, "aa:bb:cc:dd:ee:ff");
    EXPECT_TRUE(matchFilter("wlan.fc.subtype == 11", pRts));
}

TEST(Wlan, CleartextDataUnwrapsToIpv4TcpHttp) {
    // 802.11 QoS Data Frame carrying LLC/SNAP -> IPv4 -> TCP -> HTTP GET
    // FC: Subtype 8 (QoS Data), Type 2 (Data), FromDS = 1 -> 0x88, 0x02
    // Duration: 0x00, 0x00
    // Addr1 (RA/DA): aa:bb:cc:dd:ee:ff
    // Addr2 (TA/BSSID): 00:11:22:33:44:55
    // Addr3 (SA): 12:34:56:78:9a:bc
    // SeqCtrl: 0x50, 0x00 (Seq 5)
    // QoS Ctrl: 0x02, 0x00 (TID 2)
    // LLC/SNAP: AA AA 03 00 00 00 08 00 (IPv4)
    std::vector<uint8_t> frame = {
        0x88, 0x02,                         // FC
        0x00, 0x00,                         // Duration
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Addr1 (DA)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Addr2 (BSSID)
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, // Addr3 (SA)
        0x50, 0x00,                         // SeqCtrl
        0x02, 0x00,                         // QoS Ctrl (TID 2)
        // LLC/SNAP (8 bytes)
        0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00
    };

    // IPv4 Header (20 bytes): 192.168.1.100 -> 192.168.1.1, TCP
    const std::string httpPayload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
    const uint16_t tcpLen = 20 + static_cast<uint16_t>(httpPayload.size());
    const uint16_t ipTotalLen = 20 + tcpLen;

    std::vector<uint8_t> ipHeader = {
        0x45, 0x00,                         // Version 4, IHL 5
        static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
        0x12, 0x34,                         // Identification
        0x40, 0x00,                         // Flags: Don't Fragment
        64, 6,                              // TTL 64, Protocol TCP (6)
        0x00, 0x00,                         // Header checksum placeholder
        192, 168, 1, 100,                   // Src IP
        192, 168, 1, 1                      // Dst IP
    };
    const uint16_t ipCheck = ~dissect::checksumFold(dissect::checksumAdd(0, reinterpret_cast<const char *>(ipHeader.data()), ipHeader.size()));
    ipHeader[10] = static_cast<uint8_t>(ipCheck >> 8);
    ipHeader[11] = static_cast<uint8_t>(ipCheck & 0xff);

    // TCP Header (20 bytes): port 54321 -> 80
    std::vector<uint8_t> tcpHeader = {
        0xd4, 0x31,                         // Src Port 54321
        0x00, 0x50,                         // Dst Port 80
        0x00, 0x00, 0x00, 0x01,             // Seq number 1
        0x00, 0x00, 0x00, 0x00,             // Ack number 0
        0x50, 0x18,                         // Data offset 5 (20B), Flags: PSH, ACK
        0x10, 0x00,                         // Window size 4096
        0x00, 0x00,                         // Checksum placeholder
        0x00, 0x00                          // Urgent pointer
    };

    frame.insert(frame.end(), ipHeader.begin(), ipHeader.end());
    frame.insert(frame.end(), tcpHeader.begin(), tcpHeader.end());
    frame.insert(frame.end(), httpPayload.begin(), httpPayload.end());

    auto pack = parse80211(frame);
    // Upper layer decodes all the way to HTTP!
    EXPECT_EQ(pack.protocol, "HTTP");
    EXPECT_NE(pack.info.find("GET /index.html"), std::string::npos);
    EXPECT_EQ(pack.source, "192.168.1.100");
    EXPECT_EQ(pack.destination, "192.168.1.1");
    EXPECT_EQ(pack.src_port, 54321);
    EXPECT_EQ(pack.dst_port, 80);
    EXPECT_EQ(pack.l2_size, 34u); // 26 WLAN header + 8 LLC/SNAP
    EXPECT_EQ(pack.wlan_seq, 5u);

    // Filter evaluations
    EXPECT_TRUE(matchFilter("wlan", pack));
    EXPECT_TRUE(matchFilter("wlan.fc.type == 2", pack));
    EXPECT_TRUE(matchFilter("wlan.fc.subtype == 8", pack));
    EXPECT_TRUE(matchFilter("wlan.fc.fromds == 1", pack));
    EXPECT_TRUE(matchFilter("wlan.seq == 5", pack));
    EXPECT_TRUE(matchFilter("http", pack));
    EXPECT_TRUE(matchFilter("tcp.dstport == 80", pack));
    EXPECT_TRUE(matchFilter("ip.src == 192.168.1.100", pack));

    // Field tree checks: all layers are properly nested and sequenced
    const auto *wlanL = findLayer(pack, "IEEE 802.11 QoS Data");
    ASSERT_NE(wlanL, nullptr);
    const auto *llcL = findLayer(pack, "Logical-Link Control");
    ASSERT_NE(llcL, nullptr);
    const auto *ipL = findLayer(pack, "Internet Protocol Version 4");
    ASSERT_NE(ipL, nullptr);
    const auto *tcpL = findLayer(pack, "Transmission Control Protocol");
    ASSERT_NE(tcpL, nullptr);
    const auto *httpL = findLayer(pack, "Hypertext Transfer Protocol");
    ASSERT_NE(httpL, nullptr);
}

TEST(Wlan, ProtectedAndNullDataFrames) {
    // Protected frame (Encrypted CCMP)
    std::vector<uint8_t> protectedFrame = {
        0x88, 0x42,                         // FC: QoS Data, Protected = 1 (bit 14), FromDS = 1
        0x00, 0x00,                         // Duration
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // DA
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // BSSID
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, // SA
        0x60, 0x00,                         // SeqCtrl (Seq 6)
        0x00, 0x00                          // QoS Ctrl
    };
    // Append 30 bytes of encrypted payload
    for (int i = 0; i < 30; ++i) protectedFrame.push_back(static_cast<uint8_t>(i));

    auto pProt = parse80211(protectedFrame);
    EXPECT_EQ(pProt.protocol, "802.11");
    EXPECT_NE(pProt.info.find("Protected"), std::string::npos);
    EXPECT_TRUE(matchFilter("wlan.fc.protected == 1", pProt));
    EXPECT_TRUE(matchFilter("wlan.seq == 6", pProt));

    const auto *payloadL = findLayer(pProt, "Protected payload");
    ASSERT_NE(payloadL, nullptr);
    EXPECT_EQ(payloadL->length, 30u);

    // QoS Null function frame (no payload)
    std::vector<uint8_t> qosNull = {
        0xc8, 0x00,                         // FC: Subtype 12 QoS Null
        0x00, 0x00,                         // Duration
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // DA
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // SA
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // BSSID
        0x70, 0x00,                         // Seq 7
        0x00, 0x00                          // QoS Ctrl
    };
    auto pNull = parse80211(qosNull);
    EXPECT_EQ(pNull.protocol, "802.11");
    EXPECT_NE(pNull.info.find("QoS Null function"), std::string::npos);
}

TEST(Wlan, MalformedAndTruncatedFramesDoNotCrash) {
    // Frame too short (< 10 bytes)
    std::vector<uint8_t> shortFrame = {0x80, 0x00, 0x00};
    auto pShort = parse80211(shortFrame);
    EXPECT_EQ(pShort.protocol, "802.11");
    EXPECT_NE(pShort.info.find("Malformed"), std::string::npos);

    // Truncated management frame (< 24 bytes)
    std::vector<uint8_t> truncMgmt = {0x80, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07};
    auto pTrunc = parse80211(truncMgmt);
    EXPECT_NE(pTrunc.info.find("Malformed"), std::string::npos);

    // Fuzzing mutation: ensure no memory violations on corrupted 802.11 packets
    std::vector<uint8_t> baseFuzz = {
        0x80, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x10, 0x00,
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x64, 0x00, 0x31, 0x04,
        0x00, 0x20 // Tag 0 with length 32 exceeding available buffer
    };
    for (size_t len = 0; len <= baseFuzz.size(); ++len) {
        std::vector<uint8_t> slice(baseFuzz.begin(), baseFuzz.begin() + len);
        auto p = parse80211(slice);
        (void)p;
    }
}
