#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include <dissect/checksum.h>
#include <filter/filter.h>
#include <packet/packet_info.h>
#include <packet/packet_parser.h>

namespace {
    packet::PacketInfo parsePacket(uint32_t linkType, const std::vector<uint8_t> &data,
                                   dissect::ParseMode mode = dissect::ParseMode::Full) {
        packet::PacketInfo pack;
        pack.link_type = linkType;
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

TEST(RadiotapPpi, RadiotapBeaconFrameDecodesAndFilters) {
    // Radiotap header:
    // it_version = 0, it_pad = 0
    // it_len = 18 bytes (0x12, 0x00)
    // it_present = 0x0000002e (Flags, Rate, Channel, dBm Signal)
    //   Flags: 0x10 (FCS at end)
    //   Rate: 108 (54.0 Mbps)
    //   align 2 -> Channel: freq 2412 (0x6c, 0x09), flags 0x00a0
    //   dBm Signal: -65 dBm (0xbf)
    //   Pad to 18: 0x00
    std::vector<uint8_t> packet = {
        0x00, 0x00,                         // version 0, pad 0
        0x10, 0x00,                         // it_len = 16 bytes
        0x2e, 0x00, 0x00, 0x00,             // it_present mask: Flags (1), Rate (2), Channel (3), dBm Signal (5)
        0x10,                               // Flags: FCS at end
        108,                                // Rate: 108 (54 Mbps)
        // align 2 -> offset 10
        0x6c, 0x09, 0xa0, 0x00,             // Channel: 2412 MHz, flags 0x00a0
        static_cast<uint8_t>(-65),          // dBm Signal: -65 dBm
        0x00                                // Pad to 16 bytes
    };

    // IEEE 802.11 Beacon frame (Type 0, Subtype 8)
    std::vector<uint8_t> beacon = {
        0x80, 0x00,                         // FC: Beacon
        0x00, 0x00,                         // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // DA
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // SA
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // BSSID
        0x10, 0x00,                         // SeqCtrl (Seq 1)
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // Timestamp
        0x64, 0x00,                         // Beacon Interval
        0x31, 0x04,                         // Capability
        // IE 0: SSID "RadiotapWifi"
        0x00, 0x0c, 'R', 'a', 'd', 'i', 'o', 't', 'a', 'p', 'W', 'i', 'f', 'i'
    };
    packet.insert(packet.end(), beacon.begin(), beacon.end());

    // 4-byte FCS at end
    packet.push_back(0xde);
    packet.push_back(0xad);
    packet.push_back(0xbe);
    packet.push_back(0xef);

    auto pack = parsePacket(127, packet); // LinkType 127 = Radiotap
    EXPECT_EQ(pack.protocol, "802.11");
    EXPECT_NE(pack.info.find("RadiotapWifi"), std::string::npos);
    EXPECT_EQ(pack.source, "00:11:22:33:44:55");
    EXPECT_EQ(pack.destination, "ff:ff:ff:ff:ff:ff");

    // Filter tests
    EXPECT_TRUE(matchFilter("wlan", pack));
    EXPECT_TRUE(matchFilter("wlan.fc.type == 0", pack));
    EXPECT_TRUE(matchFilter("wlan.fc.subtype == 8", pack));
    EXPECT_TRUE(matchFilter("wlan.ssid == \"RadiotapWifi\"", pack));
    EXPECT_TRUE(matchFilter("radiotap.channel.freq == 2412", pack));
    EXPECT_TRUE(matchFilter("radiotap.dbm_antsignal == -65", pack));
    EXPECT_TRUE(matchFilter("radiotap.datarate == 54.0", pack));

    // Field tree
    const auto *rtLayer = findLayer(pack, "Radiotap Header");
    ASSERT_NE(rtLayer, nullptr);
    const auto *wlanLayer = findLayer(pack, "IEEE 802.11 Beacon frame");
    ASSERT_NE(wlanLayer, nullptr);
    const auto *fcsLayer = findLayer(pack, "Frame Check Sequence");
    ASSERT_NE(fcsLayer, nullptr);
}

TEST(RadiotapPpi, PpiEncapsulated80211HttpUnwrapsAllLayers) {
    // PPI Packet Header (8 bytes):
    // pph_version = 0, pph_flags = 0, pph_len = 32 bytes, pph_dlt = 105 (IEEE 802.11)
    std::vector<uint8_t> packet = {
        0x00,                               // version 0
        0x00,                               // flags 0
        0x20, 0x00,                         // pph_len = 32 bytes
        0x69, 0x00, 0x00, 0x00,             // pph_dlt = 105 (802.11)
        // TLV 1: Type 2 (802.11-Common), Length 20 bytes
        0x02, 0x00,                         // pfh_type = 2
        0x14, 0x00,                         // pfh_datalen = 20
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // TSFT (8B)
        0x02, 0x00,                         // Flags: 0x0002 (FCS included)
        108, 0x00,                          // Rate: 108 (54 Mbps)
        0x3c, 0x14,                         // Channel freq: 5180 MHz (0x143c)
        0x40, 0x01,                         // Channel flags: 0x0140 (5GHz OFDM)
        0x00,                               // FHSS hop
        0x00,                               // FHSS pat
        static_cast<uint8_t>(-50),          // Signal: -50 dBm
        static_cast<uint8_t>(-92)           // Noise: -92 dBm
    };

    // IEEE 802.11 QoS Data frame (Type 2, Subtype 8, FromDS=1 -> 0x88, 0x02)
    std::vector<uint8_t> wlanHdr = {
        0x88, 0x02,                         // FC
        0x00, 0x00,                         // Duration
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // DA
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // BSSID
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, // SA
        0x40, 0x00,                         // SeqCtrl (Seq 4)
        0x00, 0x00,                         // QoS Ctrl
        // LLC/SNAP
        0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00
    };
    packet.insert(packet.end(), wlanHdr.begin(), wlanHdr.end());

    // IPv4 + TCP + HTTP GET
    const std::string httpPayload = "GET /ppi-test HTTP/1.1\r\nHost: ppi.local\r\n\r\n";
    const uint16_t tcpLen = 20 + static_cast<uint16_t>(httpPayload.size());
    const uint16_t ipTotalLen = 20 + tcpLen;

    std::vector<uint8_t> ipHeader = {
        0x45, 0x00,
        static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
        0x56, 0x78,
        0x40, 0x00,
        64, 6,
        0x00, 0x00,
        10, 0, 0, 2,
        10, 0, 0, 1
    };
    const uint16_t ipCheck = ~dissect::checksumFold(dissect::checksumAdd(0, reinterpret_cast<const char *>(ipHeader.data()), ipHeader.size()));
    ipHeader[10] = static_cast<uint8_t>(ipCheck >> 8);
    ipHeader[11] = static_cast<uint8_t>(ipCheck & 0xff);

    std::vector<uint8_t> tcpHeader = {
        0x1f, 0x90,                         // Port 8080
        0x00, 0x50,                         // Port 80
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x18,
        0x20, 0x00,
        0x00, 0x00,
        0x00, 0x00
    };

    packet.insert(packet.end(), ipHeader.begin(), ipHeader.end());
    packet.insert(packet.end(), tcpHeader.begin(), tcpHeader.end());
    packet.insert(packet.end(), httpPayload.begin(), httpPayload.end());

    // 4-byte FCS
    packet.push_back(0x11);
    packet.push_back(0x22);
    packet.push_back(0x33);
    packet.push_back(0x44);

    auto pack = parsePacket(192, packet); // LinkType 192 = PPI
    EXPECT_EQ(pack.protocol, "HTTP");
    EXPECT_NE(pack.info.find("GET /ppi-test"), std::string::npos);
    EXPECT_EQ(pack.source, "10.0.0.2");
    EXPECT_EQ(pack.destination, "10.0.0.1");

    // Filter tests
    EXPECT_TRUE(matchFilter("ppi.dlt == 105", pack));
    EXPECT_TRUE(matchFilter("radiotap.channel.freq == 5180", pack));
    EXPECT_TRUE(matchFilter("radiotap.dbm_antsignal == -50", pack));
    EXPECT_TRUE(matchFilter("radiotap.datarate == 54.0", pack));
    EXPECT_TRUE(matchFilter("wlan", pack));
    EXPECT_TRUE(matchFilter("wlan.fc.type == 2", pack));
    EXPECT_TRUE(matchFilter("http", pack));
    EXPECT_TRUE(matchFilter("tcp.dstport == 80", pack));

    // Field tree check
    const auto *ppiLayer = findLayer(pack, "Packet Processing Information");
    ASSERT_NE(ppiLayer, nullptr);
    const auto *wlanLayer = findLayer(pack, "IEEE 802.11 QoS Data");
    ASSERT_NE(wlanLayer, nullptr);
    const auto *llcLayer = findLayer(pack, "Logical-Link Control");
    ASSERT_NE(llcLayer, nullptr);
    const auto *ipLayer = findLayer(pack, "Internet Protocol Version 4");
    ASSERT_NE(ipLayer, nullptr);
    const auto *tcpLayer = findLayer(pack, "Transmission Control Protocol");
    ASSERT_NE(tcpLayer, nullptr);
    const auto *httpLayer = findLayer(pack, "Hypertext Transfer Protocol");
    ASSERT_NE(httpLayer, nullptr);
    const auto *fcsLayer = findLayer(pack, "Frame Check Sequence");
    ASSERT_NE(fcsLayer, nullptr);
}

TEST(RadiotapPpi, TruncatedHeadersDoNotCrash) {
    // Truncated Radiotap (< 8 bytes)
    std::vector<uint8_t> shortRt = {0x00, 0x00, 0x04};
    auto pShortRt = parsePacket(127, shortRt);
    EXPECT_EQ(pShortRt.protocol, "Radiotap");
    EXPECT_NE(pShortRt.info.find("Malformed"), std::string::npos);

    // Truncated PPI (< 8 bytes)
    std::vector<uint8_t> shortPpi = {0x00, 0x00, 0x04};
    auto pShortPpi = parsePacket(192, shortPpi);
    EXPECT_EQ(pShortPpi.protocol, "PPI");
    EXPECT_NE(pShortPpi.info.find("Malformed"), std::string::npos);

    // Invalid length (> buffer)
    std::vector<uint8_t> bigLenRt = {0x00, 0x00, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00};
    auto pBigRt = parsePacket(127, bigLenRt);
    EXPECT_NE(pBigRt.info.find("Malformed"), std::string::npos);

    std::vector<uint8_t> bigLenPpi = {0x00, 0x00, 0xff, 0x00, 0x69, 0x00, 0x00, 0x00};
    auto pBigPpi = parsePacket(192, bigLenPpi);
    EXPECT_NE(pBigPpi.info.find("Malformed"), std::string::npos);
}
