#include <gtest/gtest.h>

#include <cstring>
#include <vector>

#include <filter/filter.h>
#include <packet/packet_info.h>
#include <packet/packet_parser.h>

namespace {
    packet::PacketInfo parsePacket(uint16_t etherType, const std::vector<uint8_t> &eapolPayload) {
        packet::PacketInfo pack;
        pack.link_type = 1; // Ethernet
        // Build Ethernet header (14 bytes)
        std::vector<uint8_t> eth = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // DA
            0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, // SA
            static_cast<uint8_t>(etherType >> 8), static_cast<uint8_t>(etherType & 0xff)
        };
        eth.insert(eth.end(), eapolPayload.begin(), eapolPayload.end());

        std::vector<char> raw(eth.begin(), eth.end());
        packet::PacketParser parser;
        parser.parsePacket(pack, raw, dissect::ParseMode::Full);
        return pack;
    }

    packet::PacketInfo parseWlan(const std::vector<uint8_t> &wlanFrame) {
        packet::PacketInfo pack;
        pack.link_type = 105; // 802.11
        std::vector<char> raw(wlanFrame.begin(), wlanFrame.end());
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

    std::vector<uint8_t> buildEapolKey(uint8_t descType, uint16_t keyInfo, uint64_t replay,
                                       const std::vector<uint8_t> &keyData = {}) {
        std::vector<uint8_t> p;
        // 802.1X header (4 bytes)
        p.push_back(1); // Version: 802.1X-2001
        p.push_back(3); // Type: Key (3)
        uint16_t bodyLen = 95 + static_cast<uint16_t>(keyData.size());
        p.push_back(static_cast<uint8_t>(bodyLen >> 8));
        p.push_back(static_cast<uint8_t>(bodyLen & 0xff));

        // Key Descriptor (95 bytes fixed)
        p.push_back(descType); // 2 = RSN, 254 = WPA
        p.push_back(static_cast<uint8_t>(keyInfo >> 8));
        p.push_back(static_cast<uint8_t>(keyInfo & 0xff));
        p.push_back(0x00); p.push_back(0x20); // Key Length = 32
        // Replay Counter (8 bytes)
        for (int i = 7; i >= 0; --i) {
            p.push_back(static_cast<uint8_t>((replay >> (i * 8)) & 0xff));
        }
        // WPA Key Nonce (32 bytes)
        for (int i = 0; i < 32; ++i) p.push_back(static_cast<uint8_t>(i + 1));
        // Key IV (16 bytes)
        for (int i = 0; i < 16; ++i) p.push_back(0);
        // Key RSC (8 bytes)
        for (int i = 0; i < 8; ++i) p.push_back(0);
        // Key ID (8 bytes)
        for (int i = 0; i < 8; ++i) p.push_back(0);
        // Key MIC (16 bytes)
        for (int i = 0; i < 16; ++i) p.push_back(static_cast<uint8_t>(0xaa));
        // Key Data Length (2 bytes)
        uint16_t kdLen = static_cast<uint16_t>(keyData.size());
        p.push_back(static_cast<uint8_t>(kdLen >> 8));
        p.push_back(static_cast<uint8_t>(kdLen & 0xff));
        // Key Data
        p.insert(p.end(), keyData.begin(), keyData.end());
        return p;
    }
} // namespace

TEST(Eapol, Wpa2FourWayHandshakeMessages) {
    // PMKID KDE to include in Message 1
    std::vector<uint8_t> pmkidKde = {
        0xdd, 0x14, 0x00, 0x0f, 0xac, 0x03, // Type DD, Len 20, OUI 00-0F-AC, DataType 3 (PMKID)
        1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 // 16-byte PMKID
    };

    // Message 1 of 4: Pairwise (bit 3), ACK (bit 7) -> 0x008a (Version 2, Pairwise, ACK)
    auto m1Bytes = buildEapolKey(2, 0x008a, 1, pmkidKde);
    auto m1 = parsePacket(0x888E, m1Bytes);
    EXPECT_EQ(m1.protocol, "EAPOL");
    EXPECT_EQ(m1.info, "Key (RSN) - Message 1 of 4");
    EXPECT_TRUE(matchFilter("eapol", m1));
    EXPECT_TRUE(matchFilter("eapol.type == 3", m1));
    EXPECT_TRUE(matchFilter("eapol.keydes.type == 2", m1));
    EXPECT_TRUE(matchFilter("eapol.keydes.msgnr == 1", m1));

    const auto *eapolLayer = findLayer(m1, "IEEE 802.1X Authentication");
    ASSERT_NE(eapolLayer, nullptr);
    const auto *keyLayer = findLayer(m1, "IEEE 802.11i / RSN Key Descriptor");
    ASSERT_NE(keyLayer, nullptr);

    // Message 2 of 4: Pairwise (bit 3), MIC (bit 8) -> 0x010a
    auto m2Bytes = buildEapolKey(2, 0x010a, 1);
    auto m2 = parsePacket(0x888E, m2Bytes);
    EXPECT_EQ(m2.protocol, "EAPOL");
    EXPECT_EQ(m2.info, "Key (RSN) - Message 2 of 4");
    EXPECT_TRUE(matchFilter("eapol.keydes.msgnr == 2", m2));

    // Message 3 of 4: Pairwise, Install (bit 6), ACK (bit 7), MIC (bit 8), Secure (bit 9) -> 0x03ca
    auto m3Bytes = buildEapolKey(2, 0x03ca, 2);
    auto m3 = parsePacket(0x888E, m3Bytes);
    EXPECT_EQ(m3.protocol, "EAPOL");
    EXPECT_EQ(m3.info, "Key (RSN) - Message 3 of 4");
    EXPECT_TRUE(matchFilter("eapol.keydes.msgnr == 3", m3));

    // Message 4 of 4: Pairwise, MIC (bit 8), Secure (bit 9) -> 0x030a
    auto m4Bytes = buildEapolKey(2, 0x030a, 2);
    auto m4 = parsePacket(0x888E, m4Bytes);
    EXPECT_EQ(m4.protocol, "EAPOL");
    EXPECT_EQ(m4.info, "Key (RSN) - Message 4 of 4");
    EXPECT_TRUE(matchFilter("eapol.keydes.msgnr == 4", m4));
}

TEST(Eapol, GroupHandshakeMessages) {
    // Group Message 1 of 2: Group (bit 3 = 0), ACK (bit 7), MIC (bit 8) -> 0x0182
    auto g1Bytes = buildEapolKey(2, 0x0182, 10);
    auto g1 = parsePacket(0x888E, g1Bytes);
    EXPECT_EQ(g1.protocol, "EAPOL");
    EXPECT_EQ(g1.info, "Key (RSN) - Group Message 1 of 2");

    // Group Message 2 of 2: Group (bit 3 = 0), MIC (bit 8) -> 0x0102
    auto g2Bytes = buildEapolKey(2, 0x0102, 10);
    auto g2 = parsePacket(0x888E, g2Bytes);
    EXPECT_EQ(g2.protocol, "EAPOL");
    EXPECT_EQ(g2.info, "Key (RSN) - Group Message 2 of 2");
}

TEST(Eapol, StartAndLogoffFrames) {
    // EAPOL-Start (type 1)
    std::vector<uint8_t> start = {0x01, 0x01, 0x00, 0x00};
    auto pStart = parsePacket(0x888E, start);
    EXPECT_EQ(pStart.protocol, "EAPOL");
    EXPECT_EQ(pStart.info, "EAPOL-Start");
    EXPECT_TRUE(matchFilter("eapol.type == 1", pStart));

    // EAPOL-Logoff (type 2)
    std::vector<uint8_t> logoff = {0x01, 0x02, 0x00, 0x00};
    auto pLogoff = parsePacket(0x888E, logoff);
    EXPECT_EQ(pLogoff.protocol, "EAPOL");
    EXPECT_EQ(pLogoff.info, "EAPOL-Logoff");
    EXPECT_TRUE(matchFilter("eapol.type == 2", pLogoff));
}

TEST(Eapol, EapPacketsDecodesAndFilters) {
    // EAP Request, Identity (Type 0, Code 1, ID 42, Length 5, Type 1)
    std::vector<uint8_t> req = {
        0x01, 0x00, 0x00, 0x05, // 802.1X: ver 1, type 0 (EAP), len 5
        0x01, 0x2a, 0x00, 0x05, // EAP: Code 1 (Request), ID 42, Len 5
        0x01                    // Type: 1 (Identity)
    };
    auto pReq = parsePacket(0x888E, req);
    EXPECT_EQ(pReq.protocol, "EAP");
    EXPECT_EQ(pReq.info, "Request, Identity");
    EXPECT_TRUE(matchFilter("eap", pReq));
    EXPECT_TRUE(matchFilter("eap.code == 1", pReq));
    EXPECT_TRUE(matchFilter("eap.type == 1", pReq));

    // EAP Response, Identity: alice@domain.com
    const std::string username = "alice@domain.com";
    const uint16_t eapRespLen = 5 + static_cast<uint16_t>(username.size());
    std::vector<uint8_t> resp = {
        0x01, 0x00, static_cast<uint8_t>(eapRespLen >> 8), static_cast<uint8_t>(eapRespLen & 0xff),
        0x02, 0x2a, static_cast<uint8_t>(eapRespLen >> 8), static_cast<uint8_t>(eapRespLen & 0xff),
        0x01
    };
    resp.insert(resp.end(), username.begin(), username.end());
    auto pResp = parsePacket(0x888E, resp);
    EXPECT_EQ(pResp.protocol, "EAP");
    EXPECT_EQ(pResp.info, "Response, Identity: " + username);
    EXPECT_TRUE(matchFilter("eap.identity == \"alice@domain.com\"", pResp));

    // EAP Success (Code 3)
    std::vector<uint8_t> succ = {
        0x01, 0x00, 0x00, 0x04,
        0x03, 0x2a, 0x00, 0x04
    };
    auto pSucc = parsePacket(0x888E, succ);
    EXPECT_EQ(pSucc.protocol, "EAP");
    EXPECT_EQ(pSucc.info, "Success");
    EXPECT_TRUE(matchFilter("eap.code == 3", pSucc));

    // EAP Failure (Code 4)
    std::vector<uint8_t> fail = {
        0x01, 0x00, 0x00, 0x04,
        0x04, 0x2a, 0x00, 0x04
    };
    auto pFail = parsePacket(0x888E, fail);
    EXPECT_EQ(pFail.protocol, "EAP");
    EXPECT_EQ(pFail.info, "Failure");
    EXPECT_TRUE(matchFilter("eap.code == 4", pFail));
}

TEST(Eapol, EncapsulatedIn80211WlanFrame) {
    // 802.11 QoS Data frame + LLC/SNAP (EtherType 0x888E) carrying EAPOL-Key Message 1 of 4
    std::vector<uint8_t> frame = {
        0x88, 0x02,                         // FC: QoS Data, FromDS=1
        0x00, 0x00,                         // Duration
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // DA
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // BSSID
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, // SA
        0x10, 0x00,                         // SeqCtrl
        0x00, 0x00,                         // QoS Ctrl
        // LLC/SNAP with EtherType 0x888E
        0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8e
    };

    auto eapolKey = buildEapolKey(2, 0x008a, 1);
    frame.insert(frame.end(), eapolKey.begin(), eapolKey.end());

    auto pack = parseWlan(frame);
    EXPECT_EQ(pack.protocol, "EAPOL");
    EXPECT_EQ(pack.info, "Key (RSN) - Message 1 of 4");
    EXPECT_TRUE(matchFilter("wlan", pack));
    EXPECT_TRUE(matchFilter("wlan.fc.type == 2", pack));
    EXPECT_TRUE(matchFilter("eapol", pack));
    EXPECT_TRUE(matchFilter("eapol.keydes.msgnr == 1", pack));

    const auto *wlanLayer = findLayer(pack, "IEEE 802.11 QoS Data");
    ASSERT_NE(wlanLayer, nullptr);
    const auto *llcLayer = findLayer(pack, "Logical-Link Control");
    ASSERT_NE(llcLayer, nullptr);
    const auto *eapolLayer = findLayer(pack, "IEEE 802.1X Authentication");
    ASSERT_NE(eapolLayer, nullptr);
}

TEST(Eapol, TruncatedHeadersDoNotCrash) {
    // Frame shorter than 4 bytes
    std::vector<uint8_t> shortHdr = {0x01, 0x03};
    auto p1 = parsePacket(0x888E, shortHdr);
    EXPECT_TRUE(matchFilter("malformed", p1));

    // Truncated Key Descriptor (< 99 bytes)
    std::vector<uint8_t> truncKey = {
        0x01, 0x03, 0x00, 0x60, // 802.1X
        0x02, 0x00, 0x8a        // RSN key descriptor only 3 bytes
    };
    auto p2 = parsePacket(0x888E, truncKey);
    EXPECT_TRUE(matchFilter("malformed", p2));

    // Truncated EAP (< 8 bytes)
    std::vector<uint8_t> truncEap = {
        0x01, 0x00, 0x00, 0x05,
        0x01, 0x01
    };
    auto p3 = parsePacket(0x888E, truncEap);
    EXPECT_TRUE(matchFilter("malformed", p3));
}
