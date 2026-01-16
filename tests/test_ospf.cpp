#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>

#include "support.h"

using support::parse;

namespace {
    // Helper to wrap OSPF inside IPv4 + Ethernet
    // IPv4 src=10.0.0.1, dst=224.0.0.5 (AllSPFRouters), proto=89
    std::vector<char> makeOspfPacket(const std::vector<uint8_t> &ospfPayload) {
        std::vector<uint8_t> frame = {
            0x01, 0x00, 0x5e, 0x00, 0x00, 0x05,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x08, 0x00
        };

        size_t ipTotalLen = 20 + ospfPayload.size();
        std::vector<uint8_t> ip = {
            0x45, 0xc0, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff), // DSCP CS6 (Internetwork Control)
            0x00, 0x01, 0x00, 0x00,
            1, 89, 0x00, 0x00, // TTL=1, proto=89 (OSPF)
            10, 0, 0, 1,
            224, 0, 0, 5
        };

        uint32_t csum = 0;
        for (size_t i = 0; i < ip.size(); i += 2) csum += (ip[i] << 8) | ip[i + 1];
        while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
        uint16_t folded = static_cast<uint16_t>(~csum);
        ip[10] = static_cast<uint8_t>(folded >> 8);
        ip[11] = static_cast<uint8_t>(folded & 0xff);

        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.insert(frame.end(), ospfPayload.begin(), ospfPayload.end());
        return std::vector<char>(frame.begin(), frame.end());
    }
} // namespace

TEST(Ospf, HelloPacket) {
    // OSPFv2 Hello: 24-byte header + 20-byte Hello body = 44 bytes total
    // Version=2, Type=1 (Hello), Length=44 (0x002C)
    // Router ID: 192.168.1.1 (C0 A8 01 01)
    // Area ID: 0.0.0.0 (Backbone)
    // Auth Type: 0 (Null)
    std::vector<uint8_t> ospf = {
        0x02, 0x01, 0x00, 0x2c,
        0xc0, 0xa8, 0x01, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,             // checksum placeholder
        0x00, 0x00,             // Auth Type = 0
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Auth data
        // Hello body:
        0xff, 0xff, 0xff, 0x00, // Netmask 255.255.255.0
        0x00, 0x0a,             // Hello Interval = 10 sec
        0x02,                   // Options (E-bit)
        0x01,                   // Router Priority = 1
        0x00, 0x00, 0x00, 0x28, // Dead Interval = 40 sec
        0xc0, 0xa8, 0x01, 0x01, // DR: 192.168.1.1
        0x00, 0x00, 0x00, 0x00  // BDR: 0.0.0.0
    };

    // Calculate OSPF checksum (RFC 2328: standard checksum excluding 8-byte auth field)
    uint32_t csum = 0;
    // bytes 0..11 and 14..15 (skip csum at 12..13 and auth at 16..23)
    for (size_t i = 0; i < 12; i += 2) csum += (ospf[i] << 8) | ospf[i + 1];
    csum += (ospf[14] << 8) | ospf[15];
    for (size_t i = 24; i < ospf.size(); i += 2) csum += (ospf[i] << 8) | ospf[i + 1];
    while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
    uint16_t folded = static_cast<uint16_t>(~csum);
    ospf[12] = static_cast<uint8_t>(folded >> 8);
    ospf[13] = static_cast<uint8_t>(folded & 0xff);

    auto pkt = parse(makeOspfPacket(ospf));
    EXPECT_EQ(pkt.protocol, "OSPF");
    EXPECT_EQ(pkt.app_code, 2); // Version 2
    EXPECT_EQ(pkt.app_type, 1); // Type 1 (Hello)
    EXPECT_EQ(pkt.app_text, "192.168.1.1");
    EXPECT_EQ(pkt.app_text2, "0.0.0.0");
    EXPECT_NE(pkt.info.find("Hello"), std::string::npos);

    // Filter check
    auto f = filter::Filter::compile("ospf && ospf.version == 2 && ospf.type == 1 && ospf.router_id == \"192.168.1.1\"");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}

TEST(Ospf, DatabaseDescriptionPacket) {
    // OSPFv2 DD: 24-byte header + 8-byte DD body = 32 bytes total
    // Version=2, Type=2 (DD), Length=32 (0x0020)
    std::vector<uint8_t> ospf = {
        0x02, 0x02, 0x00, 0x20,
        10, 0, 0, 1,            // Router ID 10.0.0.1
        0, 0, 0, 1,             // Area 0.0.0.1
        0, 0,                   // Checksum placeholder
        0, 0,                   // Auth Type = 0
        0, 0, 0, 0, 0, 0, 0, 0, // Auth data
        // DD body:
        0x05, 0xdc,             // MTU 1500
        0x02,                   // Options
        0x07,                   // Flags: I + M + MS
        0x00, 0x00, 0x12, 0x34  // DD Sequence Number = 0x1234
    };

    auto pkt = parse(makeOspfPacket(ospf));
    EXPECT_EQ(pkt.protocol, "OSPF");
    EXPECT_EQ(pkt.app_type, 2); // DD
    EXPECT_NE(pkt.info.find("Database Description"), std::string::npos);
}
