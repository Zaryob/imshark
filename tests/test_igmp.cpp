#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>

#include "support.h"

using support::hex;
using support::parse;

namespace {
    // Helper to wrap IGMP inside IPv4 + Ethernet
    // IPv4 src=10.0.0.1, dst=224.0.0.1, proto=2
    std::vector<char> makeIgmpPacket(const std::vector<uint8_t> &igmpPayload) {
        // Ethernet header: dst=01:00:5e:00:00:01, src=00:11:22:33:44:55, etype=0x0800
        std::vector<uint8_t> frame = {
            0x01, 0x00, 0x5e, 0x00, 0x00, 0x01,
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0x08, 0x00
        };

        // IPv4 header (20 bytes): len = 20 + payload.size(), proto = 2
        uint16_t ipTotalLen = static_cast<uint16_t>(20 + igmpPayload.size());
        std::vector<uint8_t> ip = {
            0x45, 0x00, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
            0x00, 0x01, 0x00, 0x00,
            0x01, 0x02, 0x00, 0x00, // TTL=1, proto=2 (IGMP), zero csum placeholder
            10, 0, 0, 1,            // src 10.0.0.1
            224, 0, 0, 1            // dst 224.0.0.1
        };

        // Calculate IPv4 checksum
        uint32_t csum = 0;
        for (size_t i = 0; i < ip.size(); i += 2) {
            csum += (ip[i] << 8) | ip[i + 1];
        }
        while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
        uint16_t folded = static_cast<uint16_t>(~csum);
        ip[10] = static_cast<uint8_t>(folded >> 8);
        ip[11] = static_cast<uint8_t>(folded & 0xff);

        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.insert(frame.end(), igmpPayload.begin(), igmpPayload.end());
        return std::vector<char>(frame.begin(), frame.end());
    }
} // namespace

TEST(Igmp, GeneralMembershipQuery) {
    // IGMPv2 Query (type=0x11, max_resp_time=100 (10.0s), group=0.0.0.0)
    // Checksum = ~sum(0x1164 + 0x0000 + 0x0000 + 0x0000) = ~0x1164 = 0xEE9B
    std::vector<uint8_t> payload = {
        0x11, 0x64, 0xee, 0x9b,
        0x00, 0x00, 0x00, 0x00
    };

    auto pkt = parse(makeIgmpPacket(payload));
    EXPECT_EQ(pkt.protocol, "IGMP");
    EXPECT_EQ(pkt.info, "General Membership Query");
    EXPECT_EQ(pkt.app_type, 0x11);
    EXPECT_EQ(pkt.app_code, 100);
    EXPECT_EQ(pkt.app_text, "0.0.0.0");

    // Check filter matching
    auto f = filter::Filter::compile("igmp && igmp.type == 0x11");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}

TEST(Igmp, MembershipReportV2) {
    // IGMPv2 Report (type=0x16, max_resp_time=0, group=224.1.2.3)
    // 0x1600 + csum + 0xe001 + 0x0203
    // Sum = 0x1600 + 0xe001 + 0x0203 = 0xF804 -> csum = 0x07FB
    std::vector<uint8_t> payload = {
        0x16, 0x00, 0x07, 0xfb,
        224, 1, 2, 3
    };

    auto pkt = parse(makeIgmpPacket(payload));
    EXPECT_EQ(pkt.protocol, "IGMP");
    EXPECT_EQ(pkt.info, "IGMPv2 Membership Report, group 224.1.2.3");
    EXPECT_EQ(pkt.app_type, 0x16);
    EXPECT_EQ(pkt.app_text, "224.1.2.3");

    auto f = filter::Filter::compile("igmp.group == \"224.1.2.3\"");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}
