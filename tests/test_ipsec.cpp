#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>

#include "support.h"

using support::parse;

namespace {
    // Helper to wrap L4 in IPv4 + Ethernet
    std::vector<char> makeIpv4Packet(uint8_t proto, const std::vector<uint8_t> &l4Payload) {
        std::vector<uint8_t> frame = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x08, 0x00
        };

        size_t ipTotalLen = 20 + l4Payload.size();
        std::vector<uint8_t> ip = {
            0x45, 0x00, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
            0x00, 0x01, 0x00, 0x00,
            64, proto, 0x00, 0x00,
            10, 0, 0, 1,
            10, 0, 0, 2
        };

        uint32_t csum = 0;
        for (size_t i = 0; i < ip.size(); i += 2) csum += (ip[i] << 8) | ip[i + 1];
        while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
        uint16_t folded = static_cast<uint16_t>(~csum);
        ip[10] = static_cast<uint8_t>(folded >> 8);
        ip[11] = static_cast<uint8_t>(folded & 0xff);

        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.insert(frame.end(), l4Payload.begin(), l4Payload.end());
        return std::vector<char>(frame.begin(), frame.end());
    }

    std::vector<char> makeUdpPacket(uint16_t sport, uint16_t dport, const std::vector<uint8_t> &udpPayload) {
        size_t ulen = 8 + udpPayload.size();
        std::vector<uint8_t> udp = {
            static_cast<uint8_t>(sport >> 8), static_cast<uint8_t>(sport & 0xff),
            static_cast<uint8_t>(dport >> 8), static_cast<uint8_t>(dport & 0xff),
            static_cast<uint8_t>(ulen >> 8), static_cast<uint8_t>(ulen & 0xff),
            0x00, 0x00 // zero checksum
        };
        udp.insert(udp.end(), udpPayload.begin(), udpPayload.end());
        return makeIpv4Packet(17, udp);
    }
} // namespace

TEST(Ipsec, AuthenticationHeader) {
    // AH: NextHeader=6 (TCP), PayloadLen=4 (6 * 4 = 24 bytes), Reserved=0, SPI=0x12345678, Seq=100
    // ICV = 12 bytes of authentication data
    std::vector<uint8_t> ah = {
        6, 4, 0, 0,
        0x12, 0x34, 0x56, 0x78, // SPI
        0, 0, 0, 100,           // Seq
        // 12 bytes ICV:
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
        // TCP minimal header (20 bytes): port 80 -> port 12345, seq=1, ack=0, SYN
        0x00, 0x50, 0x30, 0x39,
        0x00, 0x00, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00,
        0x50, 0x02, 0x20, 0x00,
        0x00, 0x00, 0x00, 0x00
    };

    auto pkt = parse(makeIpv4Packet(51, ah));
    EXPECT_EQ(pkt.protocol, "AH");
    EXPECT_EQ(pkt.tcp_pdu_start, 0x12345678U);
    EXPECT_EQ(pkt.app_code, 100U);
    EXPECT_NE(pkt.info.find("SPI: 0x12345678"), std::string::npos);

    auto f = filter::Filter::compile("ah && ah.spi == 0x12345678 && ah.sequence == 100");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}

TEST(Ipsec, EncapsulatingSecurityPayload) {
    // ESP: SPI=0x87654321, Seq=42, followed by encrypted payload
    std::vector<uint8_t> esp = {
        0x87, 0x65, 0x43, 0x21, // SPI
        0, 0, 0, 42,           // Seq
        0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe // Encrypted payload
    };

    auto pkt = parse(makeIpv4Packet(50, esp));
    EXPECT_EQ(pkt.protocol, "ESP");
    EXPECT_EQ(pkt.tcp_pdu_start, 0x87654321U);
    EXPECT_EQ(pkt.app_code, 42U);
    EXPECT_NE(pkt.info.find("SPI: 0x87654321"), std::string::npos);

    auto f = filter::Filter::compile("esp && esp.spi == 0x87654321 && esp.sequence == 42");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}

TEST(Ipsec, Ikev2InitMessage) {
    // IKEv2 packet over UDP port 500
    // Initiator SPI (8B): 0x1122334455667788
    // Responder SPI (8B): 0x0000000000000000
    // Next Payload: 33 (Security Association SA), Version: 0x20 (2.0)
    // Exchange: 34 (IKE_SA_INIT), Flags: 0x08 (Initiator), MsgID: 0, Length: 36
    std::vector<uint8_t> ike = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        33,   // Next Payload (SA)
        0x20, // Version 2.0
        34,   // Exchange IKE_SA_INIT
        0x08, // Flags (Initiator)
        0, 0, 0, 0, // MsgID 0
        0, 0, 0, 36, // Length 36
        // Payload (SA header): Next=0, Reserved=0, Length=8
        0, 0, 0, 8,
        0, 0, 0, 0
    };

    auto pkt = parse(makeUdpPacket(500, 500, ike));
    EXPECT_EQ(pkt.protocol, "IKEv2");
    EXPECT_EQ(pkt.app_code, 2); // Version 2
    EXPECT_EQ(pkt.app_type, 34); // IKE_SA_INIT
    EXPECT_NE(pkt.info.find("IKE_SA_INIT"), std::string::npos);

    auto f = filter::Filter::compile("ike && ike.version == 2 && ike.exchange_type == 34");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}
