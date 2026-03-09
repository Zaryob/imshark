#include <gtest/gtest.h>

#include <functional>

#include <core.h>
#include <dissect/checksum.h>
#include <filter/filter.h>

#include "frame_sweep.h"
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

namespace {
    using framesweep::Bytes;

    Bytes be32(uint32_t v) { return {static_cast<uint8_t>(v >> 24), static_cast<uint8_t>(v >> 16), static_cast<uint8_t>(v >> 8), static_cast<uint8_t>(v)}; }

    // IKEv2 IKE_SA_INIT, 56 bytes: header (28) + SA payload (8, next = Nonce 40) + Nonce payload (20)
    Bytes ikeInit(uint8_t exchange = 34, uint8_t version = 0x20) {
        Bytes b = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 33, version, exchange, 0x08, 0, 0, 0, 0, 0, 0, 0, 56,
                   40, 0, 0, 8, 0, 0, 0, 0,
                   0, 0, 0, 20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        return b;
    }

    packet::PacketInfo udpFrame(uint16_t sport, uint16_t dport, const Bytes &data) {
        return framesweep::parseEthernet(framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(sport, dport, data))));
    }
} // namespace

TEST(IkeClaim, IkeOnPort500IsRecognised) {
    const auto p = udpFrame(500, 500, ikeInit());
    EXPECT_EQ(p.protocol, "IKEv2");
    EXPECT_EQ(p.app_code, 2);
    EXPECT_EQ(p.app_type, 34);
    EXPECT_NE(p.info.find("IKE_SA_INIT"), std::string::npos);
    auto f = filter::Filter::compile("ike && ike.version == 2 && ike.exchange_type == 34");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(p));
    // the payloads carry their RFC 7296 names (33 = SA, 40 = Nonce), not the IKEv1 ones
    std::string all;
    std::function<void(const packet::Field &)> walk = [&](const packet::Field &x) { all += x.text + "\n"; for (const auto &c: x.children) walk(c); };
    for (const auto &x: p.fields) walk(x);
    EXPECT_NE(all.find("Payload: Security Association (SA) (8 bytes)"), std::string::npos) << all;
    EXPECT_NE(all.find("Payload: Nonce (Ni, Nr) (20 bytes)"), std::string::npos) << all;
}

TEST(IkeClaim, NonEspMarkerOnPort4500IsSkipped) {
    Bytes marked = {0, 0, 0, 0};
    const Bytes ike = ikeInit();
    marked.insert(marked.end(), ike.begin(), ike.end());
    const auto p = udpFrame(4500, 4500, marked);
    EXPECT_EQ(p.protocol, "IKEv2");
    framesweep::expectInside(p, 14 + 20 + 8 + marked.size(), "marker");
}

// I-4: ESP in UDP (RFC 3948) is what 4500 normally carries; its first four bytes (the SPI) are not zero
TEST(IkeClaim, EspInUdpOnPort4500IsEsp) {
    Bytes esp = be32(0x11223344);
    const Bytes rest = {0, 0, 0, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    esp.insert(esp.end(), rest.begin(), rest.end());
    const auto p = udpFrame(4500, 4500, esp);
    EXPECT_EQ(p.protocol, "ESP");
    EXPECT_EQ(p.tcp_pdu_start, 0x11223344u);
    EXPECT_EQ(p.app_code, 7u);
    auto f = filter::Filter::compile("esp.spi == 0x11223344 && !ike");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(p));
}

TEST(IkeClaim, KeepaliveAndNonIkeDatagramsFallThrough) {
    EXPECT_EQ(udpFrame(4500, 4500, {0xff}).protocol, "NAT-Keepalive");
    // random bytes on 500, a wrong version, an implausible exchange type, a Length that is not the datagram's
    Bytes random(40);
    for (size_t i = 0; i < random.size(); ++i) random[i] = static_cast<uint8_t>(i * 37 + 11);
    EXPECT_EQ(udpFrame(500, 500, random).protocol, "UDP");
    EXPECT_EQ(udpFrame(500, 500, ikeInit(34, 0x30)).protocol, "UDP");
    EXPECT_EQ(udpFrame(500, 500, ikeInit(99, 0x20)).protocol, "UDP");
    Bytes longer = ikeInit();
    longer.push_back(0);   // a datagram one byte longer than the header Length
    EXPECT_EQ(udpFrame(500, 500, longer).protocol, "UDP");
    EXPECT_EQ(udpFrame(500, 500, {1, 2, 3}).protocol, "UDP");
    // the IKE field no longer matches a mere port number
    auto f = filter::Filter::compile("ike");
    ASSERT_TRUE(f.ok);
    EXPECT_FALSE(f.filter.matches(udpFrame(500, 500, random)));
}

// I-5: a payload Length of 65535 in a 56-byte datagram
TEST(IkeClaim, PayloadLengthBeyondThePacketIsClampedAndFlagged) {
    Bytes b = ikeInit();
    b[30] = 0xff;
    b[31] = 0xff;
    const auto p = udpFrame(500, 500, b);
    EXPECT_EQ(p.protocol, "IKEv2");
    EXPECT_NE(p.info.find("Malformed"), std::string::npos) << p.info;
    framesweep::expectInside(p, 14 + 20 + 8 + b.size(), "payload 65535");
    Bytes tiny = ikeInit();
    tiny[31] = 2;   // below the 4-byte payload header
    EXPECT_NE(udpFrame(500, 500, tiny).info.find("Malformed"), std::string::npos);
}

TEST(Ipsec, AhAndEspSweepsAndFilters) {
    Bytes ah = {6, 4, 0, 0, 0, 0, 0x12, 0x34, 0, 0, 0, 9, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,   // Next Header 6, 24 bytes
                0x00, 0x14, 0x00, 0x50};                                                    // start of the protected TCP header
    const auto p = framesweep::parseEthernet(framesweep::ethernet(0x0800, framesweep::ipv4Packet(51, ah)));
    EXPECT_EQ(p.protocol, "AH");
    auto f = filter::Filter::compile("ah.spi == 0x1234 && ah.sequence == 9");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(p));

    const Bytes esp = {0, 0, 0x12, 0x34, 0, 0, 0, 3, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2};
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(51, ah)), 0x1b5ec001u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(50, esp)), 0x1b5ec002u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(500, 500, ikeInit()))), 0x1b5ec003u);
    Bytes marked = {0, 0, 0, 0};
    const Bytes ike = ikeInit(37);
    marked.insert(marked.end(), ike.begin(), ike.end());
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(4500, 4500, marked))), 0x1b5ec004u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(4500, 4500, esp))), 0x1b5ec005u);
}

TEST(Ipsec, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"AH", "ESP", "IKEv2", "ISAKMP"});
}
