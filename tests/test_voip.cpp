#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/voip.h>
#include "support.h"

using support::parse;
using namespace dissect;

namespace {

std::vector<char> makeUdpPacket(uint16_t sport, uint16_t dport, const std::vector<uint8_t> &udpPayload) {
    std::vector<uint8_t> frame = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x00
    };

    size_t ipTotalLen = 20 + 8 + udpPayload.size();
    std::vector<uint8_t> ip = {
        0x45, 0x00, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
        0x00, 0x01, 0x00, 0x00,
        64, 17, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2
    };

    uint32_t csum = 0;
    for (size_t i = 0; i < ip.size(); i += 2) csum += (ip[i] << 8) | ip[i + 1];
    while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
    uint16_t folded = static_cast<uint16_t>(~csum);
    ip[10] = static_cast<uint8_t>(folded >> 8);
    ip[11] = static_cast<uint8_t>(folded & 0xff);

    size_t udpLen = 8 + udpPayload.size();
    std::vector<uint8_t> udp = {
        static_cast<uint8_t>(sport >> 8), static_cast<uint8_t>(sport & 0xff),
        static_cast<uint8_t>(dport >> 8), static_cast<uint8_t>(dport & 0xff),
        static_cast<uint8_t>(udpLen >> 8), static_cast<uint8_t>(udpLen & 0xff),
        0, 0 // UDP checksum 0
    };

    frame.insert(frame.end(), ip.begin(), ip.end());
    frame.insert(frame.end(), udp.begin(), udp.end());
    frame.insert(frame.end(), udpPayload.begin(), udpPayload.end());

    std::vector<char> out(frame.size());
    std::memcpy(out.data(), frame.data(), frame.size());
    return out;
}

} // namespace

TEST(Voip, SipInviteRequestWithSdp) {
    std::string sipMsg =
        "INVITE sip:bob@biloxi.com SIP/2.0\r\n"
        "Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds\r\n"
        "Max-Forwards: 70\r\n"
        "To: Bob <sip:bob@biloxi.com>\r\n"
        "From: Alice <sip:alice@atlanta.com>;tag=1928301774\r\n"
        "Call-ID: a84b4c76e66710@pc33.atlanta.com\r\n"
        "CSeq: 314159 INVITE\r\n"
        "Contact: <sip:alice@pc33.atlanta.com>\r\n"
        "Content-Type: application/sdp\r\n"
        "Content-Length: 42\r\n"
        "\r\n"
        "v=0\r\n"
        "o=alice 2890844526 2890844526 IN IP4 10.0.0.1\r\n";

    std::vector<uint8_t> pdu(sipMsg.begin(), sipMsg.end());
    auto pkt = parse(makeUdpPacket(5060, 5060, pdu));

    EXPECT_EQ(pkt.protocol, "SIP");
    EXPECT_NE(pkt.info.find("INVITE sip:bob@biloxi.com"), std::string::npos);
    EXPECT_NE(pkt.info.find("314159 INVITE"), std::string::npos);
    EXPECT_EQ(pkt.app_text, "a84b4c76e66710@pc33.atlanta.com");
}

TEST(Voip, RtpDissection) {
    // RTP Header (12 bytes)
    // V=2, P=0, X=0, CC=0 -> 0x80
    // M=1, PT=0 (PCMU) -> 0x80
    // Seq: 1234 -> 0x04D2
    // TS: 160 -> 0x000000A0
    // SSRC: 0x11223344
    std::vector<uint8_t> pdu = {
        0x80, 0x80,
        0x04, 0xd2,
        0x00, 0x00, 0x00, 0xa0,
        0x11, 0x22, 0x33, 0x44,
        // 4 bytes payload
        1, 2, 3, 4
    };

    packet::PacketInfo pkt(1);
    network::TCPConnection conn;
    dissect::Context ctx{pkt, reinterpret_cast<const char *>(pdu.data()), pdu.size(),
                         conn, dissect::Registry::builtin(), dissect::ParseMode::Full};
    dissectRtp(ctx, reinterpret_cast<const char *>(pdu.data()), pdu.size());

    EXPECT_EQ(pkt.protocol, "RTP");
    EXPECT_EQ(pkt.app_type, 0); // PCMU
    EXPECT_NE(pkt.info.find("PT=0"), std::string::npos);
    EXPECT_NE(pkt.info.find("SSeq=1234"), std::string::npos);
    EXPECT_NE(pkt.info.find("0x11223344"), std::string::npos);
}

TEST(Voip, RtcpSenderReport) {
    // RTCP Header (8 bytes)
    // V=2, P=0, RC=0 -> 0x80
    // PT=200 (SR) -> 0xC8
    // Length: 1 (2 32-bit words total = 8 bytes) -> 0x0001
    // SSRC: 0x55667788
    std::vector<uint8_t> pdu = {
        0x80, 0xc8,
        0x00, 0x01,
        0x55, 0x66, 0x77, 0x88
    };

    packet::PacketInfo pkt(1);
    network::TCPConnection conn;
    dissect::Context ctx{pkt, reinterpret_cast<const char *>(pdu.data()), pdu.size(),
                         conn, dissect::Registry::builtin(), dissect::ParseMode::Full};
    dissectRtcp(ctx, reinterpret_cast<const char *>(pdu.data()), pdu.size());

    EXPECT_EQ(pkt.protocol, "RTCP");
    EXPECT_EQ(pkt.app_type, 200);
    EXPECT_NE(pkt.info.find("Sender Report (SR)"), std::string::npos);
    EXPECT_NE(pkt.info.find("0x55667788"), std::string::npos);
}

TEST(Voip, SipStreamFramer) {
    std::string sipMsg =
        "SIP/2.0 200 OK\r\n"
        "Content-Length: 5\r\n"
        "\r\n"
        "hello";

    auto f1 = frameSip(sipMsg.data(), 10);
    EXPECT_EQ(f1.kind, StreamFrame::Kind::NeedMore);

    auto f2 = frameSip(sipMsg.data(), sipMsg.size() - 2);
    EXPECT_EQ(f2.kind, StreamFrame::Kind::NeedMore);

    auto f3 = frameSip(sipMsg.data(), sipMsg.size());
    EXPECT_EQ(f3.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(f3.length, sipMsg.size());
}
