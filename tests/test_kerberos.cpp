#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/kerberos.h>
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
        0, 0 // UDP checksum 0 (none)
    };

    frame.insert(frame.end(), ip.begin(), ip.end());
    frame.insert(frame.end(), udp.begin(), udp.end());
    frame.insert(frame.end(), udpPayload.begin(), udpPayload.end());

    std::vector<char> out(frame.size());
    std::memcpy(out.data(), frame.data(), frame.size());
    return out;
}

} // namespace

TEST(Kerberos, KrbErrorPacket) {
    // Construct a KRB-ERROR packet:
    // [APPLICATION 30] SEQUENCE {
    //   [0] INTEGER 5 (pvno)
    //   [1] INTEGER 30 (msg-type: KRB-ERROR)
    //   [9] INTEGER 25 (error-code: KDC_ERR_PREAUTH_REQUIRED)
    // }
    std::vector<uint8_t> pdu = {
        0x7e, 0x11, // [APPLICATION 30] len 17
          0x30, 0x0f, // SEQUENCE len 15
            0xa0, 0x03, 0x02, 0x01, 0x05, // [0] pvno = 5
            0xa1, 0x03, 0x02, 0x01, 0x1e, // [1] msg-type = 30
            0xa9, 0x03, 0x02, 0x01, 0x19  // [9] error-code = 25 (KDC_ERR_PREAUTH_REQUIRED)
    };

    auto pkt = parse(makeUdpPacket(88, 54321, pdu));

    EXPECT_EQ(pkt.protocol, "Kerberos");
    EXPECT_EQ(pkt.app_type, 30);
    EXPECT_EQ(pkt.app_code, 25);
    EXPECT_NE(pkt.app_text.find("KRB-ERROR"), std::string::npos);
    EXPECT_NE(pkt.app_text.find("KDC_ERR_PREAUTH_REQUIRED"), std::string::npos);
}

TEST(Kerberos, TcpStreamFramer) {
    // 4-byte length prefix: 10 bytes payload
    std::vector<uint8_t> streamData = {0x00, 0x00, 0x00, 0x0a, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    auto f1 = frameKerberos(reinterpret_cast<const char *>(streamData.data()), 3);
    EXPECT_EQ(f1.kind, StreamFrame::Kind::NeedMore);

    auto f2 = frameKerberos(reinterpret_cast<const char *>(streamData.data()), 10);
    EXPECT_EQ(f2.kind, StreamFrame::Kind::NeedMore);

    auto f3 = frameKerberos(reinterpret_cast<const char *>(streamData.data()), 14);
    EXPECT_EQ(f3.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(f3.length, 14u);
}
