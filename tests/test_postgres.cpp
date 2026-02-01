#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/postgres.h>
#include "support.h"

using support::parse;
using namespace dissect;

namespace {

std::vector<char> makeTcpPacket(uint16_t sport, uint16_t dport, const std::vector<uint8_t> &tcpPayload) {
    std::vector<uint8_t> frame = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x08, 0x00
    };

    size_t ipTotalLen = 20 + 20 + tcpPayload.size();
    std::vector<uint8_t> ip = {
        0x45, 0x00, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
        0x00, 0x01, 0x00, 0x00,
        64, 6, 0x00, 0x00,
        10, 0, 0, 1,
        10, 0, 0, 2
    };

    uint32_t csum = 0;
    for (size_t i = 0; i < ip.size(); i += 2) csum += (ip[i] << 8) | ip[i + 1];
    while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
    uint16_t folded = static_cast<uint16_t>(~csum);
    ip[10] = static_cast<uint8_t>(folded >> 8);
    ip[11] = static_cast<uint8_t>(folded & 0xff);

    std::vector<uint8_t> tcp = {
        static_cast<uint8_t>(sport >> 8), static_cast<uint8_t>(sport & 0xff),
        static_cast<uint8_t>(dport >> 8), static_cast<uint8_t>(dport & 0xff),
        0, 0, 0, 1, // Seq 1
        0, 0, 0, 1, // Ack 1
        0x50, 0x18, 0x20, 0x00, // ACK + PSH
        0, 0, 0, 0 // checksum placeholder
    };

    frame.insert(frame.end(), ip.begin(), ip.end());
    frame.insert(frame.end(), tcp.begin(), tcp.end());
    frame.insert(frame.end(), tcpPayload.begin(), tcpPayload.end());

    std::vector<char> out(frame.size());
    std::memcpy(out.data(), frame.data(), frame.size());
    return out;
}

} // namespace

TEST(Postgres, SimpleQueryMessage) {
    // 'Q' + 4-byte length (includes length itself: 4 + 19 = 23) + "SELECT version();\0"
    std::string q = "SELECT version();";
    uint32_t len = 4 + q.size() + 1;
    std::vector<uint8_t> pdu = {'Q'};
    pdu.push_back(static_cast<uint8_t>(len >> 24));
    pdu.push_back(static_cast<uint8_t>(len >> 16));
    pdu.push_back(static_cast<uint8_t>(len >> 8));
    pdu.push_back(static_cast<uint8_t>(len & 0xff));
    pdu.insert(pdu.end(), q.begin(), q.end());
    pdu.push_back(0);

    auto pkt = parse(makeTcpPacket(54321, 5432, pdu));

    EXPECT_EQ(pkt.protocol, "PGSQL");
    EXPECT_NE(pkt.info.find("SELECT version();"), std::string::npos);
}

TEST(Postgres, SslRequestMessage) {
    // SSLRequest: 8 bytes (len 8, code 80877103 = 0x04D2162F)
    std::vector<uint8_t> pdu = {0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f};

    auto pkt = parse(makeTcpPacket(54321, 5432, pdu));

    EXPECT_EQ(pkt.protocol, "PGSQL");
    EXPECT_EQ(pkt.info, "SSLRequest");
}

TEST(Postgres, StreamFramer) {
    // Simple query frame: 'Q' + len(9) + "hi\0"
    std::vector<uint8_t> streamData = {'Q', 0x00, 0x00, 0x00, 0x07, 'h', 'i', 0x00};

    auto f1 = framePostgreSql(reinterpret_cast<const char *>(streamData.data()), 4);
    EXPECT_EQ(f1.kind, StreamFrame::Kind::NeedMore);

    auto f2 = framePostgreSql(reinterpret_cast<const char *>(streamData.data()), 7);
    EXPECT_EQ(f2.kind, StreamFrame::Kind::NeedMore);

    auto f3 = framePostgreSql(reinterpret_cast<const char *>(streamData.data()), 8);
    EXPECT_EQ(f3.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(f3.length, 8u);
}
