#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/mysql.h>
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

TEST(MySql, ComQueryMessage) {
    // 3 bytes payload len, 1 byte seq (0), command (0x03 COM_QUERY), query string
    std::string q = "SELECT 1";
    uint32_t len = 1 + q.size();
    std::vector<uint8_t> pdu = {
        static_cast<uint8_t>(len & 0xff),
        static_cast<uint8_t>((len >> 8) & 0xff),
        static_cast<uint8_t>((len >> 16) & 0xff),
        0x00, // Seq ID = 0
        0x03  // COM_QUERY
    };
    pdu.insert(pdu.end(), q.begin(), q.end());

    auto pkt = parse(makeTcpPacket(54321, 3306, pdu));

    EXPECT_EQ(pkt.protocol, "MySQL");
    EXPECT_EQ(pkt.app_type, 3);
    EXPECT_NE(pkt.info.find("SELECT 1"), std::string::npos);
}

TEST(MySql, ServerGreetingMessage) {
    // Handshake initialization (version 10 = 0x0A, server string "8.0.32\0")
    std::string ver = "8.0.32";
    uint32_t len = 1 + ver.size() + 1;
    std::vector<uint8_t> pdu = {
        static_cast<uint8_t>(len & 0xff),
        static_cast<uint8_t>((len >> 8) & 0xff),
        static_cast<uint8_t>((len >> 16) & 0xff),
        0x00, // Seq ID = 0
        0x0a  // Protocol 10
    };
    pdu.insert(pdu.end(), ver.begin(), ver.end());
    pdu.push_back(0); // null terminator

    auto pkt = parse(makeTcpPacket(3306, 54321, pdu));

    EXPECT_EQ(pkt.protocol, "MySQL");
    EXPECT_NE(pkt.info.find("Server Greeting"), std::string::npos);
    EXPECT_NE(pkt.info.find("8.0.32"), std::string::npos);
}

TEST(MySql, StreamFramer) {
    std::vector<uint8_t> streamData = {0x05, 0x00, 0x00, 0x00, 0x03, 't', 'e', 's', 't'};

    auto f1 = frameMySql(reinterpret_cast<const char *>(streamData.data()), 3);
    EXPECT_EQ(f1.kind, StreamFrame::Kind::NeedMore);

    auto f2 = frameMySql(reinterpret_cast<const char *>(streamData.data()), 8);
    EXPECT_EQ(f2.kind, StreamFrame::Kind::NeedMore);

    auto f3 = frameMySql(reinterpret_cast<const char *>(streamData.data()), 9);
    EXPECT_EQ(f3.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(f3.length, 9u);
}
