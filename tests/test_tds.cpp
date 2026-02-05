#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>
#include <dissect/tds.h>
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

TEST(Tds, PreLoginMessage) {
    // TDS Header: Type 18 (Pre-Login), Status 0x01 (EOM), Length 8, SPID 0, PacketID 1, Window 0
    std::vector<uint8_t> pdu = {
        0x12, 0x01, 0x00, 0x08, 0x00, 0x00, 0x01, 0x00
    };

    auto pkt = parse(makeTcpPacket(54321, 1433, pdu));

    EXPECT_EQ(pkt.protocol, "TDS");
    EXPECT_EQ(pkt.app_type, 18);
    EXPECT_NE(pkt.info.find("Pre-Login"), std::string::npos);
}

TEST(Tds, SqlBatchMessage) {
    // Type 1 (SQL Batch), Status 1 (EOM), Length 8 + UTF16 SQL text ("SELECT 1")
    std::u16string sql = u"SELECT 1";
    uint16_t totalLen = 8 + static_cast<uint16_t>(sql.size() * 2);

    std::vector<uint8_t> pdu = {
        0x01, 0x01,
        static_cast<uint8_t>(totalLen >> 8), static_cast<uint8_t>(totalLen & 0xff),
        0x00, 0x10, // SPID 16
        0x01, 0x00
    };
    for (char16_t c : sql) {
        pdu.push_back(static_cast<uint8_t>(c & 0xff));
        pdu.push_back(static_cast<uint8_t>((c >> 8) & 0xff));
    }

    auto pkt = parse(makeTcpPacket(54321, 1433, pdu));

    EXPECT_EQ(pkt.protocol, "TDS");
    EXPECT_EQ(pkt.app_type, 1);
    EXPECT_NE(pkt.info.find("SELECT 1"), std::string::npos);
}

TEST(Tds, StreamFramer) {
    std::vector<uint8_t> streamData = {
        0x01, 0x01, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00,
        'a', 0x00, 'b', 0x00
    };

    auto f1 = frameTds(reinterpret_cast<const char *>(streamData.data()), 6);
    EXPECT_EQ(f1.kind, StreamFrame::Kind::NeedMore);

    auto f2 = frameTds(reinterpret_cast<const char *>(streamData.data()), 10);
    EXPECT_EQ(f2.kind, StreamFrame::Kind::NeedMore);

    auto f3 = frameTds(reinterpret_cast<const char *>(streamData.data()), 12);
    EXPECT_EQ(f3.kind, StreamFrame::Kind::Complete);
    EXPECT_EQ(f3.length, 12u);
}
