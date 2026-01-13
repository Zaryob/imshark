#include <gtest/gtest.h>

#include <core.h>
#include <dissect/checksum.h>
#include <filter/filter.h>

#include "support.h"

using support::parse;

namespace {
    // Helper to wrap SCTP in IPv4 + Ethernet
    // IPv4 src=10.0.0.1, dst=10.0.0.2, proto=132
    std::vector<char> makeSctpPacket(uint16_t sport, uint16_t dport, uint32_t vtag, const std::vector<uint8_t> &chunksPayload) {
        std::vector<uint8_t> frame = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x08, 0x00
        };

        size_t totalSctpLen = 12 + chunksPayload.size();
        size_t ipTotalLen = 20 + totalSctpLen;

        std::vector<uint8_t> ip = {
            0x45, 0x00, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
            0x00, 0x01, 0x00, 0x00,
            64, 132, 0x00, 0x00,
            10, 0, 0, 1,
            10, 0, 0, 2
        };
        // IPv4 checksum
        uint32_t csum = 0;
        for (size_t i = 0; i < ip.size(); i += 2) csum += (ip[i] << 8) | ip[i + 1];
        while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
        uint16_t folded = static_cast<uint16_t>(~csum);
        ip[10] = static_cast<uint8_t>(folded >> 8);
        ip[11] = static_cast<uint8_t>(folded & 0xff);

        // SCTP common header (12 bytes)
        std::vector<uint8_t> sctp = {
            static_cast<uint8_t>(sport >> 8), static_cast<uint8_t>(sport & 0xff),
            static_cast<uint8_t>(dport >> 8), static_cast<uint8_t>(dport & 0xff),
            static_cast<uint8_t>(vtag >> 24), static_cast<uint8_t>((vtag >> 16) & 0xff),
            static_cast<uint8_t>((vtag >> 8) & 0xff), static_cast<uint8_t>(vtag & 0xff),
            0, 0, 0, 0 // checksum placeholder
        };
        sctp.insert(sctp.end(), chunksPayload.begin(), chunksPayload.end());

        // Calculate CRC-32C
        uint32_t calcCrc = 0;
        dissect::checkSctpCrc32c(reinterpret_cast<const char *>(sctp.data()), sctp.size(), nullptr, &calcCrc);
        sctp[8] = static_cast<uint8_t>(calcCrc & 0xff);
        sctp[9] = static_cast<uint8_t>((calcCrc >> 8) & 0xff);
        sctp[10] = static_cast<uint8_t>((calcCrc >> 16) & 0xff);
        sctp[11] = static_cast<uint8_t>((calcCrc >> 24) & 0xff);

        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.insert(frame.end(), sctp.begin(), sctp.end());
        return std::vector<char>(frame.begin(), frame.end());
    }
} // namespace

TEST(Sctp, ShutdownCompletePacket) {
    // SHUTDOWN_COMPLETE chunk: type=14, flags=0, length=4
    std::vector<uint8_t> chunks = {14, 0, 0, 4};
    auto pkt = parse(makeSctpPacket(5000, 5000, 0x12345678, chunks));

    EXPECT_EQ(pkt.protocol, "SCTP");
    EXPECT_EQ(pkt.src_port, 5000);
    EXPECT_EQ(pkt.dst_port, 5000);
    EXPECT_EQ(pkt.tcp_pdu_start, 0x12345678U);
    EXPECT_NE(pkt.info.find("SHUTDOWN_COMPLETE"), std::string::npos);

    // Filter check
    auto f = filter::Filter::compile("sctp && sctp.port == 5000 && sctp.vtag == 0x12345678");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}

TEST(Sctp, DataChunkBreakdown) {
    // DATA chunk: type=0, flags=0x03 (U + B + E), length=16 + 5 = 21 (padded to 24)
    // TSN=100, StreamID=1, SSN=0, PPID=3 (WebRTC DCEP)
    std::vector<uint8_t> chunks = {
        0, 0x07, 0, 21,
        0, 0, 0, 100, // TSN
        0, 1,         // Stream ID
        0, 0,         // SSN
        0, 0, 0, 3,   // PPID
        'h', 'e', 'l', 'l', 'o',
        0, 0, 0       // 3 bytes padding
    };
    auto pkt = parse(makeSctpPacket(38412, 5000, 0x99887766, chunks));

    EXPECT_EQ(pkt.protocol, "SCTP");
    EXPECT_EQ(pkt.src_port, 38412);
    EXPECT_EQ(pkt.dst_port, 5000);
    EXPECT_NE(pkt.info.find("DATA"), std::string::npos);

    auto f = filter::Filter::compile("sctp.chunk_type == 0");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}
