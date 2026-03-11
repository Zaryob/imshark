#include <gtest/gtest.h>

#include <core.h>
#include <dissect/checksum.h>
#include <filter/filter.h>

#include "frame_sweep.h"
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

namespace {
    using framesweep::Bytes;

    packet::PacketInfo sctpFrame(const Bytes &sctp) {
        return framesweep::parseEthernet(framesweep::ethernet(0x0800, framesweep::ipv4Packet(132, sctp)));
    }
    uint8_t sctpState(const packet::PacketInfo &p) { return dissect::transportChecksumState(p); }
    const packet::Field *firstNamed(const std::vector<packet::Field> &fs, const std::string &prefix) {
        for (const auto &f: fs) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (const auto *c = firstNamed(f.children, prefix)) return c;
        }
        return nullptr;
    }
} // namespace

// CRC-32C values from an independent bitwise Python implementation (reflected polynomial 0x82F63B78, init and final
// xor 0xffffffff; it reproduces crc32c(b"123456789") == 0xe3069283), computed over the packet with the checksum
// field zero and stored little-endian (RFC 4960 appendix B):
//   DATA packet below            -> 0x7654e8c9 -> bytes c9 e8 54 76
//   HEARTBEAT packet below       -> 0xd2d8f780 -> bytes 80 f7 d8 d2
TEST(Sctp, CrcMatchesAnIndependentComputation) {
    const Bytes data = {0x13, 0x88, 0x95, 0x0c, 0x12, 0x34, 0x56, 0x78, 0xc9, 0xe8, 0x54, 0x76,
                        0, 3, 0, 20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 60, 0x61, 0x62, 0x63, 0x64};
    const auto good = sctpFrame(data);
    EXPECT_EQ(sctpState(good), dissect::kChecksumGood);
    EXPECT_EQ(good.src_port, 5000);
    EXPECT_EQ(good.dst_port, 38156);   // 0x950c
    EXPECT_EQ(good.tcp_pdu_start, 0x12345678u);
    Bytes corrupt = data;
    corrupt[30] ^= 0x01;
    EXPECT_EQ(sctpState(sctpFrame(corrupt)), dissect::kChecksumBad);

    const Bytes hb = {0x13, 0x88, 0x95, 0x0c, 0x12, 0x34, 0x56, 0x78, 0x80, 0xf7, 0xd8, 0xd2, 4, 0, 0, 8, 0xde, 0xad, 0xbe, 0xef};
    EXPECT_EQ(sctpState(sctpFrame(hb)), dissect::kChecksumGood);
}

// I-5: a chunk Length of 65520 inside a 36-byte packet used to be reported as the field length (and the User Data
// child as 65504 bytes), far outside the frame.
TEST(Sctp, ChunkLengthBeyondThePacketIsClampedAndFlagged) {
    Bytes b = {0x13, 0x88, 0x95, 0x0c, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0,
               0, 3, 0xff, 0xf0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 60, 0x61, 0x62, 0x63, 0x64};
    const auto p = sctpFrame(b);
    EXPECT_NE(p.info.find("Malformed"), std::string::npos) << p.info;
    EXPECT_EQ(sctpState(p), dissect::kChecksumUnverified);
    framesweep::expectInside(p, 14 + 20 + b.size(), "clamped chunk");
    const auto *chunk = firstNamed(p.fields, "Chunk: DATA");
    ASSERT_NE(chunk, nullptr);
    EXPECT_EQ(size_t(chunk->offset) + chunk->length, 14 + 20 + b.size());
    EXPECT_NE(chunk->text.find("Length: 65520"), std::string::npos);   // the stated length is still shown
}

TEST(Sctp, TruncationAndMutationStayInsideTheFrame) {
    const Bytes data = {0x13, 0x88, 0x95, 0x0c, 0x12, 0x34, 0x56, 0x78, 0xc9, 0xe8, 0x54, 0x76,
                        0, 3, 0, 20, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 60, 0x61, 0x62, 0x63, 0x64};
    const Bytes hb = {0x13, 0x88, 0x95, 0x0c, 0x12, 0x34, 0x56, 0x78, 0x80, 0xf7, 0xd8, 0xd2, 4, 0, 0, 8, 0xde, 0xad, 0xbe, 0xef};
    Bytes two = data;   // two chunks: DATA padded to 4 bytes, then a SHUTDOWN_ACK
    two.insert(two.end(), {8, 0, 0, 4});
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(132, data)), 0x5c700001u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(132, hb)), 0x5c700002u);
    framesweep::sweep(framesweep::ethernet(0x0800, framesweep::ipv4Packet(132, two)), 0x5c700003u);
}

TEST(Sctp, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"SCTP"});
}
