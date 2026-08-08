// SCTP chunk bodies and parameters (dissect/sctp_chunks.cpp) on hand-built packets.
//
// Oracles: the layouts are RFC 9260 section 3 (INIT/INIT ACK 3.3.2/3.3.3, SACK 3.3.4, HEARTBEAT 3.3.5, ABORT 3.3.7, SHUTDOWN
// 3.3.8, ERROR 3.3.10, COOKIE ECHO 3.3.11, parameters 3.2.1, error causes 3.3.10.x), RFC 8260 (I-DATA, I-FORWARD-TSN), RFC 3758
// (FORWARD-TSN) and RFC 4895 / RFC 5061 (parameters), written out byte by byte in sctp_support.h and in the tests. Three whole
// packets (INIT, SACK, FORWARD-TSN) were also built by an independent Python script (struct + bitwise CRC-32C, reproducing
// crc32c(b"123456789") == 0xe3069283) and are compared byte for byte with the C++ builders, CRC included:
//   INIT    crc 0xe17808dc  1388960c00000000dc0878e10100003cdeadbeef0000ffff000affff01020304000500080a000001000c00080005000680000004
//                           c000000480080007c0c14000000900080000ea60
//   SACK    crc 0x129fb366  960c13881234567866b39f1203000020000003e8000186a0000200020002000300050005000003e7000003e6
//   FORWARD crc 0x95e0f80c  960c1388123456780cf8e095c0000010000013880001000a00020014
#include <gtest/gtest.h>

#include <core.h>
#include <dissect/checksum.h>
#include <filter/filter.h>

#include "sctp_support.h"

using namespace sctptest;

namespace {
    packet::PacketInfo parsed(const Bytes &sctp) { return framesweep::parseEthernet(ipFrame(sctp)); }
    std::string treeOf(const Bytes &sctp) { return treeText(parsed(sctp).fields); }

    Bytes initBody() {
        Bytes b;
        put32(b, 0xdeadbeef); put32(b, 0xffff); put16(b, 10); put16(b, 65535); put32(b, 0x01020304);
        return cat({b, tlv(5, {10, 0, 0, 1}), tlv(12, {0, 5, 0, 6}), tlv(0x8000, {}), tlv(0xC000, {}), tlv(0x8008, {192, 193, 64}),
                    tlv(9, {0, 0, 0xea, 0x60})});
    }
    Bytes sackBody() {
        Bytes b;
        put32(b, 1000); put32(b, 100000); put16(b, 2); put16(b, 2);
        put16(b, 2); put16(b, 3); put16(b, 5); put16(b, 5); put32(b, 999); put32(b, 998);
        return b;
    }
    Bytes forwardBody() {
        Bytes b;
        put32(b, 5000); put16(b, 1); put16(b, 10); put16(b, 2); put16(b, 20);
        return b;
    }
    Bytes fromHex(const char *h) {
        Bytes out;
        for (size_t i = 0; h[i] && h[i + 1]; i += 2) out.push_back(static_cast<uint8_t>(std::stoi(std::string(h + i, 2), nullptr, 16)));
        return out;
    }
} // namespace

TEST(SctpChunks, TheCrcHelperAndTheBuildersMatchAnIndependentPythonConstruction) {
    EXPECT_EQ(crc32c(text("123456789")), 0xe3069283u);
    EXPECT_EQ(sctpPacket(5000, 38412, 0, chunk(1, 0, initBody())),
              fromHex("1388960c00000000dc0878e10100003cdeadbeef0000ffff000affff01020304000500080a000001000c00080005000680000004c000000480080007c0c14000000900080000ea60"));
    EXPECT_EQ(sctpPacket(38412, 5000, 0x12345678, chunk(3, 0, sackBody())),
              fromHex("960c13881234567866b39f1203000020000003e8000186a0000200020002000300050005000003e7000003e6"));
    EXPECT_EQ(sctpPacket(38412, 5000, 0x12345678, chunk(192, 0, forwardBody())),
              fromHex("960c1388123456780cf8e095c0000010000013880001000a00020014"));
}

TEST(SctpChunks, InitShowsItsFixedFieldsAndEveryParameter) {
    const Bytes pkt = sctpPacket(5000, 38412, 0, chunk(1, 0, initBody()));
    const auto p = parsed(pkt);
    EXPECT_EQ(p.info, "5000 -> 38412 [INIT]");
    EXPECT_EQ(dissect::transportChecksumState(p), dissect::kChecksumGood);
    const std::string t = treeText(p.fields);
    EXPECT_TRUE(has(t, "Initiate Tag: 0xdeadbeef")) << t;
    EXPECT_TRUE(has(t, "Advertised Receiver Window Credit (a_rwnd): 65535"));
    EXPECT_TRUE(has(t, "Number of Outbound Streams: 10"));
    EXPECT_TRUE(has(t, "Number of Inbound Streams: 65535"));
    EXPECT_TRUE(has(t, "Initial TSN: 16909060"));   // 0x01020304
    EXPECT_TRUE(has(t, "Parameter: IPv4 Address (Type: 5, Length: 8)"));
    EXPECT_TRUE(has(t, "IPv4 address: 10.0.0.1"));
    EXPECT_TRUE(has(t, "Parameter: Supported Address Types (Type: 12, Length: 8)"));
    EXPECT_TRUE(has(t, "Address Type: 5 (IPv4)"));
    EXPECT_TRUE(has(t, "Address Type: 6 (IPv6)"));
    EXPECT_TRUE(has(t, "Parameter: ECN Capable (Type: 32768, Length: 4)"));
    EXPECT_TRUE(has(t, "Parameter: Forward TSN Supported (Type: 49152, Length: 4)"));
    EXPECT_TRUE(has(t, "Parameter: Supported Extensions (Type: 32776, Length: 7)"));   // padded to 8 on the wire
    EXPECT_TRUE(has(t, "Chunk Type: 192 (FORWARD_TSN)"));
    EXPECT_TRUE(has(t, "Chunk Type: 193 (ASCONF)"));
    EXPECT_TRUE(has(t, "Chunk Type: 64 (I_DATA)"));
    EXPECT_TRUE(has(t, "Suggested Cookie Life-Span Increment (msec): 60000"));
    framesweep::expectInside(p, ipFrame(pkt).size(), "INIT");
}

TEST(SctpChunks, InitAckCarriesAStateCookieAndAnIpv6Address) {
    Bytes b;
    put32(b, 0x0badf00d); put32(b, 1500); put16(b, 2); put16(b, 2); put32(b, 77);
    const Bytes v6 = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    const Bytes body = cat({b, tlv(7, text("cookie-of-21-bytes!!!")), tlv(6, v6), tlv(11, text("host.test")),
                            tlv(0x8002, {1, 2, 3, 4}), tlv(0x8003, {0, 1}), tlv(0x8004, {0, 1, 0, 3}), tlv(0xC006, {0, 0, 0, 5})});
    const auto p = parsed(sctpPacket(38412, 5000, 0xdeadbeef, chunk(2, 0, body)));
    EXPECT_EQ(p.info, "38412 -> 5000 [INIT_ACK]");
    const std::string t = treeText(p.fields);
    EXPECT_TRUE(has(t, "Parameter: State Cookie (Type: 7, Length: 25)")) << t;
    EXPECT_TRUE(has(t, "State Cookie (21 bytes)"));
    EXPECT_TRUE(has(t, "IPv6 address: 2001:db8:0:0:0:0:0:1"));
    EXPECT_TRUE(has(t, "Host name: host.test"));
    EXPECT_TRUE(has(t, "Random number (4 bytes): 01020304"));
    EXPECT_TRUE(has(t, "Chunk Type: 0 (DATA)"));
    EXPECT_TRUE(has(t, "HMAC Identifier: 1 (SHA-1)"));
    EXPECT_TRUE(has(t, "HMAC Identifier: 3 (SHA-256)"));
    EXPECT_TRUE(has(t, "Adaptation Code Point: 5"));
}

TEST(SctpChunks, SackShowsGapAckBlocksAndDuplicateTsns) {
    const Bytes pkt = sctpPacket(38412, 5000, 0x12345678, chunk(3, 0, sackBody()));
    const auto p = parsed(pkt);
    EXPECT_EQ(dissect::transportChecksumState(p), dissect::kChecksumGood);   // the Python CRC above
    EXPECT_EQ(p.info, "38412 -> 5000 [SACK]");
    const std::string t = treeText(p.fields);
    EXPECT_TRUE(has(t, "Cumulative TSN Ack: 1000")) << t;
    EXPECT_TRUE(has(t, "Advertised Receiver Window Credit (a_rwnd): 100000"));
    EXPECT_TRUE(has(t, "Number of Gap Ack Blocks: 2"));
    EXPECT_TRUE(has(t, "Number of Duplicate TSNs: 2"));
    EXPECT_TRUE(has(t, "Gap Ack Block #1: start offset 2, end offset 3 (TSN 1002 - 1003)"));
    EXPECT_TRUE(has(t, "Gap Ack Block #2: start offset 5, end offset 5 (TSN 1005 - 1005)"));
    EXPECT_TRUE(has(t, "Duplicate TSN: 999"));
    EXPECT_TRUE(has(t, "Duplicate TSN: 998"));
    framesweep::expectInside(p, ipFrame(pkt).size(), "SACK");
}

TEST(SctpChunks, ASackWhoseCountsExceedTheChunkIsMalformedAndStaysInside) {
    Bytes b;
    put32(b, 1000); put32(b, 100000); put16(b, 500); put16(b, 500); put16(b, 2); put16(b, 3);
    const Bytes pkt = sctpPacket(38412, 5000, 1, chunk(3, 0, b));
    const auto p = parsed(pkt);
    EXPECT_NE(p.info.find("Malformed"), std::string::npos) << p.info;
    framesweep::expectInside(p, ipFrame(pkt).size(), "SACK counts");
    EXPECT_TRUE(has(treeText(p.fields), "Gap Ack Block #1"));
}

TEST(SctpChunks, HeartbeatCarriesItsInfoAndTheAckEchoesIt) {
    const Bytes hb = tlv(1, {1, 2, 3, 4, 5, 6, 7, 8});
    auto p = parsed(sctpPacket(5000, 38412, 7, chunk(4, 0, hb)));
    EXPECT_EQ(p.info, "5000 -> 38412 [HEARTBEAT]");
    EXPECT_TRUE(has(treeText(p.fields), "Heartbeat Information (8 bytes): 0102030405060708"));
    p = parsed(sctpPacket(38412, 5000, 7, chunk(5, 0, hb)));
    EXPECT_EQ(p.info, "38412 -> 5000 [HEARTBEAT_ACK]");
    EXPECT_TRUE(has(treeText(p.fields), "Heartbeat Information (8 bytes): 0102030405060708"));
}

TEST(SctpChunks, AbortAndErrorListTheirCauses) {
    Bytes stream;
    put16(stream, 7); put16(stream, 0);
    const Bytes abortBody = cat({tlv(12, text("bye")), tlv(13, text("bad chunk")), tlv(1, stream)});
    auto p = parsed(sctpPacket(5000, 38412, 9, chunk(6, 1, abortBody)));
    EXPECT_EQ(p.info, "5000 -> 38412 [ABORT]");
    std::string t = treeText(p.fields);
    EXPECT_TRUE(has(t, "T bit: set")) << t;
    EXPECT_TRUE(has(t, "Error cause: User-Initiated Abort (Code: 12, Length: 7)"));
    EXPECT_TRUE(has(t, "Reason: bye"));
    EXPECT_TRUE(has(t, "Error cause: Protocol Violation (Code: 13, Length: 13)"));
    EXPECT_TRUE(has(t, "Information: bad chunk"));
    EXPECT_TRUE(has(t, "Error cause: Invalid Stream Identifier (Code: 1, Length: 8)"));
    EXPECT_TRUE(has(t, "Stream Identifier: 7"));

    Bytes missing, stale, tsn;
    put32(missing, 2); put16(missing, 7); put16(missing, 5);
    put32(stale, 1500000);
    put32(tsn, 123456);
    const Bytes errBody = cat({tlv(2, missing), tlv(3, stale), tlv(6, {0xc1, 0x00, 0x00, 0x08}), tlv(9, tsn), tlv(4, {}), tlv(10, {}),
                               tlv(5, tlv(5, {192, 0, 2, 1})), tlv(8, tlv(0x4242, {9, 9})), tlv(11, tlv(5, {192, 0, 2, 9})), tlv(99, {1})});
    p = parsed(sctpPacket(5000, 38412, 9, chunk(9, 0, errBody)));
    EXPECT_EQ(p.info, "5000 -> 38412 [ERROR]");
    t = treeText(p.fields);
    EXPECT_TRUE(has(t, "Error cause: Missing Mandatory Parameter (Code: 2, Length: 12)")) << t;
    EXPECT_TRUE(has(t, "Missing parameter type: 7 (State Cookie)"));
    EXPECT_TRUE(has(t, "Missing parameter type: 5 (IPv4 Address)"));
    EXPECT_TRUE(has(t, "Error cause: Stale Cookie (Code: 3, Length: 8)"));
    EXPECT_TRUE(has(t, "Measure of Staleness (usec): 1500000"));
    EXPECT_TRUE(has(t, "Unrecognized chunk type: 193 (ASCONF)"));
    EXPECT_TRUE(has(t, "TSN value: 123456"));
    EXPECT_TRUE(has(t, "Error cause: Out of Resource (Code: 4, Length: 4)"));
    EXPECT_TRUE(has(t, "Error cause: Cookie Received While Shutting Down (Code: 10, Length: 4)"));
    EXPECT_TRUE(has(t, "IPv4 address: 192.0.2.1"));
    EXPECT_TRUE(has(t, "IPv4 address: 192.0.2.9"));
    EXPECT_TRUE(has(t, "Error cause: Restart of an Association with New Addresses (Code: 11"));
    EXPECT_TRUE(has(t, "Error cause: Cause 99 (Code: 99, Length: 5)"));
}

TEST(SctpChunks, ShutdownCookieAndCongestionChunks) {
    Bytes cum;
    put32(cum, 4242);
    auto p = parsed(sctpPacket(5000, 38412, 3, chunk(7, 0, cum)));
    EXPECT_TRUE(has(treeText(p.fields), "Cumulative TSN Ack: 4242"));
    p = parsed(sctpPacket(5000, 38412, 3, cat({chunk(8, 0, {}), chunk(14, 1, {})})));
    EXPECT_EQ(p.info, "5000 -> 38412 [SHUTDOWN_ACK, SHUTDOWN_COMPLETE]");
    EXPECT_TRUE(has(treeText(p.fields), "T bit: set"));
    p = parsed(sctpPacket(5000, 38412, 3, cat({chunk(10, 0, text("COOKIE-BYTES")), chunk(11, 0, {})})));
    EXPECT_EQ(p.info, "5000 -> 38412 [COOKIE_ECHO, COOKIE_ACK]");
    EXPECT_TRUE(has(treeText(p.fields), "Cookie (12 bytes)"));
    p = parsed(sctpPacket(5000, 38412, 3, cat({chunk(12, 0, cum), chunk(13, 0, cum)})));
    EXPECT_EQ(p.info, "5000 -> 38412 [ECNE, CWR]");
    EXPECT_TRUE(has(treeText(p.fields), "Lowest TSN: 4242"));
}

TEST(SctpChunks, ForwardTsnAndIForwardTsnListTheirStreams) {
    auto p = parsed(sctpPacket(38412, 5000, 0x12345678, chunk(192, 0, forwardBody())));
    EXPECT_EQ(dissect::transportChecksumState(p), dissect::kChecksumGood);
    EXPECT_EQ(p.info, "38412 -> 5000 [FORWARD_TSN]");
    std::string t = treeText(p.fields);
    EXPECT_TRUE(has(t, "New Cumulative TSN: 5000"));
    EXPECT_TRUE(has(t, "Stream: 1, Stream Sequence Number: 10"));
    EXPECT_TRUE(has(t, "Stream: 2, Stream Sequence Number: 20"));

    Bytes b;
    put32(b, 9000); put16(b, 3); put16(b, 1); put32(b, 77); put16(b, 4); put16(b, 0); put32(b, 78);
    p = parsed(sctpPacket(38412, 5000, 1, chunk(194, 0, b)));
    EXPECT_EQ(p.info, "38412 -> 5000 [I_FORWARD_TSN]");
    t = treeText(p.fields);
    EXPECT_TRUE(has(t, "New Cumulative TSN: 9000"));
    EXPECT_TRUE(has(t, "Stream: 3, unordered, Message Identifier: 77"));
    EXPECT_TRUE(has(t, "Stream: 4, ordered, Message Identifier: 78"));
}

TEST(SctpChunks, DataAndIDataShowTheirHeadersAndThePayloadProtocolName) {
    auto p = parsed(sctpPacket(5000, 38412, 3, data(0x03, 100, 4, 9, 51, "hello")));
    std::string t = treeText(p.fields);
    EXPECT_TRUE(has(t, "TSN: 100")) << t;
    EXPECT_TRUE(has(t, "Stream Identifier: 4"));
    EXPECT_TRUE(has(t, "Stream Sequence Number: 9"));
    EXPECT_TRUE(has(t, "Payload Protocol Identifier: 51 (WebRTC String)"));
    EXPECT_TRUE(has(t, "Flags: 0x03 (--BE)"));
    EXPECT_TRUE(has(t, "User Data (5 bytes)"));
    p = parsed(sctpPacket(5000, 38412, 3, data(0x0f, 100, 4, 9, 123456, "")));
    EXPECT_TRUE(has(treeText(p.fields), "Flags: 0x0f (IUBE)"));
    EXPECT_TRUE(has(treeText(p.fields), "Payload Protocol Identifier: 123456"));

    // I-DATA first fragment: PPID; the next fragments: FSN
    p = parsed(sctpPacket(5000, 38412, 3, idata(0x02, 7, 5, 1000, 46, "AAAA")));
    t = treeText(p.fields);
    EXPECT_EQ(p.info, "5000 -> 38412 [I_DATA]");
    EXPECT_TRUE(has(t, "Message Identifier: 1000")) << t;
    EXPECT_TRUE(has(t, "Payload Protocol Identifier: 46 (Diameter)"));
    p = parsed(sctpPacket(5000, 38412, 3, idata(0x01, 9, 5, 1000, 2, "BB")));
    t = treeText(p.fields);
    EXPECT_TRUE(has(t, "Fragment Sequence Number: 2")) << t;
    EXPECT_FALSE(has(t, "Payload Protocol Identifier"));
}

TEST(SctpChunks, ChunksTooShortForTheirFixedPartAreMalformed) {
    for (uint8_t type: {1, 2, 3, 7, 12, 13, 192, 194}) {
        SCOPED_TRACE(int(type));
        const Bytes pkt = sctpPacket(5000, 38412, 3, chunk(type, 0, type <= 3 ? Bytes{0, 0, 0, 1} : Bytes{}));
        const auto p = parsed(pkt);
        EXPECT_NE(p.info.find("Malformed"), std::string::npos) << p.info;
        framesweep::expectInside(p, ipFrame(pkt).size(), "short chunk");
    }
    // an INIT parameter that claims more than the chunk holds, and one with a length below 4
    Bytes b;
    put32(b, 1); put32(b, 1); put16(b, 1); put16(b, 1); put32(b, 1);
    for (int bad: {200, 2}) {
        const Bytes pkt = sctpPacket(5000, 38412, 0, chunk(1, 0, cat({b, tlv(5, {10, 0, 0, 1}, bad)})));
        const auto p = parsed(pkt);
        EXPECT_NE(p.info.find("Malformed"), std::string::npos) << bad << ": " << p.info;
        framesweep::expectInside(p, ipFrame(pkt).size(), "bad parameter");
    }
}

TEST(SctpChunks, ABundleKeepsEveryChunkAndTheFirstTypeFilterWorks) {
    const Bytes pkt = sctpPacket(38412, 5000, 0x12345678, cat({chunk(3, 0, sackBody()), data(0x03, 10, 0, 0, 0, "abc"), chunk(4, 0, tlv(1, {1, 2, 3, 4}))}));
    const auto p = parsed(pkt);
    EXPECT_EQ(p.info, "38412 -> 5000 [SACK, DATA, HEARTBEAT]");
    EXPECT_EQ(p.app_type, 3);
    auto f = filter::Filter::compile("sctp.chunk_type == 3");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(p));
}

// A frame found by the mutation sweep: the IPv4 version/IHL byte became 0x7a (a 40 byte header), so the SCTP packet starts in the
// middle of the real one and the "chunk" at its end is an ERROR chunk with Length 0 and a single byte of room.
TEST(SctpChunks, AChunkWithLengthZeroHasNoBody) {
    const Bytes f = fromHex("00112233445566778899aabb08007a000038000100004084663f0a0000010a0000021388960c000000018f9ebfb5"
                            "0900001800030008000000090008000c4242000609090000");
    const auto p = framesweep::parseEthernet(f);
    EXPECT_NE(p.info.find("Malformed"), std::string::npos) << p.info;
    framesweep::expectInside(p, f.size(), "length zero chunk");
}

TEST(SctpChunks, EveryCutAndMutationOfTheChunkPacketsStaysInsideTheFrame) {
    Bytes b;
    put32(b, 0x0badf00d); put32(b, 1500); put16(b, 2); put16(b, 2); put32(b, 77);
    uint32_t seed = 0x5c7a0000u;
    const std::vector<Bytes> packets = {
        sctpPacket(5000, 38412, 0, chunk(1, 0, initBody())),
        sctpPacket(38412, 5000, 1, chunk(2, 0, cat({b, tlv(7, text("cookie")), tlv(6, Bytes(16, 1))}))),
        sctpPacket(38412, 5000, 1, chunk(3, 0, sackBody())),
        sctpPacket(5000, 38412, 1, chunk(6, 1, cat({tlv(12, text("bye")), tlv(2, {0, 0, 0, 1, 0, 7, 0, 0})}))),
        sctpPacket(5000, 38412, 1, chunk(9, 0, cat({tlv(3, {0, 0, 0, 9}), tlv(8, tlv(0x4242, {9, 9}))}))),
        sctpPacket(38412, 5000, 1, chunk(192, 0, forwardBody())),
        sctpPacket(38412, 5000, 1, chunk(194, 0, cat({Bytes{0, 0, 0, 1}, Bytes{0, 3, 0, 1, 0, 0, 0, 7}}))),
        sctpPacket(38412, 5000, 1, cat({idata(0x02, 1, 1, 1, 51, "xy"), idata(0x01, 2, 1, 1, 1, "z"), data(0x03, 3, 1, 1, 0, "q")})),
        sctpPacket(5000, 38412, 1, cat({chunk(4, 0, tlv(1, {1, 2, 3, 4})), chunk(10, 0, text("COOKIE")), chunk(7, 0, Bytes{0, 0, 0, 1})})),
    };
    for (const auto &pkt: packets) framesweep::sweep(ipFrame(pkt), seed++);
}
