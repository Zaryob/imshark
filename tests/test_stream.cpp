#include <gtest/gtest.h>

#include <algorithm>
#include <random>

#include <core.h>
#include <stream/follow.h>

#include "support.h"

using support::tcpPacket;
using support::udpPacket;

namespace {
    const std::string A = "0a000001", B = "0a000002";   // 10.0.0.1 and 10.0.0.2
    std::string seqHex(uint32_t v) { char b[16]; std::snprintf(b, sizeof b, "%08x", v); return b; }

    struct Loaded {
        std::string path;
        std::vector<packet::PacketInfo> packets;
        explicit Loaded(const std::vector<std::vector<char>> &frames) {
            path = support::writeTemp("stream_test.pcap", support::pcapBytes(frames));
            core::FileProcessor fp;
            std::string message;
            EXPECT_TRUE(fp.processPcapFile(path, packets, message)) << message;
        }
        ~Loaded() { std::remove(path.c_str()); }

        stream::Stream follow(uint32_t index) const {
            const auto indices = stream::conversationPackets(packets, index);
            stream::Stream s;
            EXPECT_TRUE(stream::reassemble(path, packets, indices, s));
            return s;
        }
    };

    std::string text(const stream::Stream &s, stream::Direction d) {
        std::string out;
        for (const auto &c: s.chunks) if (c.direction == d) out += c.data;
        return out;
    }

    // client = A:5000, server = B:80
    std::vector<char> c2s(uint32_t seq, const std::string &data, const std::string &flags = "18") { return tcpPacket(A, B, "1388", "0050", seqHex(seq), seqHex(9001), flags, data); }
    std::vector<char> s2c(uint32_t seq, const std::string &data, const std::string &flags = "18") { return tcpPacket(B, A, "0050", "1388", seqHex(seq), seqHex(1001), flags, data); }
} // namespace

TEST(Follow, InOrderConversationKeepsTheDirectionsApart) {
    Loaded cap({tcpPacket(A, B, "1388", "0050", seqHex(1000), "00000000", "02"),
                tcpPacket(B, A, "0050", "1388", seqHex(9000), seqHex(1001), "12"),
                tcpPacket(A, B, "1388", "0050", seqHex(1001), seqHex(9001), "10"),
                c2s(1001, "GET /index HTTP/1.1\r\n"),
                s2c(9001, "HTTP/1.1 200 OK\r\n"),
                c2s(1022, "Host: x\r\n\r\n"),
                s2c(9018, "bye")});
    const auto s = cap.follow(3);
    EXPECT_TRUE(s.tcp);
    EXPECT_EQ(s.addressA, "10.0.0.1");
    EXPECT_EQ(s.portA, 5000);
    EXPECT_EQ(s.addressB, "10.0.0.2");
    EXPECT_EQ(s.portB, 80);
    EXPECT_EQ(s.packets, 7);
    ASSERT_EQ(s.chunks.size(), 4u);
    EXPECT_EQ(s.chunks[0].direction, stream::Direction::AtoB);
    EXPECT_EQ(s.chunks[0].data, "GET /index HTTP/1.1\r\n");
    EXPECT_EQ(s.chunks[0].firstPacket, 4);
    EXPECT_EQ(s.chunks[1].data, "HTTP/1.1 200 OK\r\n");
    EXPECT_EQ(s.chunks[2].data, "Host: x\r\n\r\n");
    EXPECT_EQ(s.chunks[3].data, "bye");
    EXPECT_EQ(s.bytesAtoB, 21u + 11u);
    EXPECT_EQ(s.bytesBtoA, 17u + 3u);
    EXPECT_EQ(s.missingBytes, 0u);
    EXPECT_FALSE(s.truncated);
}

TEST(Follow, OutOfOrderSegmentsAreHeldBackAndRetransmissionsDropped) {
    Loaded cap({tcpPacket(A, B, "1388", "0050", seqHex(1000), "00000000", "02"),
                c2s(1001, "Hello "),          // 1001..1006
                c2s(1011, "Z!"),              // 1011..1012 arrives before the middle part
                c2s(1007, "abcd"),            // 1007..1010 fills the hole
                c2s(1001, "Hello "),          // retransmission
                c2s(1011, "Z!"),              // retransmission
                c2s(1013, "end")});
    const auto s = cap.follow(1);
    EXPECT_EQ(text(s, stream::Direction::AtoB), "Hello abcdZ!end");
    EXPECT_EQ(s.missingBytes, 0u);
}

TEST(Follow, OverlappingRetransmissionOnlyAddsTheNewBytes) {
    Loaded cap({tcpPacket(A, B, "1388", "0050", seqHex(1000), "00000000", "02"),
                c2s(1001, "abcdef"),
                c2s(1004, "defghi"),          // overlaps "def", adds "ghi"
                c2s(1010, "jkl")});
    EXPECT_EQ(text(cap.follow(1), stream::Direction::AtoB), "abcdefghijkl");
}

TEST(Follow, CapturedHolesAreReportedAsMissingBytes) {
    Loaded cap({tcpPacket(A, B, "1388", "0050", seqHex(1000), "00000000", "02"),
                c2s(1001, "first"),           // 1001..1005
                c2s(1010, "later"),           // 1006..1009 never captured
                s2c(9001, "reply")});
    const auto s = cap.follow(1);
    EXPECT_EQ(s.missingBytes, 4u);
    EXPECT_EQ(text(s, stream::Direction::AtoB), "firstlater");
    bool sawGap = false;
    for (const auto &c: s.chunks) if (c.missingBefore == 4) { sawGap = true; EXPECT_EQ(c.data, "later"); }
    EXPECT_TRUE(sawGap);
    EXPECT_EQ(text(s, stream::Direction::BtoA), "reply");
}

TEST(Follow, TheStreamStartsWhereTheCaptureStarts) {
    // mid-connection capture: no SYN, the first data segment defines the start
    Loaded cap({c2s(5000, "mid"), c2s(5003, "dle"), s2c(777, "pong")});
    const auto s = cap.follow(0);
    EXPECT_EQ(text(s, stream::Direction::AtoB), "middle");
    EXPECT_EQ(text(s, stream::Direction::BtoA), "pong");
}

TEST(Follow, OtherConnectionsAreNotMixedIn) {
    Loaded cap({c2s(1, "one"),
                tcpPacket(A, B, "1389", "0050", seqHex(1), seqHex(1), "18", "two"),            // other client port
                tcpPacket(A, "0a000003", "1388", "0050", seqHex(1), seqHex(1), "18", "three"), // other server
                udpPacket(A, B, "1388", "0050", "udp"),                                      // same ports, other protocol
                s2c(1, "back")});
    const auto s = cap.follow(0);
    EXPECT_EQ(s.packets, 2);
    EXPECT_EQ(text(s, stream::Direction::AtoB), "one");
    EXPECT_EQ(text(s, stream::Direction::BtoA), "back");
    EXPECT_EQ(stream::conversationPackets(cap.packets, 1), (std::vector<uint32_t>{1}));
    EXPECT_EQ(stream::conversationPackets(cap.packets, 4), (std::vector<uint32_t>{0, 4})) << "following from a reply packet finds the same conversation";
}

TEST(Follow, UdpDatagramsInArrivalOrder) {
    Loaded cap({udpPacket(A, B, "c350", "0035", "ping"), udpPacket(B, A, "0035", "c350", "pong"),
                udpPacket(A, B, "c350", "0035", "p1"), udpPacket(A, B, "c350", "0035", "p2")});
    const auto s = cap.follow(1);
    EXPECT_FALSE(s.tcp);
    ASSERT_EQ(s.chunks.size(), 3u) << "consecutive datagrams in one direction are merged";
    EXPECT_EQ(s.chunks[0].data, "ping");
    EXPECT_EQ(s.chunks[1].data, "pong");
    EXPECT_EQ(s.chunks[2].data, "p1p2");
}

TEST(Follow, NonStreamPacketsAndBadInput) {
    Loaded cap({support::hex(support::kArpRequest), c2s(1, "x")});
    EXPECT_TRUE(stream::conversationPackets(cap.packets, 0).empty()) << "ARP is not a stream";
    EXPECT_TRUE(stream::conversationPackets(cap.packets, 99).empty());

    stream::Stream out;
    EXPECT_TRUE(stream::reassemble(cap.path, cap.packets, {}, out));
    EXPECT_TRUE(out.chunks.empty());
    EXPECT_FALSE(stream::reassemble("/no/such/file.pcap", cap.packets, {1}, out));
    core::ScanControl control;
    control.cancelRequested = true;
    EXPECT_FALSE(stream::reassemble(cap.path, cap.packets, {1}, out, &control));
}

TEST(Follow, SizeLimitTruncates) {
    Loaded cap({c2s(1, "0123456789"), c2s(11, "abcdefghij"), s2c(1, "reply")});
    stream::Stream s;
    ASSERT_TRUE(stream::reassemble(cap.path, cap.packets, stream::conversationPackets(cap.packets, 0), s, nullptr, 15));
    EXPECT_TRUE(s.truncated);
    EXPECT_EQ(s.bytesAtoB + s.bytesBtoA, 15u);
    EXPECT_EQ(text(s, stream::Direction::AtoB), "0123456789abcde");
}

// Property: however the segments of a stream are reordered and duplicated, the original bytes come out
TEST(Follow, ReorderedAndDuplicatedSegmentsReassembleToTheOriginal) {
    std::mt19937 rng(2024);
    for (int round = 0; round < 40; ++round) {
        std::string original(rng() % 1500 + 1, '\0');
        for (auto &c: original) c = static_cast<char>('a' + rng() % 26);

        struct Seg { uint32_t seq; std::string data; };
        std::vector<Seg> segs;
        for (size_t pos = 0; pos < original.size();) {
            const size_t len = std::min<size_t>(rng() % 120 + 1, original.size() - pos);
            segs.push_back({static_cast<uint32_t>(1001 + pos), original.substr(pos, len)});
            pos += len;
        }
        std::vector<Seg> sent = segs;
        for (const auto &s: segs) if (rng() % 3 == 0) sent.push_back(s);   // retransmissions
        std::shuffle(sent.begin(), sent.end(), rng);

        std::vector<std::vector<char>> frames = {tcpPacket(A, B, "1388", "0050", seqHex(1000), "00000000", "02")};
        for (const auto &s: sent) frames.push_back(c2s(s.seq, s.data));
        Loaded cap(frames);
        const auto s = cap.follow(0);
        ASSERT_EQ(text(s, stream::Direction::AtoB), original) << "round " << round;
        EXPECT_EQ(s.missingBytes, 0u);
    }
}
