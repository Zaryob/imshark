// TCP message reassembly infrastructure: a test protocol with a 4 byte header ("TM" + 16-bit length) and one that runs
// until the connection closes are registered next to the built-in dissectors.
#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <random>

#include <core.h>
#include <filter/filter.h>

#include "support.h"

namespace {
    using dissect::StreamFrame;

    // "TM" + big endian body length + body
    StreamFrame frameTm(const char *d, size_t n) {
        if (n >= 1 && d[0] != 'T') return {StreamFrame::Kind::Reject, 0};
        if (n >= 2 && d[1] != 'M') return {StreamFrame::Kind::Reject, 0};
        if (n < 4) return {StreamFrame::Kind::NeedMore, 0};
        const size_t total = 4 + ((static_cast<size_t>(static_cast<uint8_t>(d[2])) << 8) | static_cast<uint8_t>(d[3]));
        if (n < total) return {StreamFrame::Kind::NeedMore, 0};
        return {StreamFrame::Kind::Complete, total};
    }

    // "UC" followed by data that ends when the sender closes
    StreamFrame frameUntilClose(const char *d, size_t n) {
        if (n >= 1 && d[0] != 'U') return {StreamFrame::Kind::Reject, 0};
        if (n >= 2 && d[1] != 'C') return {StreamFrame::Kind::Reject, 0};
        return n < 2 ? StreamFrame{StreamFrame::Kind::NeedMore, 0} : StreamFrame{StreamFrame::Kind::UntilClose, 0};
    }

    void describe(const char *name, dissect::Context &ctx, const char *d, size_t n, size_t headerLen) {
        ctx.pack.protocol = name;
        ctx.pack.info = std::string(name) + ": " + std::string(d + headerLen, n - headerLen);
        ctx.addLayer(name, ctx.offsetOf(d), n);
    }

    const dissect::Registry &testRegistry() {
        static const dissect::Registry registry = [] {
            dissect::Registry r = dissect::Registry::builtin();
            r.registerTcpStream(9000, {"TM", frameTm, [](dissect::Context &c, const char *d, size_t n) { describe("TESTMSG", c, d, n, 4); }});
            r.registerTcpStream(9001, {"UC", frameUntilClose, [](dissect::Context &c, const char *d, size_t n) { describe("UNTILCLOSE", c, d, n, 2); }});
            return r;
        }();
        return registry;
    }

    std::string makeTm(const std::string &body) {
        std::string m = "TM";
        m += static_cast<char>(body.size() >> 8);
        m += static_cast<char>(body.size() & 0xff);
        return m + body;
    }

    std::string seqHex(uint32_t v) { char b[16]; std::snprintf(b, sizeof b, "%08x", v); return b; }

    // client 10.0.0.1:50000 -> server 10.0.0.2:<port>
    std::vector<char> seg(uint32_t seq, const std::string &data, const char *port = "2328", const char *flags = "18") {
        return support::tcpPacket("0a000001", "0a000002", "c350", port, seqHex(seq), "00000001", flags, data);
    }
    std::vector<char> reply(uint32_t seq, const std::string &data, const char *port = "2328") {
        return support::tcpPacket("0a000002", "0a000001", port, "c350", seqHex(seq), "00000001", "18", data);
    }

    struct Capture {
        std::string path;
        std::vector<packet::PacketInfo> packets;
        core::FileProcessor fp{testRegistry()};
        std::string message;
        explicit Capture(const std::vector<std::vector<char>> &frames) {
            path = support::writeTemp("tcpreasm.pcap", support::pcapBytes(frames));
            EXPECT_TRUE(fp.processPcapFile(path, packets, message)) << message;
        }
        ~Capture() { std::remove(path.c_str()); }

        packet::PacketInfo details(size_t i) {
            packet::PacketInfo d;
            EXPECT_TRUE(core::buildPacketDetails(path, packets[i], d, &packets, &fp.captureInfo(), &testRegistry()));
            return d;
        }
    };

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto r = find(f.children, prefix)) return r;
        }
        return nullptr;
    }

    // SYN (seq 999 -> data starts at relative 1) so that every test starts from a known place
    std::vector<char> syn(const char *port = "2328") {
        return support::tcpPacket("0a000001", "0a000002", "c350", port, seqHex(999), "00000000", "02");
    }
}

TEST(TcpReassembly, AMessageSplitOverThreeSegments) {
    const std::string msg = makeTm("hello reassembled world");     // 4 + 23 = 27 bytes
    Capture cap({syn(), seg(1000, msg.substr(0, 10)), seg(1010, msg.substr(10, 10)), seg(1020, msg.substr(20))});
    ASSERT_EQ(cap.packets.size(), 4u);
    EXPECT_EQ(cap.packets[1].protocol, "TCP");
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 1);
    EXPECT_EQ(cap.packets[1].tcp_reassembled_in, 4u);
    EXPECT_NE(cap.packets[1].info.find("[TCP segment of a reassembled PDU] [Reassembled in #4]"), std::string::npos) << cap.packets[1].info;
    EXPECT_EQ(cap.packets[2].tcp_pdu_state, 1);
    const auto &last = cap.packets[3];
    EXPECT_EQ(last.protocol, "TESTMSG");
    EXPECT_EQ(last.info, "TESTMSG: hello reassembled world");
    EXPECT_EQ(last.tcp_pdu_state, 2);
    EXPECT_EQ(last.tcp_pdu_len, msg.size());
    EXPECT_EQ(last.tcp_pdu_start, 1u);
    EXPECT_EQ(cap.packets[0].tcp_pdu_state, 0) << "the SYN is not part of any message";

    EXPECT_TRUE(filter::Filter::compile("tcp.segment && tcp.reassembled_in == 4").filter.matches(cap.packets[1]));
    EXPECT_TRUE(filter::Filter::compile("tcp.reassembled && tcp.reassembled.length == 27").filter.matches(last));
    EXPECT_TRUE(filter::Filter::compile("!tcp.segment && !tcp.reassembled").filter.matches(cap.packets[0]));
}

TEST(TcpReassembly, DetailsOfTheCompletingPacketAreRebuiltFromTheFile) {
    const std::string msg = makeTm("rebuilt from the capture file");
    Capture cap({syn(), seg(1000, msg.substr(0, 9)), seg(1009, msg.substr(9, 9)), seg(1018, msg.substr(18))});
    const auto d = cap.details(3);
    EXPECT_EQ(d.protocol, "TESTMSG");
    EXPECT_EQ(d.info, cap.packets[3].info);
    const auto *layer = find(d.fields, "[Reassembled TCP (33 bytes) from frames #2, #3, #4]");
    ASSERT_NE(layer, nullptr);
    EXPECT_EQ(layer->length, 0u) << "nothing in this frame to highlight";
    EXPECT_NE(find(layer->children, "TESTMSG"), nullptr);

    const auto first = cap.details(1);
    EXPECT_EQ(first.info, cap.packets[1].info) << "segments show the same text when rebuilt";
    EXPECT_NE(find(first.fields, "[TCP segment of a reassembled PDU]"), nullptr);
}

TEST(TcpReassembly, OutOfOrderRetransmittedAndOverlappingSegments) {
    const std::string msg = makeTm(std::string(40, 'x') + "END");   // 47 bytes
    // arrival: part 2 first (a hole), then part 1 fills it, a retransmission of part 1, then the tail with an overlap
    Capture cap({syn(), seg(1020, msg.substr(20, 14)), seg(1000, msg.substr(0, 20)), seg(1000, msg.substr(0, 20)), seg(1030, msg.substr(30))});
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 1) << "held back until the hole is filled";
    EXPECT_EQ(cap.packets[2].tcp_pdu_state, 1);
    EXPECT_EQ(cap.packets[3].tcp_pdu_state, 0) << "a pure retransmission adds nothing and is decoded on its own";
    EXPECT_EQ(cap.packets[4].tcp_pdu_state, 2);
    EXPECT_EQ(cap.packets[4].protocol, "TESTMSG");
    EXPECT_EQ(cap.packets[4].info.substr(0, 20), "TESTMSG: xxxxxxxxxxx");
    EXPECT_EQ(cap.packets[1].tcp_reassembled_in, 5u);
    EXPECT_EQ(cap.packets[2].tcp_reassembled_in, 5u);
    const auto d = cap.details(4);
    EXPECT_NE(find(d.fields, "[Reassembled TCP (47 bytes) from frames #2, #3, #5]"), nullptr) << "the retransmission contributed nothing";
    EXPECT_EQ(d.info, cap.packets[4].info);
}

TEST(TcpReassembly, SeveralMessagesInOneStreamAndPipelining) {
    const std::string a = makeTm("first message"), b = makeTm("second"), c = makeTm("third one here");
    // a is split, the tail of a shares a segment with all of b, c is split again
    const std::string joined = a + b + c;
    Capture cap({syn(), seg(1000, joined.substr(0, 8)), seg(1008, joined.substr(8, a.size() - 8 + b.size())),
                 seg(1000 + a.size() + b.size(), c.substr(0, 5)), seg(1000 + a.size() + b.size() + 5, c.substr(5))});
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 1);
    EXPECT_EQ(cap.packets[2].tcp_pdu_state, 2) << "completes the first message (the second one fits behind it)";
    EXPECT_EQ(cap.packets[2].info, "TESTMSG: first message");
    EXPECT_EQ(cap.packets[3].tcp_pdu_state, 1) << "starts the third message";
    EXPECT_EQ(cap.packets[4].tcp_pdu_state, 2);
    EXPECT_EQ(cap.packets[4].info, "TESTMSG: third one here");
    EXPECT_EQ(cap.packets[3].tcp_reassembled_in, 5u);
}

TEST(TcpReassembly, AMessageThatFitsOneSegmentIsDecodedAsBefore) {
    const std::string msg = makeTm("short");
    Capture cap({syn(), seg(1000, msg)});
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 3) << "no reassembly involved";
    EXPECT_EQ(cap.packets[1].protocol, "TESTMSG") << "wholly inside the segment: still decoded by the stream protocol";
    EXPECT_EQ(cap.packets[1].info, "TESTMSG: short");
    const auto d = cap.details(1);
    EXPECT_EQ(d.info, cap.packets[1].info);
    EXPECT_EQ(find(d.fields, "[Reassembled"), nullptr);
    const auto *layer = find(d.fields, "TESTMSG");
    ASSERT_NE(layer, nullptr);
    EXPECT_EQ(layer->offset, 14u + 20u + 20u) << "the fields point at the real bytes of the frame";
    EXPECT_FALSE(filter::Filter::compile("tcp.reassembled || tcp.segment").filter.matches(cap.packets[1]));
}

TEST(TcpReassembly, DirectionsAndConnectionsAreIndependent) {
    const std::string a = makeTm("client says hello"), b = makeTm("server answers");
    Capture cap({syn(), seg(1000, a.substr(0, 6)),
                 reply(5000, b.substr(0, 7)),                       // the server's own stream, own sequence space
                 seg(1006, a.substr(6)),
                 reply(5007, b.substr(7)),
                 // a second connection (another client port) interleaved
                 support::tcpPacket("0a000001", "0a000002", "c351", "2328", seqHex(1000), "00000001", "18", a.substr(0, 4)),
                 support::tcpPacket("0a000001", "0a000002", "c351", "2328", seqHex(1004), "00000001", "18", a.substr(4))});
    EXPECT_EQ(cap.packets[3].info, "TESTMSG: client says hello");
    EXPECT_EQ(cap.packets[4].info, "TESTMSG: server answers");
    EXPECT_EQ(cap.packets[6].info, "TESTMSG: client says hello") << "the second connection reassembles its own message";
    EXPECT_EQ(cap.packets[1].tcp_reassembled_in, 4u);
    EXPECT_EQ(cap.packets[2].tcp_reassembled_in, 5u);
    EXPECT_EQ(cap.packets[5].tcp_reassembled_in, 7u);
}

TEST(TcpReassembly, ANonMatchingStreamIsLeftAlone) {
    Capture cap({syn(), seg(1000, "GARBAGE that is not a TM message"), seg(1100, "more garbage")});
    for (size_t i = 1; i < 3; ++i) {
        EXPECT_EQ(cap.packets[i].tcp_pdu_state, 0) << i;
        EXPECT_EQ(cap.packets[i].protocol, "TCP");
    }
}

TEST(TcpReassembly, MessagesThatRunUntilTheConnectionCloses) {
    Capture cap({syn("2329"), seg(1000, "UC first part ", "2329"), seg(1014, "second part ", "2329"), seg(1026, "and the end", "2329"),
                 seg(1037, "", "2329", "11")});                       // FIN + ACK
    for (size_t i = 1; i <= 3; ++i) EXPECT_EQ(cap.packets[i].tcp_pdu_state, 1) << i;
    EXPECT_EQ(cap.packets[3].tcp_reassembled_in, 5u);
    const auto &fin = cap.packets[4];
    EXPECT_EQ(fin.tcp_pdu_state, 2) << "the FIN completes it, although it carries no data";
    EXPECT_EQ(fin.protocol, "UNTILCLOSE");
    EXPECT_EQ(fin.info, "UNTILCLOSE:  first part second part and the end");
    const auto d = cap.details(4);
    EXPECT_EQ(d.info, fin.info);
    EXPECT_NE(find(d.fields, "[Reassembled TCP (37 bytes) from frames #2, #3, #4]"), nullptr);
}

TEST(TcpReassembly, AClosedConnectionForgetsAnIncompleteMessage) {
    const std::string msg = makeTm("never completed");
    Capture cap({syn(), seg(1000, msg.substr(0, 8)), seg(1008, "", "2328", "11"),     // FIN with half a message
                 syn(), seg(1000, makeTm("fresh start"))});                                // the port is reused
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 1);
    EXPECT_EQ(cap.packets[1].tcp_reassembled_in, 0u) << "it never completed";
    EXPECT_EQ(cap.packets[2].tcp_pdu_state, 0) << "a bare FIN is not a segment of anything";
    EXPECT_EQ(cap.packets[4].tcp_pdu_state, 3);
    EXPECT_EQ(cap.packets[4].info, "TESTMSG: fresh start") << "the leftovers of the old connection did not leak into the new one";
}

TEST(TcpReassembly, AHoleThatNeverFillsIsGivenUp) {
    const std::string big(2 * 1024 * 1024, 'a');                  // more out-of-order data than the window allows
    std::vector<std::vector<char>> frames = {syn(), seg(1000, makeTm("head").substr(0, 3))};      // 3 bytes: the message start
    frames.push_back(seg(1000 + 5000, big.substr(0, 1400)));      // far ahead: a hole of ~5000 bytes
    for (int i = 0; i < 800; ++i) frames.push_back(seg(1000 + 5000 + 1400 * (i + 1), big.substr(0, 1400)));   // > kMaxPending
    frames.push_back(seg(1000 + 5000 + 1400 * 801, makeTm("after the loss")));
    Capture cap(frames);
    EXPECT_EQ(cap.packets.back().protocol, "TESTMSG") << "after giving the hole up, the stream resynchronises at the next segment";
    EXPECT_EQ(cap.packets.back().info, "TESTMSG: after the loss");
}

TEST(TcpReassembly, IncompleteDirectionsAreBoundedInMemory) {
    dissect::TcpStreams streams;
    auto select = [](const char *, size_t) -> const dissect::StreamProtocol * { return nullptr; };
    for (uint32_t i = 0; i < dissect::TcpStreams::kMaxDirections + 50; ++i) {
        streams.feed("key" + std::to_string(i), i, 0, "x", 1, false, false, select);
    }
    EXPECT_LE(streams.directions(), dissect::TcpStreams::kMaxDirections);
}

// Property: however a stream of messages is cut into segments and delivered (reordered, duplicated), every message is
// found exactly once with the right bytes, and rebuilding the completing packet from the file agrees with the loading pass.
TEST(TcpReassembly, RandomCuttingReorderingAndDuplicationFindsEveryMessage) {
    std::mt19937 rng(321);
    for (int round = 0; round < 40; ++round) {
        std::vector<std::string> messages;
        std::string stream;
        for (int i = 0, n = 1 + static_cast<int>(rng() % 5); i < n; ++i) {
            std::string body(1 + rng() % 300, 'a');
            for (auto &c: body) c = static_cast<char>('a' + rng() % 26);
            messages.push_back(body);
            stream += makeTm(body);
        }
        struct Seg { uint32_t seq; std::string data; };
        std::vector<Seg> segs;
        for (size_t pos = 0; pos < stream.size();) {
            const size_t n = std::min<size_t>(1 + rng() % 120, stream.size() - pos);
            segs.push_back({static_cast<uint32_t>(1000 + pos), stream.substr(pos, n)});
            pos += n;
        }
        std::vector<Seg> sent = segs;
        for (const auto &s: segs) if (rng() % 4 == 0) sent.push_back(s);          // retransmissions
        // reorder only inside a small window, like real networks do
        for (size_t i = 0; i + 1 < sent.size(); ++i) if (rng() % 3 == 0) std::swap(sent[i], sent[i + 1]);

        std::vector<std::vector<char>> frames = {syn()};
        for (const auto &s: sent) frames.push_back(seg(s.seq, s.data));
        Capture cap(frames);

        std::vector<std::string> found;
        for (size_t i = 0; i < cap.packets.size(); ++i) {
            const auto &p = cap.packets[i];
            if (p.protocol == "TESTMSG") {
                found.push_back(p.info.substr(9));
                const auto d = cap.details(i);                                   // rebuilding agrees with the loading pass
                ASSERT_EQ(d.info, p.info) << "round " << round << " packet " << i + 1;
                ASSERT_EQ(d.protocol, p.protocol);
            }
        }
        size_t expectedViaStream = 0;
        for (const auto &p: cap.packets) expectedViaStream += p.tcp_pdu_state >= 2;
        EXPECT_EQ(found.size(), expectedViaStream) << "round " << round;
        EXPECT_LE(found.size(), messages.size());
        for (const auto &f: found) EXPECT_NE(std::find(messages.begin(), messages.end(), f), messages.end()) << "round " << round << ": a message that was never sent";
    }
}

TEST(TcpReassembly, RandomCorruptionNeverCrashes) {
    std::mt19937 rng(77);
    const std::string msg = makeTm("a message that will be damaged in many ways");
    for (int round = 0; round < 1500; ++round) {
        packet::PacketParser parser(testRegistry());
        for (int i = 0; i < 5; ++i) {
            std::string data = msg.substr(rng() % msg.size());
            data.resize(rng() % (data.size() + 1));
            for (unsigned k = rng() % 3; k > 0 && !data.empty(); --k) data[rng() % data.size()] = static_cast<char>(rng());
            auto frame = seg(static_cast<uint32_t>(1000 + rng() % 200), data, "2328", (rng() % 5 == 0) ? "11" : (rng() % 7 == 0 ? "04" : "18"));
            if (rng() % 9 == 0) frame.resize(rng() % (frame.size() + 1));
            packet::PacketInfo p(i + 1);
            parser.parsePacket(p, frame, (round % 2) ? dissect::ParseMode::Full : dissect::ParseMode::Summary);
        }
    }
}
