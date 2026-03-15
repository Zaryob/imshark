// TCP message reassembly infrastructure: a test protocol with a 4 byte header ("TM" + 16-bit length) and one that runs
// until the connection closes are registered next to the built-in dissectors.
#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <random>

#include <core.h>
#include <dissect/x509.h>
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
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 4);
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
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 4);
    EXPECT_EQ(cap.packets[2].tcp_pdu_state, 2) << "completes the first message (the second one fits behind it)";
    EXPECT_EQ(cap.packets[2].info, "TESTMSG: first message, TESTMSG: second") << "the whole message that follows in the segment is decoded as well";
    EXPECT_EQ(cap.packets[3].tcp_pdu_state, 4) << "starts the third message";
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
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 4);
    for (size_t i = 2; i <= 3; ++i) EXPECT_EQ(cap.packets[i].tcp_pdu_state, 1) << i;
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
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 4);
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
    auto select = [](const char *, size_t, uint32_t) -> const dissect::StreamProtocol * { return nullptr; };
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
                std::string rest = p.info.substr(9);
                for (size_t cut; (cut = rest.find(", TESTMSG: ")) != std::string::npos;) {
                    found.push_back(rest.substr(0, cut));
                    rest = rest.substr(cut + 11);
                }
                found.push_back(rest);
                const auto d = cap.details(i);                                   // rebuilding agrees with the loading pass
                ASSERT_EQ(d.info, p.info) << "round " << round << " packet " << i + 1;
                ASSERT_EQ(d.protocol, p.protocol);
            }
        }
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

namespace {
    // a DNS query for "a.test" A, with the 2-byte TCP length prefix
    std::string dnsQuery(uint16_t id, const std::string &label = "a") {
        std::string m;
        m += static_cast<char>(id >> 8); m += static_cast<char>(id & 0xff);
        m += std::string("\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00", 10);
        m += static_cast<char>(label.size()) + label + "\x04test" + std::string("\x00\x00\x01\x00\x01", 5);
        std::string out;
        out += static_cast<char>(m.size() >> 8); out += static_cast<char>(m.size() & 0xff);
        return out + m;
    }
    const dissect::Registry &builtin() { return dissect::Registry::builtin(); }
}

TEST(DnsOverTcp, MessageSplitAfterTheLengthPrefixIsReassembled) {
    const std::string q = dnsQuery(0x1234);
    core::FileProcessor fp(builtin());
    std::vector<packet::PacketInfo> packets;
    std::string msg;
    const std::string path = support::writeTemp("dnstcp1.pcap", support::pcapBytes({syn("0035"), seg(1000, q.substr(0, 2), "0035"), seg(1002, q.substr(2, 7), "0035"), seg(1009, q.substr(9), "0035")}));
    ASSERT_TRUE(fp.processPcapFile(path, packets, msg)) << msg;
    EXPECT_EQ(packets[1].tcp_pdu_state, 4);
    EXPECT_EQ(packets[3].protocol, "DNS");
    EXPECT_NE(packets[3].info.find("Standard query 0x1234 A a.test"), std::string::npos) << packets[3].info;
    packet::PacketInfo d;
    ASSERT_TRUE(core::buildPacketDetails(path, packets[3], d, &packets, &fp.captureInfo(), &builtin()));
    EXPECT_EQ(d.info, packets[3].info);
    std::remove(path.c_str());
}

TEST(DnsOverTcp, SeveralMessagesInOneSegmentAreAllDecoded) {
    const std::string joined = dnsQuery(1, "a") + dnsQuery(2, "b") + dnsQuery(3, "c");
    core::FileProcessor fp(builtin());
    std::vector<packet::PacketInfo> packets;
    std::string msg;
    const std::string path = support::writeTemp("dnstcp2.pcap", support::pcapBytes({syn("0035"), seg(1000, joined, "0035")}));
    ASSERT_TRUE(fp.processPcapFile(path, packets, msg)) << msg;
    const auto &p = packets[1];
    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_NE(p.info.find("0x1 A a.test"), std::string::npos) << p.info;
    EXPECT_NE(p.info.find("0x2 A b.test"), std::string::npos) << p.info;
    EXPECT_NE(p.info.find("0x3 A c.test"), std::string::npos) << p.info;
    packet::PacketInfo d;
    ASSERT_TRUE(core::buildPacketDetails(path, p, d, &packets, &fp.captureInfo(), &builtin()));
    EXPECT_EQ(d.info, p.info) << "details agree with the loading pass";
    std::remove(path.c_str());
}

TEST(DnsOverTcp, TheTailOfOneMessageAndWholeNextOnesShareASegment) {
    const std::string a = dnsQuery(1, "a"), b = dnsQuery(2, "b"), c = dnsQuery(3, "c");
    const std::string all = a + b + c;
    core::FileProcessor fp(builtin());
    std::vector<packet::PacketInfo> packets;
    std::string msg;
    const std::string path = support::writeTemp("dnstcp3.pcap", support::pcapBytes({syn("0035"), seg(1000, all.substr(0, 10), "0035"), seg(1010, all.substr(10), "0035")}));
    ASSERT_TRUE(fp.processPcapFile(path, packets, msg)) << msg;
    const auto &p = packets[2];
    EXPECT_EQ(p.tcp_pdu_state, 2);
    EXPECT_NE(p.info.find("0x1 A a"), std::string::npos) << p.info;
    EXPECT_NE(p.info.find("0x3 A c"), std::string::npos) << p.info;
    packet::PacketInfo d;
    ASSERT_TRUE(core::buildPacketDetails(path, p, d, &packets, &fp.captureInfo(), &builtin()));
    EXPECT_EQ(d.info, p.info);
    std::remove(path.c_str());
}

namespace {
    // client -> server on port 80 ("0050"), server -> client replies
    std::vector<char> toServer(uint32_t seq, const std::string &data) { return seg(seq, data, "0050"); }
    std::vector<char> fromServer(uint32_t seq, const std::string &data) { return reply(seq, data, "0050"); }
    std::vector<char> fromServer443(uint32_t seq, const std::string &data) { return reply(seq, data, "01bb"); }

    struct HttpCapture {
        std::string path;
        std::vector<packet::PacketInfo> packets;
        core::FileProcessor fp{builtin()};
        explicit HttpCapture(const std::vector<std::vector<char>> &frames) {
            std::string message;
            path = support::writeTemp("httpstream.pcap", support::pcapBytes(frames));
            EXPECT_TRUE(fp.processPcapFile(path, packets, message)) << message;
        }
        ~HttpCapture() { std::remove(path.c_str()); }
        packet::PacketInfo details(size_t i) {
            packet::PacketInfo d;
            EXPECT_TRUE(core::buildPacketDetails(path, packets[i], d, &packets, &fp.captureInfo(), &builtin()));
            return d;
        }
    };

    std::string readFixture(const char *name) {
        std::ifstream f(std::string(IMSHARK_TEST_DATA_DIR) + "/gzip/" + name, std::ios::binary);
        return std::string(std::istreambuf_iterator<char>(f), {});
    }
}

TEST(HttpStream, ResponseWithContentLengthSplitOverSegments) {
    const std::string body(3000, 'b');
    const std::string resp = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 3000\r\n\r\n" + body;
    HttpCapture cap({syn("0050"), fromServer(1000, resp.substr(0, 1400)), fromServer(2400, resp.substr(1400, 1400)), fromServer(3800, resp.substr(2800))});
    // the SYN is on the client direction; the server side starts at its own sequence number
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 4);
    EXPECT_EQ(cap.packets[3].tcp_pdu_state, 2);
    EXPECT_EQ(cap.packets[3].protocol, "HTTP");
    EXPECT_EQ(cap.packets[3].info, "HTTP/1.1 200 OK (text/plain)");
    const auto d = cap.details(3);
    EXPECT_EQ(d.info, cap.packets[3].info);
    EXPECT_NE(find(d.fields, "File Data: 3000 bytes"), nullptr);
    EXPECT_TRUE(filter::Filter::compile("http.response.code == 200 && tcp.reassembled").filter.matches(cap.packets[3]));
}

TEST(HttpStream, PipelinedRequestsAreAllShown) {
    const std::string reqs = "GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n";
    HttpCapture cap({syn("0050"), toServer(1000, reqs)});
    EXPECT_EQ(cap.packets[1].protocol, "HTTP");
    EXPECT_EQ(cap.packets[1].info, "GET /a HTTP/1.1, GET /b HTTP/1.1");
    EXPECT_EQ(cap.packets[1].app_text2, "/a") << "the filter facts are the first message's";
    EXPECT_EQ(cap.details(1).info, cap.packets[1].info);
}

TEST(HttpStream, ChunkedBodyIsFramedAndDechunked) {
    const std::string resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    HttpCapture cap({syn("0050"), fromServer(1000, resp.substr(0, 60)), fromServer(1060, resp.substr(60))});
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 4);
    EXPECT_EQ(cap.packets[2].tcp_pdu_state, 2);
    const auto d = cap.details(2);
    EXPECT_NE(find(d.fields, "De-chunked entity body (11 bytes)"), nullptr);
}

TEST(HttpStream, GzipBodyIsInflated) {
    const std::string gz = readFixture("hello.gz");
    ASSERT_FALSE(gz.empty());
    const std::string resp = "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: " + std::to_string(gz.size()) + "\r\n\r\n" + gz;
    HttpCapture cap({syn("0050"), fromServer(1000, resp.substr(0, 70)), fromServer(1070, resp.substr(70))});
    const auto d = cap.details(2);
    EXPECT_NE(find(d.fields, "Content-encoded entity body (gzip): " + std::to_string(gz.size()) + " bytes -> 12 bytes"), nullptr);

    std::string bad = resp;
    bad[bad.size() - 12] ^= 0x7f;
    HttpCapture cap2({syn("0050"), fromServer(1000, bad)});
    EXPECT_NE(find(cap2.details(1).fields, "[Could not decompress the gzip body"), nullptr);
}

TEST(HttpStream, ResponseWithoutLengthShowsItsHeadersAndTheBodyFollowsAsSegments) {
    HttpCapture cap({syn("0050"), fromServer(1000, "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html>"), fromServer(1051, "</html>")});
    EXPECT_EQ(cap.packets[1].info, "HTTP/1.0 200 OK (text/html)");
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 3);
    EXPECT_EQ(cap.packets[2].protocol, "TCP");
}

TEST(HttpStream, FirstSegmentOfAMessageIsDecodedAsFarAsItGoes) {
    const std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: 3000\r\nContent-Type: text/plain\r\n\r\n" + std::string(3000, 'z');
    HttpCapture cap({syn("0050"), fromServer(1000, resp.substr(0, 100)), fromServer(1100, resp.substr(100))});
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 4);
    EXPECT_EQ(cap.packets[1].protocol, "HTTP");
    EXPECT_EQ(cap.packets[1].info, "HTTP/1.1 200 OK (text/plain) [TCP segment of a reassembled PDU] [Reassembled in #3]");
    EXPECT_EQ(cap.details(1).info, cap.packets[1].info);
    EXPECT_TRUE(filter::Filter::compile("tcp.segment && http").filter.matches(cap.packets[1]));
}

TEST(HttpStream, ResponseToHeadAndBodylessStatusesDoNotSwallowTheNextMessage) {
    const std::string head = "HTTP/1.1 200 OK\r\nContent-Length: 5000\r\n\r\n";            // reply to HEAD: announces, sends nothing
    const std::string next = "HTTP/1.1 304 Not Modified\r\nETag: x\r\n\r\n";
    HttpCapture cap({syn("0050"), fromServer(1000, head + next)});
    EXPECT_EQ(cap.packets[1].info.rfind("HTTP/1.1 200 OK", 0), 0u) << cap.packets[1].info;
    EXPECT_NE(cap.packets[1].info.find("HTTP/1.1 304 Not Modified"), std::string::npos) << cap.packets[1].info;
}

TEST(HttpStream, NonHttpAndUpgradedStreamsAreLeftAlone) {
    HttpCapture cap({syn("0050"), fromServer(1000, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\x81\x05hello"), fromServer(1048, std::string("\x81\x05world", 7))});
    EXPECT_EQ(cap.packets[1].protocol, "HTTP");
    EXPECT_EQ(cap.packets[2].protocol, "TCP") << "WebSocket frames are not HTTP";
    EXPECT_EQ(cap.packets[2].tcp_pdu_state, 0);

    HttpCapture junk({syn("0050"), fromServer(1000, "GET but not really\x01 http"), fromServer(1030, "more")});
    EXPECT_EQ(junk.packets[1].tcp_pdu_state, 0);
    EXPECT_EQ(junk.packets[2].tcp_pdu_state, 0);
}

TEST(HttpStream, HugeBodiesDoNotBufferTheWholeMessage) {
    HttpCapture cap({syn("0050"), fromServer(1000, "HTTP/1.1 200 OK\r\nContent-Length: 1000000000\r\n\r\nstart of a very large body")});
    EXPECT_EQ(cap.packets[1].protocol, "HTTP") << "the headers are shown at once";
    EXPECT_EQ(cap.packets[1].tcp_pdu_state, 3);
}

TEST(HttpStream, MalformedLengthsAndChunksAreRejectedNotTrusted) {
    HttpCapture cap({syn("0050"), fromServer(1000, "HTTP/1.1 200 OK\r\nContent-Length: 12x\r\n\r\nabc"),
                     fromServer(1100, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nZZ\r\nabc")});
    for (size_t i = 1; i < 3; ++i) EXPECT_EQ(cap.packets[i].tcp_pdu_state, 0) << i;
}

TEST(HttpStream, RandomSegmentationNeverChangesTheDecodedMessages) {
    std::mt19937 rng(9);
    const std::string body(2500, 'x');
    const std::string stream = "HTTP/1.1 200 OK\r\nContent-Length: 2500\r\n\r\n" + body + "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
    for (int round = 0; round < 40; ++round) {
        std::vector<std::vector<char>> frames = {syn("0050")};
        for (size_t pos = 0; pos < stream.size();) {
            const size_t n = std::min<size_t>(1 + rng() % 900, stream.size() - pos);
            frames.push_back(fromServer(static_cast<uint32_t>(1000 + pos), stream.substr(pos, n)));
            pos += n;
        }
        HttpCapture cap(frames);
        std::string all;
        for (const auto &p: cap.packets) if (p.protocol == "HTTP") all += p.info + "|";
        EXPECT_NE(all.find("HTTP/1.1 200 OK"), std::string::npos) << round << ": " << all;
        EXPECT_NE(all.find("HTTP/1.1 404 Not Found"), std::string::npos) << round << ": " << all;
        for (size_t i = 0; i < cap.packets.size(); ++i) {
            if (cap.packets[i].protocol == "HTTP") ASSERT_EQ(cap.details(i).info, cap.packets[i].info) << round << " #" << i + 1;
        }
    }
}

// ---- TLS -----------------------------------------------------------------------------------------------------------
namespace {
    std::string der(unsigned tag, const std::string &body) {
        std::string out(1, static_cast<char>(tag));
        if (body.size() < 128) out += static_cast<char>(body.size());
        else if (body.size() < 256) { out += static_cast<char>(0x81); out += static_cast<char>(body.size()); }
        else { out += static_cast<char>(0x82); out += static_cast<char>(body.size() >> 8); out += static_cast<char>(body.size() & 0xff); }
        return out + body;
    }
    std::string rdn(const std::string &oidTail, const std::string &value) {
        return der(0x31, der(0x30, der(0x06, std::string("\x55\x04", 2) + oidTail) + der(0x13, value)));
    }

    // a structurally valid certificate (the signature is not checked by the dissector)
    std::string certificate(const std::string &cn, const std::vector<std::string> &sans, size_t padding = 0) {
        const std::string name = der(0x30, rdn(std::string("\x06", 1), "US") + rdn(std::string("\x0a", 1), "Example Org") + rdn(std::string("\x03", 1), cn));
        const std::string issuer = der(0x30, rdn(std::string("\x03", 1), "Example CA"));
        std::string general;
        for (const auto &s: sans) general += der(0x82, s);
        const std::string san = der(0x30, der(0x06, std::string("\x55\x1d\x11", 3)) + der(0x04, der(0x30, general)));
        const std::string tbs = der(0x30, der(0xa0, der(0x02, "\x02")) + der(0x02, std::string("\x01\x23\x45", 3)) + der(0x30, der(0x06, "\x2a")) + issuer +
                                              der(0x30, der(0x17, "260102030405Z") + der(0x17, "270102030405Z")) + name + der(0x30, der(0x30, der(0x06, "\x2a")) + der(0x03, std::string("\x00\x01", 2))) +
                                              der(0xa3, der(0x30, san)) + (padding ? der(0x04, std::string(padding, 'p')) : ""));
        return der(0x30, tbs + der(0x30, der(0x06, "\x2a")) + der(0x03, std::string("\x00\x01", 2)));
    }

    std::string be24(size_t v) { return std::string{char(v >> 16), char((v >> 8) & 0xff), char(v & 0xff)}; }
    std::string tlsRecord(unsigned type, const std::string &body) {
        return std::string{char(type), 3, 3, char(body.size() >> 8), char(body.size() & 0xff)} + body;
    }
    // a Certificate handshake message (TLS 1.2 layout) with the given chain
    std::string certificateMessage(const std::vector<std::string> &chain) {
        std::string list;
        for (const auto &c: chain) list += be24(c.size()) + c;
        const std::string body = be24(list.size()) + list;
        return std::string{char(11)} + be24(body.size()) + body;
    }
}

TEST(TlsStream, CertificateSpanningRecordsAndSegmentsIsReassembled) {
    const std::string leaf = certificate("www.example.org", {"www.example.org", "example.org"}, 17000);   // > one record with the chain
    const std::string message = certificateMessage({leaf, certificate("Example CA", {})});
    ASSERT_GT(message.size(), 16384u) << "the message must need two records";
    const std::string records = tlsRecord(22, message.substr(0, 16000)) + tlsRecord(22, message.substr(16000));
    std::vector<std::vector<char>> frames = {syn("01bb")};
    uint32_t seq = 1000;
    for (size_t pos = 0; pos < records.size(); pos += 1400) {
        frames.push_back(fromServer443(seq, records.substr(pos, 1400)));
        seq += static_cast<uint32_t>(std::min<size_t>(1400, records.size() - pos));
    }
    core::FileProcessor fp(builtin());
    std::vector<packet::PacketInfo> packets;
    std::string msg;
    const std::string path = support::writeTemp("tlsstream.pcap", support::pcapBytes(frames));
    ASSERT_TRUE(fp.processPcapFile(path, packets, msg)) << msg;
    const auto &last = packets.back();
    EXPECT_EQ(last.protocol, "TLS");
    EXPECT_EQ(last.tcp_pdu_state, 2);
    EXPECT_EQ(last.info, "Certificate");
    EXPECT_EQ(last.app_text2, "www.example.org");
    EXPECT_TRUE(filter::Filter::compile("tls.handshake.certificate_subject == \"www.example.org\" && tls.handshake.type == 11").filter.matches(last));
    EXPECT_EQ(packets[1].tcp_pdu_state, 4);
    EXPECT_EQ(packets[1].protocol, "TLS");

    packet::PacketInfo d;
    ASSERT_TRUE(core::buildPacketDetails(path, last, d, &packets, &fp.captureInfo(), &builtin()));
    EXPECT_EQ(d.info, last.info);
    EXPECT_NE(find(d.fields, "Certificate: www.example.org"), nullptr);
    EXPECT_NE(find(d.fields, "Subject: C=US, O=Example Org, CN=www.example.org"), nullptr);
    EXPECT_NE(find(d.fields, "Issuer: CN=Example CA"), nullptr);
    EXPECT_NE(find(d.fields, "Not Before: 2026-01-02 03:04:05 UTC"), nullptr);
    EXPECT_NE(find(d.fields, "Not After: 2027-01-02 03:04:05 UTC"), nullptr);
    EXPECT_NE(find(d.fields, "Subject Alternative Names: www.example.org, example.org"), nullptr);
    EXPECT_NE(find(d.fields, "Certificate: Example CA"), nullptr);
    EXPECT_NE(find(d.fields, "[Handshake message spans 2 records]"), nullptr);
    std::remove(path.c_str());
}

TEST(TlsStream, SeveralRecordsInOneSegmentAndEncryptedRecordsStayRecords) {
    const std::string hello = tlsRecord(22, std::string{2, 0, 0, 0});               // not meaningful, but a framed handshake record
    const std::string data = tlsRecord(23, std::string(300, 'e'));
    core::FileProcessor fp(builtin());
    std::vector<packet::PacketInfo> packets;
    std::string msg;
    const std::string stream = data + data + tlsRecord(21, std::string("\x02\x28", 2));
    const std::string path = support::writeTemp("tlsstream2.pcap", support::pcapBytes({syn("01bb"), fromServer443(1000, stream.substr(0, 400)), fromServer443(1400, stream.substr(400))}));
    ASSERT_TRUE(fp.processPcapFile(path, packets, msg)) << msg;
    EXPECT_EQ(packets[1].protocol, "TLS");
    EXPECT_EQ(packets[1].info.rfind("Application Data", 0), 0u) << packets[1].info;
    EXPECT_EQ(packets[2].protocol, "TLS");
    EXPECT_NE(packets[2].info.find("Alert"), std::string::npos) << packets[2].info;
    packet::PacketInfo d;
    ASSERT_TRUE(core::buildPacketDetails(path, packets[2], d, &packets, &fp.captureInfo(), &builtin()));
    EXPECT_EQ(d.info, packets[2].info);
    EXPECT_NE(find(d.fields, "Description: handshake_failure (40)"), nullptr);
    std::remove(path.c_str());
    (void) hello;
}

TEST(TlsStream, CertificateParserSurvivesDamage) {
    std::mt19937 rng(5);
    const std::string cert = certificate("host.test", {"a.test", "b.test"});
    for (int i = 0; i < 4000; ++i) {
        std::string d = cert;
        d.resize(rng() % (d.size() + 1));
        for (unsigned k = rng() % 4; k > 0 && !d.empty(); --k) d[rng() % d.size()] = static_cast<char>(rng());
        dissect::parseCertificate(reinterpret_cast<const unsigned char *>(d.data()), d.size());
    }
    const auto ok = dissect::parseCertificate(reinterpret_cast<const unsigned char *>(cert.data()), cert.size());
    EXPECT_TRUE(ok.ok);
    EXPECT_EQ(ok.commonName, "host.test");
    EXPECT_EQ(ok.serial, "012345");
    EXPECT_EQ(ok.dnsNames.size(), 2u);
}
