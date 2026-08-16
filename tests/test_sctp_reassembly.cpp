// SCTP user message reassembly through the dissector: a capture with fragmented messages on four streams (ordered, unordered,
// I-DATA) arriving out of order and bundled with other chunks, loaded the way the application loads it (load pass) and then
// replayed packet by packet (Replay reads only what the load pass decided).
//
// Oracles: the byte layouts of DATA and I-DATA are RFC 9260 3.3.1 and RFC 8260 2.1 (sctp_support.h); the expected messages are
// the strings the test cut into fragments; "Replay equals the load pass" is checked on every packet (Info, protocol, summary
// facts and a tree that stays inside the frame).
#include <gtest/gtest.h>

#include <cstdio>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include <core.h>
#include <filter/filter.h>
#include <stats/statistics.h>

#include "sctp_support.h"
#include "support.h"
#include "tls_support.h"

using namespace sctptest;
using tlstest::Loaded;

namespace {
    const Bytes kA = {10, 0, 0, 1}, kB = {10, 0, 0, 2};

    std::vector<char> toChars(const Bytes &b) { return std::vector<char>(b.begin(), b.end()); }
    // A (38412) -> B (5000) and back
    std::vector<char> fromA(const Bytes &chunks, uint32_t vtag = 0x11111111) { return toChars(ipFrame(sctpPacket(38412, 5000, vtag, chunks), kA, kB)); }
    std::vector<char> fromB(const Bytes &chunks, uint32_t vtag = 0x22222222) { return toChars(ipFrame(sctpPacket(5000, 38412, vtag, chunks), kB, kA)); }
    std::vector<char> udpFromA(const Bytes &chunks) {
        return toChars(framesweep::ethernet(0x0800, framesweep::ipv4Packet(17, framesweep::udpDatagram(9899, 9899, sctpPacket(38412, 5000, 0x11111111, chunks)), kA, kB)));
    }

    struct Cap {
        std::vector<std::vector<char>> frames;
        std::unique_ptr<Loaded> loaded;
        Loaded &load(const std::string &name) {
            loaded = std::make_unique<Loaded>(support::pcapBytes(frames), "sctp_" + name + ".pcap", false);
            EXPECT_TRUE(loaded->ok) << loaded->message;
            return *loaded;
        }
    };

    // Load pass == Replay for every packet: protocol, Info, the summary facts, and a tree inside the frame
    void expectReplayEqualsLoad(Loaded &cap) {
        for (size_t i = 0; i < cap.packets.size(); ++i) {
            const auto d = cap.details(i);
            const auto &p = cap.packets[i];
            EXPECT_EQ(d.protocol, p.protocol) << i;
            EXPECT_EQ(d.info, p.info) << i;
            EXPECT_EQ(d.app_type, p.app_type) << i;
            EXPECT_EQ(d.app_flags, p.app_flags) << i;
            EXPECT_EQ(d.app_code, p.app_code) << i;
            EXPECT_EQ(d.app_stream, p.app_stream) << i;
            EXPECT_EQ(d.app_text2, p.app_text2) << i;
            EXPECT_EQ(d.tcp_pdu_len, p.tcp_pdu_len) << i;
            EXPECT_EQ(d.checksum_state, p.checksum_state) << i;
            tlstest::expectInside(d.fields, d.raw_data.size());
        }
    }

    const std::string kS1 = "alpha-", kS1b = "bravo-", kS1c = "charlie";           // stream 1, ordered, SSN 0, TSN 10, 11, 12
    const std::string kU1 = "unordered-", kU2 = "message";                          // stream 3, unordered, TSN 13, 14
    const std::string kS2 = "one-two-", kS2b = "three";                             // stream 2, ordered, SSN 0, TSN 15, 16
    const std::string kI1 = "idata-", kI2 = "mid-", kI3 = "end";                    // stream 4, I-DATA MID 5, TSN 17, 18, 19 (FSN 0, 1, 2)

    // The capture of the tests below (arrival order scrambled):
    //  1 A>B s1 TSN10 B  + s2 TSN15 B      2 A>B s1 TSN12 E        3 B>A SACK           4 A>B s3 TSN14 E (unordered)
    //  5 A>B s1 TSN11  -> completes s1     6 A>B s3 TSN13 B -> completes s3             7 A>B I-DATA TSN18 FSN1
    //  8 A>B I-DATA TSN19 FSN2 E           9 A>B I-DATA TSN17 B PPID 46 -> completes   10 A>B s2 TSN16 E -> completes s2
    // 11 A>B s1 TSN10 B again + a whole DATA on stream 5
    std::vector<std::vector<char>> scrambled() {
        return {
            fromA(cat({data(0x02, 10, 1, 0, 51, kS1), data(0x02, 15, 2, 0, 51, kS2)})),
            fromA(data(0x01, 12, 1, 0, 51, kS1c)),
            fromB(chunk(3, 0, cat({Bytes{0, 0, 0, 9}, Bytes{0, 0, 1, 0}, Bytes{0, 0, 0, 0}}))),
            fromA(data(0x05, 14, 3, 0, 51, kU2)),
            fromA(data(0x00, 11, 1, 0, 51, kS1b)),
            fromA(data(0x06, 13, 3, 0, 51, kU1)),
            fromA(idata(0x00, 18, 4, 5, 1, kI2)),
            fromA(idata(0x01, 19, 4, 5, 2, kI3)),
            fromA(idata(0x02, 17, 4, 5, 46, kI1)),
            fromA(data(0x01, 16, 2, 0, 51, kS2b)),
            fromA(cat({data(0x02, 10, 1, 0, 51, kS1), data(0x03, 20, 5, 0, 0, "whole")})),
        };
    }
}

TEST(SctpReassembly, FragmentsOnFourStreamsInAnyOrderBecomeMessagesAndEarlierPacketsSayWhere) {
    Cap c;
    c.frames = scrambled();
    Loaded &cap = c.load("scrambled");
    ASSERT_EQ(cap.packets.size(), 11u);
    const auto &p = cap.packets;
    for (const auto &pk: p) EXPECT_EQ(pk.protocol, "SCTP");

    EXPECT_EQ(p[0].info, "38412 -> 5000 [DATA, DATA] [Reassembled in #5] [Reassembled in #10]");
    EXPECT_EQ(p[1].info, "38412 -> 5000 [DATA] [Reassembled in #5]");
    EXPECT_EQ(p[2].info, "5000 -> 38412 [SACK]");
    EXPECT_EQ(p[3].info, "38412 -> 5000 [DATA] [Reassembled in #6]");
    EXPECT_EQ(p[4].info, "38412 -> 5000 [DATA] [Reassembled SCTP message: 19 bytes, stream 1]");
    EXPECT_EQ(p[5].info, "38412 -> 5000 [DATA] [Reassembled SCTP message: 17 bytes, stream 3]");
    EXPECT_EQ(p[6].info, "38412 -> 5000 [I_DATA] [Reassembled in #9]");
    EXPECT_EQ(p[7].info, "38412 -> 5000 [I_DATA] [Reassembled in #9]");
    EXPECT_EQ(p[8].info, "38412 -> 5000 [I_DATA] [Reassembled SCTP message: 13 bytes, stream 4]");
    EXPECT_EQ(p[9].info, "38412 -> 5000 [DATA] [Reassembled SCTP message: 13 bytes, stream 2]");
    EXPECT_EQ(p[10].info, "38412 -> 5000 [DATA, DATA] [Retransmission]");

    // the completing packet's tree: the message, its frames in fragment order, its protocol, the bytes
    std::string t = treeText(cap.details(4).fields);
    EXPECT_TRUE(has(t, "[Reassembled SCTP message (19 bytes) from frame(s) 1, 5, 2]")) << t;
    EXPECT_TRUE(has(t, "Reassembled data (19 bytes): alpha-bravo-charlie"));
    EXPECT_TRUE(has(t, "Payload Protocol Identifier: 51 (WebRTC String)"));
    EXPECT_TRUE(has(t, "[SCTP fragment of a user message (middle, TSN 11)]"));
    // an earlier fragment: where it was reassembled
    t = treeText(cap.details(0).fields);
    EXPECT_TRUE(has(t, "[Reassembled in #5]")) << t;
    EXPECT_TRUE(has(t, "[Reassembled in #10]"));
    EXPECT_TRUE(has(t, "[SCTP fragment of a user message (first, TSN 10)]"));
    // the unordered and the I-DATA message
    t = treeText(cap.details(5).fields);
    EXPECT_TRUE(has(t, "Reassembled data (17 bytes): unordered-message")) << t;
    EXPECT_TRUE(has(t, "Flags: 0x06 (--B-)") || has(t, "(-UB-)")) << t;
    t = treeText(cap.details(8).fields);
    EXPECT_TRUE(has(t, "[Reassembled SCTP message (13 bytes) from frame(s) 9, 7, 8]")) << t;
    EXPECT_TRUE(has(t, "Reassembled data (13 bytes): idata-mid-end"));
    EXPECT_TRUE(has(t, "Payload Protocol Identifier: 46 (Diameter)"));
    EXPECT_TRUE(has(t, "Message Identifier: 5"));
    // the repeat of a fragment of a completed message
    t = treeText(cap.details(10).fields);
    EXPECT_TRUE(has(t, "[Retransmission of a fragment seen in #5]")) << t;

    // multi-stream totals of the direction A -> B
    t = treeText(cap.details(1).fields);
    EXPECT_TRUE(has(t, "[Stream 1 in this direction: 4 DATA chunk(s), 25 bytes, 1 message end(s) in the capture; 5 stream(s) in use]")) << t;

    expectReplayEqualsLoad(cap);
    EXPECT_EQ(cap.fp.sessions().sctpTable().messageCount(), 4u);
    EXPECT_EQ(cap.fp.sessions().sctpTable().pendingMessages(), 0u);
}

TEST(SctpReassembly, TheSameCaptureInOrderGivesTheSameMessages) {
    auto frames = scrambled();
    // in order of TSN: 1 (s1 B, s2 B), 5 (s1 mid), 2 (s1 E) ... rebuild: the order does not change what the messages are
    std::vector<std::vector<char>> inOrder = {frames[0], frames[4], frames[1], frames[8], frames[6], frames[7], frames[5], frames[3], frames[9]};
    Cap c;
    c.frames = inOrder;
    Loaded &cap = c.load("inorder");
    const auto &t = cap.fp.sessions().sctpTable();
    ASSERT_EQ(t.messageCount(), 4u);
    std::vector<std::string> got;
    for (uint32_t i = 0; i < 4; ++i) got.push_back(t.message(i)->data);
    std::sort(got.begin(), got.end());
    std::vector<std::string> want = {kS1 + kS1b + kS1c, kU1 + kU2, kS2 + kS2b, kI1 + kI2 + kI3};
    std::sort(want.begin(), want.end());
    EXPECT_EQ(got, want);
    expectReplayEqualsLoad(cap);
}

TEST(SctpReassembly, FragmentsInUdpEncapsulatedPacketsReassemble) {
    Cap c;
    c.frames = {udpFromA(data(0x02, 10, 1, 0, 51, "udp-")), udpFromA(data(0x01, 11, 1, 0, 51, "encapsulated"))};
    Loaded &cap = c.load("udp");
    EXPECT_EQ(cap.packets[0].protocol, "SCTP");
    EXPECT_EQ(cap.packets[0].info, "38412 -> 5000 [DATA] [Reassembled in #2]");
    EXPECT_EQ(cap.packets[1].info, "38412 -> 5000 [DATA] [Reassembled SCTP message: 16 bytes, stream 1]");
    EXPECT_TRUE(has(treeText(cap.details(1).fields), "Reassembled data (16 bytes): udp-encapsulated"));
    expectReplayEqualsLoad(cap);
}

TEST(SctpReassembly, ATableThatRanOutOfRoomSaysSoInsteadOfPretending) {
    Cap c;
    c.frames = scrambled();
    const std::string path = support::writeTemp("sctp_lost.pcap", support::pcapBytes(c.frames));
    core::FileProcessor fp;
    fp.sessions().setMaxMemoryPerTable(400);
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(fp.processPcapFile(path, packets, message));
    EXPECT_TRUE(fp.sessions().isTableStateLost("sctp"));
    bool saidSo = false;
    for (size_t i = 0; i < packets.size(); ++i) {
        packet::PacketInfo d;
        ASSERT_TRUE(core::buildPacketDetails(path, packets[i], d, &packets, &fp.captureInfo(), nullptr, &fp.sessions()));
        EXPECT_EQ(d.info, packets[i].info) << i;
        tlstest::expectInside(d.fields, d.raw_data.size());
        saidSo = saidSo || packets[i].info.find("[SCTP reassembly state lost]") != std::string::npos;
    }
    EXPECT_TRUE(saidSo);
    std::remove(path.c_str());
}

TEST(SctpReassembly, ConflictingBytesAreFlaggedAndTheFirstCopyWins) {
    Cap c;
    c.frames = {fromA(data(0x02, 10, 1, 0, 51, "aaaa")), fromA(data(0x02, 10, 1, 0, 51, "aXaa")), fromA(data(0x01, 11, 1, 0, 51, "bb"))};
    Loaded &cap = c.load("conflict");
    EXPECT_NE(cap.packets[1].info.find("[Retransmission] [Conflicting fragment]"), std::string::npos) << cap.packets[1].info;
    EXPECT_EQ(cap.fp.sessions().sctpTable().message(0)->data, "aaaabb");
    EXPECT_TRUE(has(treeText(cap.details(1).fields), "other bytes than the first copy"));
    expectReplayEqualsLoad(cap);
}

TEST(SctpReassembly, ADamagedPacketThatCarriesAFragmentIsStillReplayedLikeTheLoadPass) {
    // a cut packet (its chunk is not counted or reassembled) and a bad-CRC copy of a fragment (still a copy of it)
    Bytes first = ipFrame(sctpPacket(38412, 5000, 1, data(0x02, 10, 1, 0, 51, "aaaa")), kA, kB);
    Cap c;
    c.frames = {toChars(first)};
    Bytes cutFrame(first.begin(), first.end() - 6);
    c.frames.push_back(toChars(cutFrame));
    Bytes badCrc = first;
    badCrc[badCrc.size() - 1] ^= 0xff;
    c.frames.push_back(toChars(badCrc));
    c.frames.push_back(fromA(data(0x01, 11, 1, 0, 51, "bb")));
    Loaded &cap = c.load("damaged");
    // the first copy of TSN 10 (packet 1) completes the message with TSN 11; the cut copy and the bad-CRC copy are repeats
    EXPECT_NE(cap.packets[3].info.find("Reassembled SCTP message: 6 bytes"), std::string::npos) << cap.packets[3].info;
    EXPECT_EQ(cap.packets[1].info.find("Reassembled in"), std::string::npos) << cap.packets[1].info;
    expectReplayEqualsLoad(cap);
}

TEST(SctpReassembly, ConversationsAndEndpointsSeeTheSctpPorts) {
    Cap c;
    c.frames = scrambled();
    c.frames.push_back(udpFromA(data(0x03, 30, 1, 0, 51, "udp")));
    Loaded &cap = c.load("b8");
    const auto conversations = stats::conversations(cap.packets, nullptr, stats::AddressKind::Sctp);
    ASSERT_EQ(conversations.size(), 1u);
    const auto &conv = conversations[0];
    EXPECT_EQ(conv.addressA, "10.0.0.1");
    EXPECT_EQ(conv.portA, 38412);
    EXPECT_EQ(conv.addressB, "10.0.0.2");
    EXPECT_EQ(conv.portB, 5000);
    EXPECT_EQ(conv.packets, 12u);        // the UDP encapsulated packet is the same SCTP conversation
    EXPECT_EQ(conv.packetsAtoB, 11u);
    EXPECT_EQ(conv.packetsBtoA, 1u);
    EXPECT_EQ(stats::endpoints(cap.packets, nullptr, stats::AddressKind::Sctp).size(), 2u);
    auto f = filter::Filter::compile(stats::conversationFilter(conv, stats::AddressKind::Sctp));
    ASSERT_TRUE(f.ok);
    size_t matched = 0;
    for (const auto &pk: cap.packets) matched += f.filter.matches(pk);
    EXPECT_EQ(matched, 12u);
}

TEST(SctpReassembly, SeededDamageToTheWholeCaptureNeverBreaksReplayEquality) {
    // Random byte changes and cuts anywhere in the frames of the scrambled capture (fragment flags, TSNs, streams, lengths,
    // ports): whatever the load pass decides, Replay shows the same Info and facts, and trees stay inside their frames.
    uint32_t seed = 0x5c7a2001u;
    auto next = [&seed]() { seed = seed * 1664525u + 1013904223u; return seed >> 8; };
    for (int round = 0; round < 40; ++round) {
        Cap c;
        c.frames = scrambled();
        for (int i = 0, n = 1 + int(next() % 6); i < n; ++i) {
            auto &frame = c.frames[next() % c.frames.size()];
            frame[14 + 20 + next() % (frame.size() - 34)] = static_cast<char>(next());   // inside the SCTP packet
        }
        if (next() % 3 == 0) { auto &frame = c.frames[next() % c.frames.size()]; frame.resize(34 + next() % (frame.size() - 33)); }
        Loaded &cap = c.load("damage" + std::to_string(round));
        SCOPED_TRACE("round " + std::to_string(round));
        expectReplayEqualsLoad(cap);
    }
}

namespace {
    size_t count(const std::vector<packet::PacketInfo> &packets, const std::string &expression) {
        auto f = filter::Filter::compile(expression);
        EXPECT_TRUE(f.ok) << expression << " did not compile";
        size_t n = 0;
        if (f.ok) for (const auto &p: packets) n += f.filter.matches(p);
        return n;
    }
}

// Expected counts follow from the capture comment above scrambled(): the first data chunk of each packet decides.
TEST(SctpReassembly, FilterFieldsDescribeTheDataChunksAndTheReassembly) {
    Cap c;
    c.frames = scrambled();
    Loaded &cap = c.load("fields");
    const auto &p = cap.packets;
    EXPECT_EQ(count(p, "sctp"), 11u);
    EXPECT_EQ(count(p, "sctp.data"), 10u);                                    // all but the SACK
    EXPECT_EQ(count(p, "sctp.checksum.status == 1"), 11u);
    EXPECT_EQ(count(p, "sctp.reassembled"), 4u);                              // packets 5, 6, 9, 10
    EXPECT_EQ(count(p, "sctp.reassembled && sctp.data.sid == 1"), 1u);
    EXPECT_EQ(count(p, "sctp.data.fragment"), 10u);
    EXPECT_EQ(count(p, "sctp.data.idata"), 3u);
    EXPECT_EQ(count(p, "sctp.data.unordered"), 2u);
    EXPECT_EQ(count(p, "sctp.data.retransmission"), 1u);
    EXPECT_EQ(count(p, "sctp.data.ppid == 46"), 1u);                          // the message's PPID, on the completing packet
    EXPECT_EQ(count(p, "sctp.data.ppid == 51"), 7u);
    EXPECT_EQ(count(p, "sctp.data.sid == 4"), 3u);
    EXPECT_EQ(count(p, "sctp.data.ssn == 5"), 3u);                            // the MID of the I-DATA message
    EXPECT_EQ(count(p, "sctp.data.tsn == 10"), 2u);                           // the fragment and its retransmission
    EXPECT_EQ(count(p, "sctp.chunk_type == 3"), 1u);
    EXPECT_EQ(count(p, "!sctp.data"), 1u);
}

TEST(SctpReassembly, TheHierarchyNamesSctpUnderIpAndUnderUdp) {
    Cap c;
    c.frames = {fromA(data(0x03, 1, 0, 0, 0, "x")), udpFromA(data(0x03, 2, 0, 0, 0, "y"))};
    Loaded &cap = c.load("hierarchy");
    const auto root = stats::protocolHierarchy(cap.packets, nullptr);
    std::string flat;
    std::function<void(const stats::HierarchyNode &, int)> dump = [&](const stats::HierarchyNode &n, int depth) {
        flat += std::string(depth, ' ') + n.name + " " + std::to_string(n.packets) + "\n";
        for (const auto &ch: n.children) dump(ch, depth + 1);
    };
    dump(root, 0);
    EXPECT_NE(flat.find("  Internet Protocol Version 4 2\n"), std::string::npos) << flat;
    EXPECT_NE(flat.find("   Stream Control Transmission Protocol 1\n"), std::string::npos) << flat;             // directly under IP
    EXPECT_NE(flat.find("   User Datagram Protocol 1\n    Stream Control Transmission Protocol 1\n"), std::string::npos) << flat;   // under UDP
    EXPECT_EQ(flat.find("Other IP protocol"), std::string::npos) << flat;
}
