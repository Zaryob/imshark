#include <gtest/gtest.h>

#include <network/byteorder.h>

#include <network/tcp_connection.h>

namespace {
    network::TCPHeader segment(uint16_t sp, uint16_t dp, uint32_t seq, uint32_t ack, uint8_t flags) {
        network::TCPHeader h{};
        h.src_port = network::hton16(sp);
        h.dest_port = network::hton16(dp);
        h.seq_num = network::hton32(seq);
        h.ack_num = network::hton32(ack);
        h.flags = flags;
        return h;
    }
} // namespace

TEST(TcpTracking, RelativeNumbersFollowWireshark) {
    network::TCPConnection c;
    int64_t seq, ack;
    const std::string a = "10.0.0.1", b = "10.0.0.2";

    c.trackTCPConnections(seq, ack, a, b, segment(5000, 80, 1000, 0, 0x02)); // SYN
    EXPECT_EQ(seq, 0);
    EXPECT_EQ(ack, -1) << "no ACK flag -> hidden";

    c.trackTCPConnections(seq, ack, b, a, segment(80, 5000, 9000, 1001, 0x12)); // SYN-ACK
    EXPECT_EQ(seq, 0);
    EXPECT_EQ(ack, 1);

    c.trackTCPConnections(seq, ack, a, b, segment(5000, 80, 1001, 9001, 0x18)); // PSH-ACK with data
    EXPECT_EQ(seq, 1);
    EXPECT_EQ(ack, 1);

    c.trackTCPConnections(seq, ack, b, a, segment(80, 5000, 9001, 1101, 0x10));
    EXPECT_EQ(seq, 1);
    EXPECT_EQ(ack, 101);
}

TEST(TcpTracking, ReusedPortStartsNewConnection) {
    network::TCPConnection c;
    int64_t seq, ack;
    c.trackTCPConnections(seq, ack, "a", "b", segment(1, 2, 100, 0, 0x02));
    c.trackTCPConnections(seq, ack, "a", "b", segment(1, 2, 101, 0, 0x10));
    EXPECT_EQ(seq, 1);
    c.trackTCPConnections(seq, ack, "a", "b", segment(1, 2, 900000, 0, 0x02));
    EXPECT_EQ(seq, 0);
}

TEST(TcpTracking, SeparateConnectionsDoNotInterfere) {
    network::TCPConnection c;
    int64_t seq, ack;
    c.trackTCPConnections(seq, ack, "a", "b", segment(1, 2, 100, 0, 0x02));
    c.trackTCPConnections(seq, ack, "a", "b", segment(3, 4, 5000, 0, 0x02));
    c.trackTCPConnections(seq, ack, "a", "b", segment(1, 2, 110, 0, 0x10));
    EXPECT_EQ(seq, 10);
}

// ---- TCP analysis ---------------------------------------------------------------------------------------

namespace {
    using network::TcpAnalysis;

    struct Flow {
        network::TCPConnection c;
        int64_t seq = 0, ack = 0;
        // client 10.0.0.1:5000 <-> server 10.0.0.2:80
        TcpAnalysis client(uint32_t s, uint32_t a, uint8_t flags, uint32_t len, uint16_t win = 1000) {
            auto h = segment(5000, 80, s, a, flags);
            h.window = network::hton16(win);
            return c.trackAndAnalyze(seq, ack, "10.0.0.1", "10.0.0.2", h, len);
        }
        TcpAnalysis server(uint32_t s, uint32_t a, uint8_t flags, uint32_t len, uint16_t win = 1000) {
            auto h = segment(80, 5000, s, a, flags);
            h.window = network::hton16(win);
            return c.trackAndAnalyze(seq, ack, "10.0.0.2", "10.0.0.1", h, len);
        }
    };
    constexpr uint8_t ACK = 0x10, PSH_ACK = 0x18, SYN = 0x02, FIN_ACK = 0x11, RST = 0x04;
} // namespace

TEST(TcpAnalysis, InOrderDataHasNoFlags) {
    Flow f;
    EXPECT_EQ(f.client(1000, 0, SYN, 0).flags, 0);
    EXPECT_EQ(f.server(9000, 1001, SYN | ACK, 0).flags, 0);
    EXPECT_EQ(f.client(1001, 9001, ACK, 0).flags, 0);
    EXPECT_EQ(f.client(1001, 9001, PSH_ACK, 100).flags, 0);
    EXPECT_EQ(f.client(1101, 9001, PSH_ACK, 100).flags, 0);
    EXPECT_EQ(f.server(9001, 1201, ACK, 0).flags, 0);
    EXPECT_EQ(f.client(1201, 9001, FIN_ACK, 0).flags, 0);
}

TEST(TcpAnalysis, Retransmission) {
    Flow f;
    f.client(1000, 0, SYN, 0);
    f.client(1001, 5, PSH_ACK, 100);
    const auto r = f.client(1001, 5, PSH_ACK, 100);
    EXPECT_EQ(r.flags, network::kTcpRetransmission);
    // a partial overlap that extends the stream is still a retransmission (of the overlapping part)
    EXPECT_EQ(f.client(1051, 5, PSH_ACK, 100).flags, network::kTcpRetransmission);
    EXPECT_EQ(f.client(1151, 5, PSH_ACK, 10).flags, 0) << "new data after the overlap continues normally";
}

TEST(TcpAnalysis, SynRetransmission) {
    Flow f;
    EXPECT_EQ(f.client(1000, 0, SYN, 0).flags, 0);
    EXPECT_EQ(f.client(1000, 0, SYN, 0).flags, network::kTcpRetransmission);
}

TEST(TcpAnalysis, LostSegmentThenOutOfOrderFill) {
    Flow f;
    f.client(1000, 0, SYN, 0);
    f.client(1001, 5, PSH_ACK, 100);                                        // 1001..1100
    EXPECT_EQ(f.client(1201, 5, PSH_ACK, 100).flags, network::kTcpLostSegment) << "1101..1200 missing";
    EXPECT_EQ(f.client(1101, 5, PSH_ACK, 100).flags, network::kTcpOutOfOrder) << "the missing segment arrives late";
    EXPECT_EQ(f.client(1101, 5, PSH_ACK, 100).flags, network::kTcpRetransmission) << "and once more: now a real repeat";
    EXPECT_EQ(f.client(1301, 5, PSH_ACK, 10).flags, 0) << "the stream continues normally after the gap was filled";
}

TEST(TcpAnalysis, GapFilledInPiecesAndInTheMiddle) {
    Flow f;
    f.client(1000, 0, SYN, 0);
    f.client(1001, 5, PSH_ACK, 100);
    f.client(1401, 5, PSH_ACK, 100);                                        // gap 1101..1400
    EXPECT_EQ(f.client(1201, 5, PSH_ACK, 100).flags, network::kTcpOutOfOrder) << "middle of the gap";
    EXPECT_EQ(f.client(1101, 5, PSH_ACK, 100).flags, network::kTcpOutOfOrder) << "front part";
    EXPECT_EQ(f.client(1301, 5, PSH_ACK, 100).flags, network::kTcpOutOfOrder) << "rest";
    EXPECT_EQ(f.client(1201, 5, PSH_ACK, 100).flags, network::kTcpRetransmission) << "the gap is closed now";
}

TEST(TcpAnalysis, DuplicateAcksAreCounted) {
    Flow f;
    f.client(1000, 0, SYN, 0);
    f.server(9000, 1001, SYN | ACK, 0);
    EXPECT_EQ(f.server(9001, 1101, ACK, 0).flags, 0) << "first ACK with this number";
    const auto d1 = f.server(9001, 1101, ACK, 0);
    EXPECT_EQ(d1.flags, network::kTcpDuplicateAck);
    EXPECT_EQ(d1.duplicateAckCount, 1);
    EXPECT_EQ(f.server(9001, 1101, ACK, 0).duplicateAckCount, 2);
    EXPECT_EQ(f.server(9001, 1101, ACK, 0).duplicateAckCount, 3);
    EXPECT_EQ(f.server(9001, 1201, ACK, 0).flags, 0) << "a new ACK number ends the series";
    EXPECT_EQ(f.server(9001, 1201, ACK, 0).duplicateAckCount, 1) << "and the counter restarts";
}

TEST(TcpAnalysis, DataSegmentsAreNeverDuplicateAcks) {
    Flow f;
    f.client(1000, 0, SYN, 0);
    f.server(9001, 1101, ACK, 0);
    EXPECT_EQ(f.server(9001, 1101, PSH_ACK, 50).flags & network::kTcpDuplicateAck, 0);
}

TEST(TcpAnalysis, WindowUpdateAndZeroWindow) {
    Flow f;
    f.client(1000, 0, SYN, 0);
    f.server(9001, 1101, ACK, 0, 1000);
    EXPECT_EQ(f.server(9001, 1101, ACK, 0, 5000).flags, network::kTcpWindowUpdate);
    EXPECT_EQ(f.server(9001, 1101, ACK, 0, 0).flags, network::kTcpZeroWindow) << "a zero window is not a dup ACK";
    EXPECT_EQ(f.server(9001, 1101, ACK, 0, 0).flags, network::kTcpZeroWindow);
    EXPECT_EQ(f.server(9001, 1101, ACK, 0, 4000).flags, network::kTcpWindowUpdate);
}

TEST(TcpAnalysis, KeepAlive) {
    Flow f;
    f.client(1000, 0, SYN, 0);
    f.client(1001, 5, PSH_ACK, 100);                                        // next expected: 1101
    EXPECT_EQ(f.client(1100, 5, ACK, 0).flags, network::kTcpKeepAlive) << "0 bytes at nextSeq - 1";
    EXPECT_EQ(f.client(1100, 5, ACK, 1).flags, network::kTcpKeepAlive) << "1 byte garbage keep-alive";
    EXPECT_EQ(f.client(1101, 6, ACK, 0).flags, 0) << "a plain ACK at nextSeq is nothing special";
}

TEST(TcpAnalysis, ResetsAndFinsAreNotDuplicates) {
    Flow f;
    f.client(1000, 0, SYN, 0);
    f.client(1001, 5, ACK, 0);
    EXPECT_EQ(f.client(1001, 5, RST, 0).flags & network::kTcpDuplicateAck, 0);
    EXPECT_EQ(f.client(1001, 5, FIN_ACK, 0).flags, 0) << "the first FIN is normal";
    EXPECT_EQ(f.client(1001, 5, FIN_ACK, 0).flags, network::kTcpRetransmission) << "a repeated FIN is a retransmission";
}

TEST(TcpAnalysis, SequenceNumbersWrapAround) {
    Flow f;
    f.client(0xFFFFFF00u, 0, SYN, 0);
    f.client(0xFFFFFF01u, 5, PSH_ACK, 0xFF);                                // ends at 0xFFFFFFFF+1 = 0
    EXPECT_EQ(f.client(0x00000000u, 5, PSH_ACK, 10).flags, 0) << "in order across the wrap";
    EXPECT_EQ(f.client(0xFFFFFF01u, 5, PSH_ACK, 0xFF).flags, network::kTcpRetransmission) << "old data before the wrap";
    EXPECT_EQ(f.client(0x00000020u, 5, PSH_ACK, 10).flags, network::kTcpLostSegment);
}

TEST(TcpAnalysis, ConnectionsAreIndependentAndDirectionsToo) {
    Flow f;
    f.client(1000, 0, SYN, 0);
    f.client(1001, 5, PSH_ACK, 100);
    EXPECT_EQ(f.server(1001, 1101, PSH_ACK, 100).flags, 0) << "the server's sequence space is separate";
    network::TCPHeader other = segment(6000, 80, 1001, 5, PSH_ACK);
    other.window = network::hton16(1000);
    int64_t s, a;
    EXPECT_EQ(f.c.trackAndAnalyze(s, a, "10.0.0.1", "10.0.0.2", other, 100).flags, 0) << "another connection (other port)";
}
