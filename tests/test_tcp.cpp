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
