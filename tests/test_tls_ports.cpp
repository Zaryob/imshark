// TLS on the ports of the enterprise protocols (LDAP, PostgreSQL, MySQL, TDS, SMB, Kerberos, RPC, NFS): a TLS record there
// is TLS (LDAPS is TLS from the first byte), a plain message of the port's own protocol still decodes as that protocol.
#include <gtest/gtest.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    // ClientHello record: handshake type 1 (length 0) in a TLS 1.0 record, then a server's ServerHello record
    const std::string kClientHello = bytes("160301" "0004" "01000000");
    const std::string kServerHello = bytes("160303" "0004" "02000000");
    const std::string kAppData = bytes("170303" "0010" "00112233445566778899aabbccddeeff");
}

TEST(TlsOnProtocolPorts, ARecordIsTlsOnEveryPortThatRegistersAStreamProtocol) {
    for (uint16_t port: {636, 389, 5432, 3306, 1433, 445, 139, 88, 135, 2049, 111}) {
        Flow flow(50000, port, "tlsport" + std::to_string(port));
        flow.client(kClientHello).server(kServerHello).client(kAppData);
        flow.load();
        ASSERT_EQ(flow.packets().size(), 3u);
        for (size_t i = 0; i < 3; ++i) EXPECT_EQ(flow.packets()[i].protocol, "TLS") << "port " << port << " packet " << i + 1;
        EXPECT_EQ(flow.packets()[0].info, "Client Hello") << port;
        flow.expectReplayEqualsLoad();
    }
}

TEST(TlsOnProtocolPorts, AStandaloneFrameWithoutStreamStateIsTlsToo) {
    for (uint16_t port: {636, 389, 5432, 3306, 1433}) {
        char p[8];
        std::snprintf(p, sizeof p, "%04x", port);
        const auto pkt = support::parse(support::tcpPacket("0a000001", "0a000002", "c350", p, "00000001", "00000001", "18", kClientHello));
        EXPECT_EQ(pkt.protocol, "TLS") << port;
    }
}

TEST(TlsOnProtocolPorts, ASegmentedHelloIsReassembledAsTlsOnTheLdapsPort) {
    Flow flow(50001, 636, "ldaps_split");
    // a handshake of 14 bytes (type 1, length 10) split over two segments
    const std::string record = bytes("160301" "000e" "0100000a" "0303" "0000000000000000");
    flow.client(record.substr(0, 7)).client(record.substr(7));
    flow.load();
    EXPECT_EQ(flow.packets()[0].protocol, "TLS");
    EXPECT_EQ(flow.packets()[1].protocol, "TLS");
    EXPECT_NE(flow.packets()[0].info.find("[TCP segment of a reassembled PDU]"), std::string::npos) << flow.packets()[0].info;
}

TEST(TlsUpgradeTable, MarksADirectionFromASequenceNumberOnAndIsReadOnlyOnceFrozen) {
    dissect::SessionTables t;
    EXPECT_FALSE(t.isTlsUpgraded("10.0.0.1", 50000, "10.0.0.2", 389, 100));
    ASSERT_TRUE(t.markTlsUpgrade("10.0.0.1", 50000, "10.0.0.2", 389, 100));
    EXPECT_FALSE(t.isTlsUpgraded("10.0.0.1", 50000, "10.0.0.2", 389, 99));
    EXPECT_TRUE(t.isTlsUpgraded("10.0.0.1", 50000, "10.0.0.2", 389, 100));
    EXPECT_TRUE(t.markTlsUpgrade("10.0.0.3", 50000, "10.0.0.2", 389, 4294967290u));
    EXPECT_TRUE(t.isTlsUpgraded("10.0.0.3", 50000, "10.0.0.2", 389, 5)) << "sequence numbers compare modulo 2^32";
    EXPECT_FALSE(t.isTlsUpgraded("10.0.0.3", 50000, "10.0.0.2", 389, 4294967000u));
    EXPECT_FALSE(t.isTlsUpgraded("10.0.0.2", 389, "10.0.0.1", 50000, 100)) << "the other direction has its own mark";
    ASSERT_TRUE(t.markTlsUpgrade("10.0.0.1", 50000, "10.0.0.2", 389, 500));   // the first mark wins
    EXPECT_TRUE(t.isTlsUpgraded("10.0.0.1", 50000, "10.0.0.2", 389, 100));
    t.forgetTlsUpgrade("10.0.0.2", 389, "10.0.0.1", 50000);   // a new connection between the endpoints
    EXPECT_FALSE(t.isTlsUpgraded("10.0.0.1", 50000, "10.0.0.2", 389, 100));
    ASSERT_TRUE(t.markTlsUpgrade("10.0.0.1", 50000, "10.0.0.2", 389, 7));
    t.freeze();
    EXPECT_FALSE(t.markTlsUpgrade("10.0.0.1", 50001, "10.0.0.2", 389, 7));
    EXPECT_TRUE(t.isTlsUpgraded("10.0.0.1", 50000, "10.0.0.2", 389, 7));
    t.unfreeze();
    t.clear();
    EXPECT_FALSE(t.isTlsUpgraded("10.0.0.1", 50000, "10.0.0.2", 389, 7));
}

TEST(TlsUpgradeTable, ABudgetThatIsTooSmallMarksTheTableStateLost) {
    dissect::SessionTables t(64);
    EXPECT_FALSE(t.markTlsUpgrade("10.0.0.1", 50000, "10.0.0.2", 389, 7));
    EXPECT_TRUE(t.isTableStateLost("tls-upgrade"));
}
