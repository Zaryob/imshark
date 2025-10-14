#include <gtest/gtest.h>

#include "core.h"
#include "dissect/session.h"
#include "support.h"

#include <atomic>
#include <thread>
#include <vector>

namespace {

const packet::Field *findField(const std::vector<packet::Field> &fields, const std::string &prefix) {
    for (const auto &f : fields) {
        if (f.text.rfind(prefix, 0) == 0 || f.text.find(prefix) != std::string::npos) return &f;
        if (const auto *c = findField(f.children, prefix)) return c;
    }
    return nullptr;
}

} // namespace

TEST(SessionTables, FreezePreventsMutation) {
    core::SessionTables tbl;
    EXPECT_FALSE(tbl.isFrozen());

    EXPECT_TRUE(tbl.addFtpDataPort(21000));
    EXPECT_TRUE(tbl.hasFtpDataPort(21000));
    EXPECT_EQ(tbl.ftpDataPorts().size(), 1u);

    EXPECT_TRUE(tbl.addTftpSession("10.0.0.1", 50001, "10.0.0.2", 0));
    EXPECT_EQ(tbl.tftpSessions().size(), 1u);

    tbl.freeze();
    EXPECT_TRUE(tbl.isFrozen());

    // Mutations must be rejected while frozen
    EXPECT_FALSE(tbl.addFtpDataPort(21001));
    EXPECT_FALSE(tbl.hasFtpDataPort(21001));
    EXPECT_EQ(tbl.ftpDataPorts().size(), 1u);

    EXPECT_FALSE(tbl.addTftpSession("10.0.0.3", 50002, "10.0.0.4", 0));
    EXPECT_EQ(tbl.tftpSessions().size(), 1u);

    // TFTP matchOrUpdate matches existing session, but does NOT update serverPort when frozen
    EXPECT_TRUE(tbl.matchOrUpdateTftpSession(50001, 60000));
    EXPECT_EQ(tbl.tftpSessions()[0].serverPort, 0); // remains 0 because frozen!

    // Unfreeze and reset with clear()
    tbl.clear();
    EXPECT_FALSE(tbl.isFrozen());
    EXPECT_FALSE(tbl.hasFtpDataPort(21000));
    EXPECT_TRUE(tbl.tftpSessions().empty());
    EXPECT_EQ(tbl.totalMemoryUsage(), 0u);
}

TEST(SessionTables, MemoryLimitAndStateLostDiagnostic) {
    // Set limit: 200 bytes per table
    core::SessionTables tbl(200);
    EXPECT_FALSE(tbl.hasStateLost());

    // FTP ports (~34 bytes each)
    for (uint16_t p = 30000; p < 30005; ++p) {
        tbl.addFtpDataPort(p);
    }
    // More ports will eventually overflow the 200 bytes budget
    for (uint16_t p = 30005; p < 30020; ++p) {
        tbl.addFtpDataPort(p);
    }
    EXPECT_TRUE(tbl.hasStateLost());
    EXPECT_TRUE(tbl.isTableStateLost("ftp"));
    EXPECT_FALSE(tbl.isTableStateLost("tftp"));

    // TFTP table: 1 session is ~124 bytes, fits in 200 bytes
    EXPECT_TRUE(tbl.addTftpSession("10.0.0.1", 40000, "10.0.0.2", 0));
    EXPECT_FALSE(tbl.isTableStateLost("tftp"));

    // Second TFTP session exceeds 200 bytes -> overflows
    EXPECT_FALSE(tbl.addTftpSession("10.0.0.1", 40001, "10.0.0.2", 0));
    EXPECT_TRUE(tbl.isTableStateLost("tftp"));
}

TEST(SessionTables, ReplayConsistencyWithBuildPacketDetails) {
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;

    const std::string path = support::writeTemp("ftp_session_test.pcap", support::pcapBytes({
        // Packet 1: FTP server says 227 Entering Passive Mode (10,0,0,2,195,80) -> port 50000
        support::tcpPacket("0a000002", "0a000001", "0015", "d000", "00000001", "00000001", "18",
                           "227 Entering Passive Mode (10,0,0,2,195,80)\r\n"),
        // Packet 2: Data transfer on negotiated dynamic port 50000 (0xc350)
        support::tcpPacket("0a000002", "0a000001", "c350", "d001", "00000001", "00000001", "18",
                           "Listing file1.txt\r\nfile2.txt\r\n"),
    }));

    ASSERT_TRUE(fp.processPcapFile(path, packets, message)) << message;
    ASSERT_EQ(packets.size(), 2u);

    // Verify session state was recorded and frozen
    EXPECT_TRUE(fp.sessions().isFrozen());
    EXPECT_TRUE(fp.sessions().hasFtpDataPort(50000));
    EXPECT_EQ(packets[0].protocol, "FTP");
    EXPECT_EQ(packets[1].protocol, "FTP-DATA");

    // Build details for packet 2 using the recorded sessions
    packet::PacketInfo details;
    ASSERT_TRUE(core::buildPacketDetails(path, packets[1], details, &packets, &fp.captureInfo(), nullptr, &fp.sessions()));
    EXPECT_EQ(details.protocol, "FTP-DATA");
    EXPECT_NE(findField(details.fields, "FTP Data"), nullptr);

    std::remove(path.c_str());
}

TEST(SessionTables, ThreadSafetyConcurrentReaders) {
    core::SessionTables tbl;
    for (uint16_t p = 10000; p < 10100; ++p) {
        tbl.addFtpDataPort(p);
    }
    tbl.freeze();

    std::atomic<bool> ok{true};
    std::vector<std::thread> readers;
    for (int t = 0; t < 8; ++t) {
        readers.emplace_back([&tbl, &ok] {
            for (int i = 0; i < 500; ++i) {
                for (uint16_t p = 10000; p < 10100; ++p) {
                    if (!tbl.hasFtpDataPort(p)) ok = false;
                }
                if (tbl.hasFtpDataPort(9999)) ok = false;
            }
        });
    }

    for (auto &th : readers) th.join();
    EXPECT_TRUE(ok.load());
}
