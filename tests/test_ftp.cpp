#include <gtest/gtest.h>

#include "dissect/protocols.h"
#include "dissect/session.h"
#include "filter/filter.h"
#include "packet/packet_parser.h"
#include "support.h"

#include <random>
#include <string>

namespace {

packet::PacketInfo ftpTcp(const std::string &payload, const char *sport = "c350", const char *dport = "0015") {
    // 0015 = 21 (FTP control)
    return support::parse(support::tcpPacket("0a000001", "0a000002", sport, dport, "00000001", "00000001", "18", payload));
}

bool matches(const std::string &expr, const packet::PacketInfo &pkt) {
    auto r = filter::Filter::compile(expr);
    EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
    return r.ok && r.filter.matches(pkt);
}

const packet::Field *findField(const std::vector<packet::Field> &fields, const std::string &prefix) {
    for (const auto &f : fields) {
        if (f.text.rfind(prefix, 0) == 0 || f.text.find(prefix) != std::string::npos) return &f;
        if (const auto *c = findField(f.children, prefix)) return c;
    }
    return nullptr;
}

} // namespace

TEST(FtpDissect, ServerGreetingAndCommands) {
    const auto pBanner = ftpTcp("220 FTP Server ready.\r\n", "0015", "c350");
    EXPECT_EQ(pBanner.protocol, "FTP");
    EXPECT_EQ(pBanner.info, "Response: 220 FTP Server ready.");
    EXPECT_EQ(pBanner.app_type, 2); // response
    EXPECT_EQ(pBanner.app_code, 220);
    EXPECT_TRUE(matches("ftp", pBanner));
    EXPECT_TRUE(matches("ftp.rsp", pBanner));
    EXPECT_TRUE(matches("ftp.response.code == 220", pBanner));
    EXPECT_NE(findField(pBanner.fields, "Response code: 220"), nullptr);

    const auto pUser = ftpTcp("USER anonymous\r\n");
    EXPECT_EQ(pUser.protocol, "FTP");
    EXPECT_EQ(pUser.info, "Request: USER anonymous");
    EXPECT_EQ(pUser.app_type, 1); // request
    EXPECT_EQ(pUser.app_text, "USER");
    EXPECT_EQ(pUser.app_text2, "anonymous");
    EXPECT_TRUE(matches("ftp.req", pUser));
    EXPECT_TRUE(matches("ftp.command == \"USER\"", pUser));
    EXPECT_TRUE(matches("ftp.arg == \"anonymous\"", pUser));

    const auto pPass = ftpTcp("PASS guest@example.com\r\n");
    EXPECT_EQ(pPass.info, "Request: PASS guest@example.com");
    EXPECT_TRUE(matches("ftp.command == \"PASS\"", pPass));

    const auto pRetr = ftpTcp("RETR document.pdf\r\n");
    EXPECT_EQ(pRetr.info, "Request: RETR document.pdf");
    EXPECT_TRUE(matches("ftp.arg == \"document.pdf\"", pRetr));
}

TEST(FtpDissect, PassiveModePasvAndEpsv) {
    // 227 Entering Passive Mode (192,168,1,10,195,80) -> port 195*256 + 80 = 50000
    const auto pPasv = ftpTcp("227 Entering Passive Mode (192,168,1,10,195,80)\r\n", "0015", "c350");
    EXPECT_EQ(pPasv.protocol, "FTP");
    EXPECT_EQ(pPasv.app_code, 227);
    EXPECT_NE(findField(pPasv.fields, "Passive IPv4 address: 192.168.1.10"), nullptr);
    EXPECT_NE(findField(pPasv.fields, "Passive port: 50000"), nullptr);

    // 229 Entering Extended Passive Mode (|||51234|)
    const auto pEpsv = ftpTcp("229 Entering Extended Passive Mode (|||51234|)\r\n", "0015", "c350");
    EXPECT_EQ(pEpsv.protocol, "FTP");
    EXPECT_EQ(pEpsv.app_code, 229);
    EXPECT_NE(findField(pEpsv.fields, "Extended passive port: 51234"), nullptr);
}

TEST(FtpDissect, ActiveModePortAndEprt) {
    // PORT 10,0,0,1,156,64 -> port 156*256 + 64 = 40000
    const auto pPort = ftpTcp("PORT 10,0,0,1,156,64\r\n");
    EXPECT_EQ(pPort.protocol, "FTP");
    EXPECT_EQ(pPort.app_text, "PORT");
    EXPECT_NE(findField(pPort.fields, "Active address: 10.0.0.1"), nullptr);
    EXPECT_NE(findField(pPort.fields, "Active port: 40000"), nullptr);

    // EPRT |1|10.0.0.1|40001|
    const auto pEprt = ftpTcp("EPRT |1|10.0.0.1|40001|\r\n");
    EXPECT_EQ(pEprt.protocol, "FTP");
    EXPECT_EQ(pEprt.app_text, "EPRT");
    EXPECT_NE(findField(pEprt.fields, "Active address: 10.0.0.1"), nullptr);
    EXPECT_NE(findField(pEprt.fields, "Active port: 40001"), nullptr);
}

TEST(FtpDissect, StaticFtpDataPort20) {
    // Port 20 = 0x0014
    const std::string fileData = "150 Opening BINARY mode data connection\r\nFile content here...";
    const auto pkt = support::parse(support::tcpPacket("0a000001", "0a000002", "0014", "c350", "00000001", "00000001", "18", fileData));
    EXPECT_EQ(pkt.protocol, "FTP-DATA");
    EXPECT_NE(pkt.info.find("FTP Data:"), std::string::npos);
    EXPECT_TRUE(matches("ftp_data", pkt));
    EXPECT_NE(findField(pkt.fields, "FTP Data"), nullptr);
}

TEST(FtpDissect, DynamicDataPortTracking) {
    packet::PacketParser parser;

    // 1. Server responds with PASV indicating port 50000 (0xc350)
    packet::PacketInfo p1(1);
    const auto f1 = support::tcpPacket("0a000002", "0a000001", "0015", "d000", "00000001", "00000001", "18", "227 Entering Passive Mode (10,0,0,2,195,80)\r\n");
    parser.parsePacket(p1, f1, dissect::ParseMode::Summary);
    EXPECT_EQ(p1.protocol, "FTP");
    EXPECT_TRUE(parser.sessions().hasFtpDataPort(50000));

    // 2. Data transferred on dynamic port 50000 (0xc350)
    packet::PacketInfo p2(2);
    const auto f2 = support::tcpPacket("0a000002", "0a000001", "c350", "d001", "00000001", "00000001", "18", "Listing file1.txt\r\nfile2.txt\r\n");
    parser.parsePacket(p2, f2, dissect::ParseMode::Summary);
    EXPECT_EQ(p2.protocol, "FTP-DATA");
    EXPECT_TRUE(matches("ftp_data", p2));

    // 3. Replay mode builds full field tree for packet 2
    packet::PacketInfo p2Replay(2);
    p2Replay.protocol = p2.protocol; // like buildPacketDetails does
    parser.parsePacket(p2Replay, f2, dissect::ParseMode::Replay);
    EXPECT_EQ(p2Replay.protocol, "FTP-DATA");
    EXPECT_NE(findField(p2Replay.fields, "FTP Data"), nullptr);
}

TEST(FtpDissect, MultilineResponse) {
    const std::string multiline =
        "230-Welcome to the FTP server!\r\n"
        "230-Please read the README.\r\n"
        "230 User logged in, proceed.\r\n";
    const auto pkt = ftpTcp(multiline, "0015", "c350");
    EXPECT_EQ(pkt.protocol, "FTP");
    EXPECT_EQ(pkt.app_code, 230);
    EXPECT_NE(findField(pkt.fields, "Response: 230-Welcome to the FTP server!"), nullptr);
    EXPECT_NE(findField(pkt.fields, "Response: 230 User logged in, proceed."), nullptr);
    EXPECT_NE(findField(pkt.fields, "more lines to follow (-)"), nullptr);
    EXPECT_NE(findField(pkt.fields, "end of response ( )"), nullptr);
}

TEST(FtpDissect, FuzzResistance) {
    std::mt19937 rng(54321);
    std::uniform_int_distribution<int> byteDist(0, 255);
    std::uniform_int_distribution<size_t> lenDist(1, 200);

    for (int iter = 0; iter < 1000; ++iter) {
        const size_t len = lenDist(rng);
        std::string payload;
        payload.reserve(len);
        for (size_t b = 0; b < len; ++b) {
            payload.push_back(static_cast<char>(byteDist(rng)));
        }

        const auto frame = support::tcpPacket("0a000001", "0a000002", "c350", "0015", "00000001", "00000001", "18", payload);
        const auto pkt = support::parse(frame);
        EXPECT_EQ(pkt.protocol, "FTP");
        std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
            EXPECT_LE(size_t(f.offset) + f.length, frame.size()) << f.text;
            for (const auto &c : f.children) check(c);
        };
        for (const auto &l : pkt.fields) check(l);
    }
}
