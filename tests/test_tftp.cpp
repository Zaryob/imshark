#include <gtest/gtest.h>

#include "dissect/protocols.h"
#include "dissect/session.h"
#include "filter/filter.h"
#include "packet/packet_parser.h"
#include "support.h"

#include <random>
#include <string>

namespace {

packet::PacketInfo tftpUdp(const std::string &payload, const char *sport = "c350", const char *dport = "0045") {
    // 0045 = 69 (TFTP port)
    return support::parse(support::udpPacket("0a000001", "0a000002", sport, dport, payload));
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

TEST(TftpDissect, ReadRequestAndOptions) {
    // Opcode 1 (RRQ) + "rfc1350.txt\0" + "octet\0" + "blksize\0" + "1428\0"
    std::string payload = std::string("\x00\x01" "rfc1350.txt\0octet\0blksize\0" "1428\0", 34);
    const auto pkt = tftpUdp(payload);
    EXPECT_EQ(pkt.protocol, "TFTP");
    EXPECT_NE(pkt.info.find("Read Request, File: rfc1350.txt, Mode: octet"), std::string::npos);
    EXPECT_EQ(pkt.app_type, 1);
    EXPECT_EQ(pkt.app_text, "rfc1350.txt");
    EXPECT_EQ(pkt.app_text2, "octet");
    EXPECT_TRUE(matches("tftp", pkt));
    EXPECT_TRUE(matches("tftp.opcode == 1", pkt));
    EXPECT_TRUE(matches("tftp.source_file == \"rfc1350.txt\"", pkt));
    EXPECT_TRUE(matches("tftp.mode == \"octet\"", pkt));

    EXPECT_NE(findField(pkt.fields, "Source File: rfc1350.txt"), nullptr);
    EXPECT_NE(findField(pkt.fields, "Type: octet"), nullptr);
    EXPECT_NE(findField(pkt.fields, "Option: blksize = 1428"), nullptr);
}

TEST(TftpDissect, WriteRequest) {
    // Opcode 2 (WRQ) + "upload.bin\0" + "netascii\0"
    std::string payload = std::string("\x00\x02" "upload.bin\0netascii\0", 22);
    const auto pkt = tftpUdp(payload);
    EXPECT_EQ(pkt.protocol, "TFTP");
    EXPECT_NE(pkt.info.find("Write Request, File: upload.bin"), std::string::npos);
    EXPECT_EQ(pkt.app_type, 2);
    EXPECT_TRUE(matches("tftp.opcode == 2", pkt));
    EXPECT_TRUE(matches("tftp.source_file == \"upload.bin\"", pkt));
}

TEST(TftpDissect, DataAndAck) {
    // DATA: Opcode 3 + Block 1 (0x0001) + Data "Payload123"
    std::string dataPayload = std::string("\x00\x03\x00\x01" "Payload123", 14);
    const auto pData = tftpUdp(dataPayload);
    EXPECT_EQ(pData.protocol, "TFTP");
    EXPECT_NE(pData.info.find("Data Packet, Block: 1 (10 bytes)"), std::string::npos);
    EXPECT_EQ(pData.app_type, 3);
    EXPECT_EQ(pData.app_code, 1);
    EXPECT_TRUE(matches("tftp.opcode == 3", pData));
    EXPECT_TRUE(matches("tftp.block == 1", pData));
    EXPECT_NE(findField(pData.fields, "Block: 1"), nullptr);
    EXPECT_NE(findField(pData.fields, "Data (10 bytes)"), nullptr);

    // ACK: Opcode 4 + Block 1 (0x0001)
    std::string ackPayload = std::string("\x00\x04\x00\x01", 4);
    const auto pAck = tftpUdp(ackPayload);
    EXPECT_EQ(pAck.protocol, "TFTP");
    EXPECT_EQ(pAck.info, "Acknowledgement, Block: 1");
    EXPECT_EQ(pAck.app_type, 4);
    EXPECT_EQ(pAck.app_code, 1);
    EXPECT_TRUE(matches("tftp.opcode == 4", pAck));
    EXPECT_TRUE(matches("tftp.block == 1", pAck));
    EXPECT_NE(findField(pAck.fields, "Block: 1"), nullptr);
}

TEST(TftpDissect, ErrorAndOack) {
    // ERROR: Opcode 5 + ErrorCode 1 (0x0001) + "File not found\0"
    std::string errPayload = std::string("\x00\x05\x00\x01" "File not found\0", 19);
    const auto pErr = tftpUdp(errPayload);
    EXPECT_EQ(pErr.protocol, "TFTP");
    EXPECT_NE(pErr.info.find("Error Code, Code: 1, Message: File not found"), std::string::npos);
    EXPECT_EQ(pErr.app_type, 5);
    EXPECT_EQ(pErr.app_code, 1);
    EXPECT_TRUE(matches("tftp.error.code == 1", pErr));
    EXPECT_NE(findField(pErr.fields, "Error Code: File not found (1)"), nullptr);
    EXPECT_NE(findField(pErr.fields, "Error Message: File not found"), nullptr);

    // OACK: Opcode 6 + "blksize\0" + "1428\0"
    std::string oackPayload = std::string("\x00\x06" "blksize\0" "1428\0", 15);
    const auto pOack = tftpUdp(oackPayload);
    EXPECT_EQ(pOack.protocol, "TFTP");
    EXPECT_NE(pOack.info.find("Option Acknowledgement (blksize=1428)"), std::string::npos);
    EXPECT_EQ(pOack.app_type, 6);
    EXPECT_NE(findField(pOack.fields, "Option: blksize = 1428"), nullptr);
}

TEST(TftpDissect, DynamicTidConversationTracking) {
    packet::PacketParser parser;

    // 1. Client port 50123 (0xc3cb) -> Server port 69 (0x0045): RRQ
    std::string rrq = std::string("\x00\x01" "kernel.bin\0octet\0", 18);
    auto f1 = support::udpPacket("0a000001", "0a000002", "c3cb", "0045", rrq);
    packet::PacketInfo p1(1);
    parser.parsePacket(p1, f1, dissect::ParseMode::Summary);
    EXPECT_EQ(p1.protocol, "TFTP");
    ASSERT_EQ(parser.sessions().tftpSessions.size(), 1u);
    EXPECT_EQ(parser.sessions().tftpSessions[0].clientPort, 50123);

    // 2. Server port 61456 (0xf010) (TID) -> Client port 50123 (0xc3cb): DATA block 1
    std::string data = std::string("\x00\x03\x00\x01" "KernelData...", 17);
    auto f2 = support::udpPacket("0a000002", "0a000001", "f010", "c3cb", data);
    packet::PacketInfo p2(2);
    parser.parsePacket(p2, f2, dissect::ParseMode::Summary);
    EXPECT_EQ(p2.protocol, "TFTP");
    EXPECT_EQ(parser.sessions().tftpSessions[0].serverPort, 61456);

    // 3. Client port 50123 -> Server port 61456: ACK block 1
    std::string ack = std::string("\x00\x04\x00\x01", 4);
    auto f3 = support::udpPacket("0a000001", "0a000002", "c3cb", "f010", ack);
    packet::PacketInfo p3(3);
    parser.parsePacket(p3, f3, dissect::ParseMode::Summary);
    EXPECT_EQ(p3.protocol, "TFTP");

    // 4. Replay mode reproduces TFTP and details
    packet::PacketInfo p2Replay(2);
    p2Replay.protocol = p2.protocol;
    parser.parsePacket(p2Replay, f2, dissect::ParseMode::Replay);
    EXPECT_EQ(p2Replay.protocol, "TFTP");
    EXPECT_NE(findField(p2Replay.fields, "Block: 1"), nullptr);
}

TEST(TftpDissect, FuzzResistance) {
    std::mt19937 rng(9876);
    std::uniform_int_distribution<int> byteDist(0, 255);
    std::uniform_int_distribution<size_t> lenDist(0, 100);

    for (int iter = 0; iter < 1000; ++iter) {
        const size_t len = lenDist(rng);
        std::string payload;
        payload.reserve(len);
        for (size_t b = 0; b < len; ++b) {
            payload.push_back(static_cast<char>(byteDist(rng)));
        }

        const auto frame = support::udpPacket("0a000001", "0a000002", "c350", "0045", payload);
        const auto pkt = support::parse(frame);
        EXPECT_EQ(pkt.protocol, "TFTP");
        std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
            EXPECT_LE(size_t(f.offset) + f.length, frame.size()) << f.text;
            for (const auto &c : f.children) check(c);
        };
        for (const auto &l : pkt.fields) check(l);
    }
}
