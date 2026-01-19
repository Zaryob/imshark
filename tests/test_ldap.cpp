#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>

#include "support.h"

using support::parse;

namespace {
    // Wrap TCP payload in IPv4 + Ethernet
    std::vector<char> makeTcpPacket(uint16_t sport, uint16_t dport, const std::vector<uint8_t> &tcpPayload) {
        std::vector<uint8_t> frame = {
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
            0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
            0x08, 0x00
        };

        size_t ipTotalLen = 20 + 20 + tcpPayload.size();
        std::vector<uint8_t> ip = {
            0x45, 0x00, static_cast<uint8_t>(ipTotalLen >> 8), static_cast<uint8_t>(ipTotalLen & 0xff),
            0x00, 0x01, 0x00, 0x00,
            64, 6, 0x00, 0x00,
            10, 0, 0, 1,
            10, 0, 0, 2
        };

        uint32_t csum = 0;
        for (size_t i = 0; i < ip.size(); i += 2) csum += (ip[i] << 8) | ip[i + 1];
        while (csum >> 16) csum = (csum & 0xffff) + (csum >> 16);
        uint16_t folded = static_cast<uint16_t>(~csum);
        ip[10] = static_cast<uint8_t>(folded >> 8);
        ip[11] = static_cast<uint8_t>(folded & 0xff);

        std::vector<uint8_t> tcp = {
            static_cast<uint8_t>(sport >> 8), static_cast<uint8_t>(sport & 0xff),
            static_cast<uint8_t>(dport >> 8), static_cast<uint8_t>(dport & 0xff),
            0, 0, 0, 1, // Seq 1
            0, 0, 0, 1, // Ack 1
            0x50, 0x18, 0x20, 0x00, // ACK + PSH
            0, 0, 0, 0 // checksum placeholder
        };

        // Pseudo header checksum for TCP
        std::vector<uint8_t> pseudo = {
            10, 0, 0, 1,
            10, 0, 0, 2,
            0, 6,
            static_cast<uint8_t>((20 + tcpPayload.size()) >> 8), static_cast<uint8_t>((20 + tcpPayload.size()) & 0xff)
        };
        uint32_t tcsum = 0;
        for (size_t i = 0; i < pseudo.size(); i += 2) tcsum += (pseudo[i] << 8) | pseudo[i + 1];
        for (size_t i = 0; i < tcp.size(); i += 2) tcsum += (tcp[i] << 8) | tcp[i + 1];
        for (size_t i = 0; i + 1 < tcpPayload.size(); i += 2) tcsum += (tcpPayload[i] << 8) | tcpPayload[i + 1];
        if (tcpPayload.size() % 2 != 0) tcsum += static_cast<uint32_t>(tcpPayload.back()) << 8;

        while (tcsum >> 16) tcsum = (tcsum & 0xffff) + (tcsum >> 16);
        uint16_t tfolded = static_cast<uint16_t>(~tcsum);
        tcp[16] = static_cast<uint8_t>(tfolded >> 8);
        tcp[17] = static_cast<uint8_t>(tfolded & 0xff);

        frame.insert(frame.end(), ip.begin(), ip.end());
        frame.insert(frame.end(), tcp.begin(), tcp.end());
        frame.insert(frame.end(), tcpPayload.begin(), tcpPayload.end());
        return std::vector<char>(frame.begin(), frame.end());
    }
} // namespace

TEST(Ldap, BindRequestMessage) {
    // LDAP Message: SEQUENCE { MessageID=1, BindRequest [APPLICATION 0] { version=3, name="cn=admin,dc=example,dc=com", simple="secret" } }
    // 0x30, length
    //   0x02, 0x01, 0x01 (INTEGER 1)
    //   0x60, length (APPLICATION 0 constructed)
    //     0x02, 0x01, 0x03 (version 3)
    //     0x04, 0x1d, "cn=admin,dc=example,dc=com"
    //     0x80, 0x06, "secret" (context-specific primitive 0)
    std::string name = "cn=admin,dc=example,dc=com";
    std::vector<uint8_t> bindReq = {
        0x02, 0x01, 0x03,
        0x04, static_cast<uint8_t>(name.size())
    };
    bindReq.insert(bindReq.end(), name.begin(), name.end());
    bindReq.push_back(0x80);
    bindReq.push_back(0x06);
    std::string pass = "secret";
    bindReq.insert(bindReq.end(), pass.begin(), pass.end());

    std::vector<uint8_t> ldapMsg = {
        0x30, static_cast<uint8_t>(3 + 2 + bindReq.size()),
        0x02, 0x01, 0x01, // MsgID = 1
        0x60, static_cast<uint8_t>(bindReq.size()) // [APPLICATION 0]
    };
    ldapMsg.insert(ldapMsg.end(), bindReq.begin(), bindReq.end());

    auto pkt = parse(makeTcpPacket(54321, 389, ldapMsg));
    EXPECT_EQ(pkt.protocol, "LDAP");
    EXPECT_EQ(pkt.tcp_pdu_start, 1U); // MsgID
    EXPECT_EQ(pkt.app_type, 0U); // BindRequest
    EXPECT_EQ(pkt.app_text, name);
    EXPECT_NE(pkt.info.find("BindRequest"), std::string::npos);

    auto f = filter::Filter::compile("ldap && ldap.message_id == 1 && ldap.protocol_op == 0");
    ASSERT_TRUE(f.ok);
    EXPECT_TRUE(f.filter.matches(pkt));
}

TEST(Ldap, SearchResultDoneMessage) {
    // LDAP Message: SEQUENCE { MessageID=2, SearchResultDone [APPLICATION 5] { resultCode=0 (success), matchedDN="", diagnosticMessage="" } }
    std::vector<uint8_t> doneBody = {
        0x0a, 0x01, 0x00, // ENUMERATED 0 (success)
        0x04, 0x00,       // matchedDN = ""
        0x04, 0x00        // diagnostic = ""
    };
    std::vector<uint8_t> ldapMsg = {
        0x30, static_cast<uint8_t>(3 + 2 + doneBody.size()),
        0x02, 0x01, 0x02, // MsgID = 2
        0x65, static_cast<uint8_t>(doneBody.size()) // [APPLICATION 5]
    };
    ldapMsg.insert(ldapMsg.end(), doneBody.begin(), doneBody.end());

    auto pkt = parse(makeTcpPacket(389, 54321, ldapMsg));
    EXPECT_EQ(pkt.protocol, "LDAP");
    EXPECT_EQ(pkt.tcp_pdu_start, 2U);
    EXPECT_EQ(pkt.app_type, 5U); // SearchResultDone
    EXPECT_NE(pkt.info.find("SearchResultDone"), std::string::npos);
    EXPECT_NE(pkt.info.find("result=success"), std::string::npos);
}
