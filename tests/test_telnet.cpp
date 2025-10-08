#include <gtest/gtest.h>

#include "dissect/protocols.h"
#include "filter/filter.h"
#include "support.h"

#include <random>
#include <string>

namespace {

packet::PacketInfo telnetTcp(const std::string &payload) {
    return support::parse(support::tcpPacket("0a000001", "0a000002", "c350", "0017", "00000001", "00000001", "18", payload));
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

TEST(TelnetDissect, SimplePlainText) {
    const std::string text = "login: admin\r\n";
    const auto pkt = telnetTcp(text);
    EXPECT_EQ(pkt.protocol, "Telnet");
    EXPECT_NE(pkt.info.find("[ Telnet data: login: admin"), std::string::npos);
    EXPECT_TRUE(matches("telnet", pkt));
    EXPECT_TRUE(matches("telnet.data contains \"login\"", pkt));
    EXPECT_NE(findField(pkt.fields, "Data (14 bytes)"), nullptr);
}

TEST(TelnetDissect, CommandNegotiations) {
    // IAC DO ECHO (0xFF 0xFD 0x01) + IAC WILL SUPPRESS-GO-AHEAD (0xFF 0xFB 0x03)
    const std::string payload = "\xff\xfd\x01\xff\xfb\x03";
    const auto pkt = telnetTcp(payload);
    EXPECT_EQ(pkt.protocol, "Telnet");
    EXPECT_NE(pkt.info.find("Do Echo"), std::string::npos);
    EXPECT_NE(pkt.info.find("Will Suppress Go Ahead"), std::string::npos);
    EXPECT_EQ(pkt.app_type, 253); // DO
    EXPECT_EQ(pkt.app_code, 1);   // Echo
    EXPECT_TRUE(matches("telnet.cmd == 253", pkt));
    EXPECT_TRUE(matches("telnet.subcmd == 1", pkt));

    EXPECT_NE(findField(pkt.fields, "Do Echo"), nullptr);
    EXPECT_NE(findField(pkt.fields, "Will Suppress Go Ahead"), nullptr);
    EXPECT_NE(findField(pkt.fields, "Command: Do (253)"), nullptr);
    EXPECT_NE(findField(pkt.fields, "Option: Echo (1)"), nullptr);
}

TEST(TelnetDissect, SubnegotiationNaws) {
    // IAC SB NAWS (31) 0x00 0x50 (80) 0x00 0x18 (24) IAC SE
    const std::string payload("\xff\xfa\x1f\x00\x50\x00\x18\xff\xf0", 9);
    const auto pkt = telnetTcp(payload);
    EXPECT_EQ(pkt.protocol, "Telnet");
    EXPECT_NE(pkt.info.find("NAWS"), std::string::npos);
    EXPECT_NE(pkt.info.find("80"), std::string::npos);
    EXPECT_NE(pkt.info.find("24"), std::string::npos);
    EXPECT_EQ(pkt.app_type, 250); // SB
    EXPECT_EQ(pkt.app_code, 31);  // NAWS
    EXPECT_TRUE(matches("telnet.cmd == 250", pkt));
    EXPECT_TRUE(matches("telnet.subcmd == 31", pkt));

    const auto *sb = findField(pkt.fields, "Subnegotiation: Negotiate About Window Size");
    ASSERT_NE(sb, nullptr);
    EXPECT_NE(findField(sb->children, "Width: 80"), nullptr);
    EXPECT_NE(findField(sb->children, "Height: 24"), nullptr);
    EXPECT_NE(findField(sb->children, "Subnegotiation End (SE)"), nullptr);
}

TEST(TelnetDissect, SubnegotiationTerminalTypeAndSpeed) {
    // IAC SB TERMINAL-TYPE (24) IS (0) "xterm-256color" IAC SE
    const std::string payload = std::string("\xff\xfa\x18\x00xterm-256color\xff\xf0", 22);
    const auto pkt = telnetTcp(payload);
    EXPECT_EQ(pkt.protocol, "Telnet");
    EXPECT_NE(pkt.info.find("Terminal Type IS xterm-256color"), std::string::npos);
    EXPECT_EQ(pkt.app_type, 250);
    EXPECT_EQ(pkt.app_code, 24);

    const auto *sb = findField(pkt.fields, "Subnegotiation: Terminal Type");
    ASSERT_NE(sb, nullptr);
}

TEST(TelnetDissect, EscapedLiteralIacAndCommands) {
    // Literal 0xFF 0xFF followed by IAC AYT (246)
    const std::string payload = "\xff\xff\xff\xf6";
    const auto pkt = telnetTcp(payload);
    EXPECT_EQ(pkt.protocol, "Telnet");
    EXPECT_NE(pkt.info.find("Are You There"), std::string::npos);
    EXPECT_NE(findField(pkt.fields, "Literal Data: 0xFF"), nullptr);
    EXPECT_NE(findField(pkt.fields, "Command: Are You There (AYT) (246)"), nullptr);
}

TEST(TelnetDissect, TruncatedAndUnterminated) {
    // Truncated IAC
    const auto p1 = telnetTcp("\xff");
    EXPECT_EQ(p1.protocol, "Telnet");
    EXPECT_NE(p1.info.find("truncated"), std::string::npos);

    // Truncated DO command (missing option)
    const auto p2 = telnetTcp("\xff\xfd");
    EXPECT_EQ(p2.protocol, "Telnet");
    EXPECT_NE(p2.info.find("truncated"), std::string::npos);

    // Unterminated SB
    const auto p3 = telnetTcp("\xff\xfa\x18\x00vt100");
    EXPECT_EQ(p3.protocol, "Telnet");
    EXPECT_NE(p3.info.find("unterminated"), std::string::npos);
}

TEST(TelnetDissect, FuzzResistance) {
    std::mt19937 rng(42);
    std::uniform_int_distribution<int> byteDist(0, 255);
    std::uniform_int_distribution<size_t> lenDist(1, 128);

    for (int iter = 0; iter < 1000; ++iter) {
        const size_t len = lenDist(rng);
        std::string payload;
        payload.reserve(len);
        // Half the time, force IAC prefix to fuzz command parser
        if (iter % 2 == 0) payload.push_back(static_cast<char>(0xff));
        for (size_t b = payload.size(); b < len; ++b) {
            payload.push_back(static_cast<char>(byteDist(rng)));
        }

        const auto frame = support::tcpPacket("0a000001", "0a000002", "c350", "0017", "00000001", "00000001", "18", payload);
        const auto pkt = support::parse(frame);
        EXPECT_EQ(pkt.protocol, "Telnet");
        std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
            EXPECT_LE(size_t(f.offset) + f.length, frame.size()) << f.text;
            for (const auto &c : f.children) check(c);
        };
        for (const auto &l : pkt.fields) check(l);
    }
}
