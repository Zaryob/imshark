// Choosing the protocol of a port: content based recognition (DNS on any port), Decode As, STARTTLS.
#include <gtest/gtest.h>

#include <functional>
#include <random>

#include <core.h>
#include <dissect/registry.h>

#include "support.h"

using support::hex;

namespace {
    std::string bytes(const std::string &hexText) { auto v = hex(hexText); return std::string(v.begin(), v.end()); }

    // DNS query for a.test A
    const std::string kDnsQuery = "1234" "0100" "0001" "0000" "0000" "0000" "01" "61" "04" "74657374" "00" "0001" "0001";

    packet::PacketInfo udpTo(const std::string &port, const std::string &payloadHex, const dissect::Registry &registry = dissect::Registry::builtin()) {
        packet::PacketParser parser(registry);
        packet::PacketInfo info(1);
        auto frame = support::udpPacket("0a000001", "0a000002", "c350", port, bytes(payloadHex));
        parser.parsePacket(info, frame, dissect::ParseMode::Full);
        return info;
    }

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto r = find(f.children, prefix)) return r;
        }
        return nullptr;
    }

    std::string u16(unsigned v) { char b[8]; std::snprintf(b, sizeof b, "%04x", v); return b; }
}

TEST(ContentRecognition, DnsOnAnyUdpPort) {
    const auto p = udpTo("2710", kDnsQuery);
    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_EQ(p.info, "Standard query 0x1234 A a.test");
    EXPECT_NE(find(p.fields, "Domain Name System (query)"), nullptr);
    EXPECT_EQ(udpTo("0035", kDnsQuery).info, p.info) << "the standard port decodes the same";
}

TEST(ContentRecognition, DnsResponsesWithRecordsAreRecognisedToo) {
    const std::string response = "1234" "8180" "0001" "0001" "0000" "0000" "01" "61" "04" "74657374" "00" "0001" "0001" "c00c" "0001" "0001" "0000012c" "0004" "0a000005";
    const auto p = udpTo("2710", response);
    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_NE(p.info.find("response 0x1234"), std::string::npos) << p.info;
}

TEST(ContentRecognition, OtherUdpPayloadsAreNotClaimed) {
    EXPECT_EQ(udpTo("2710", "68656c6c6f20776f726c64210a").protocol, "UDP") << "text";
    EXPECT_EQ(udpTo("2710", kDnsQuery + "00").protocol, "UDP") << "a trailing byte: not a clean DNS message";
    EXPECT_EQ(udpTo("2710", kDnsQuery.substr(0, kDnsQuery.size() - 4)).protocol, "UDP") << "truncated question";
    EXPECT_EQ(udpTo("2710", "1234" "0100" "0000" "0000" "0000" "0000").protocol, "UDP") << "a query without a question";
    EXPECT_EQ(udpTo("2710", "1234" "0140" "0001" "0000" "0000" "0000" "0161" "00" "0001" "0001").protocol, "UDP") << "reserved Z bit set";
    EXPECT_EQ(udpTo("2710", "1234" "0100" "0001" "0000" "0000" "0000" "0161" "00" "0001" "0063").protocol, "UDP") << "unknown class";
    EXPECT_EQ(udpTo("2710", "1234" "7900" "0001" "0000" "0000" "0000" "0161" "00" "0001" "0001").protocol, "UDP") << "reserved opcode 15";
}

TEST(ContentRecognition, RandomDatagramsAreNeverMistakenForDns) {
    std::mt19937 rng(99);
    int claimed = 0;
    for (int i = 0; i < 20000; ++i) {
        std::string payload(12 + rng() % 60, '\0');
        for (auto &c: payload) c = static_cast<char>(rng());
        if (rng() % 2) { payload[4] = 0; payload[5] = 1; }    // even with a plausible question count
        packet::PacketParser parser;
        packet::PacketInfo info(1);
        auto frame = support::udpPacket("0a000001", "0a000002", "c350", "2710", payload);
        parser.parsePacket(info, frame, dissect::ParseMode::Summary);
        claimed += info.protocol == "DNS";
    }
    EXPECT_EQ(claimed, 0);
}

TEST(ContentRecognition, DnsOverTcpOnAnyPortAndSplitAcrossSegments) {
    const std::string msg = bytes(kDnsQuery);
    const std::string framed = bytes(u16(static_cast<unsigned>(msg.size()))) + msg;
    auto seg = [&](uint32_t seq, const std::string &data) {
        char s[16];
        std::snprintf(s, sizeof s, "%08x", seq);
        return support::tcpPacket("0a000001", "0a000002", "c350", "1f95", s, "00000001", "18", data);   // port 8085
    };
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    const std::string path = support::writeTemp("dnsport.pcap", support::pcapBytes({seg(1000, framed.substr(0, 9)), seg(1009, framed.substr(9))}));
    ASSERT_TRUE(fp.processPcapFile(path, packets, message)) << message;
    EXPECT_EQ(packets[1].protocol, "DNS");
    EXPECT_EQ(packets[1].tcp_pdu_state, 2);
    EXPECT_EQ(packets[0].tcp_pdu_state, 4) << "the first segment is decoded as far as it goes";
    std::remove(path.c_str());

    // plain text and binary data on the same port stay TCP
    const std::vector<std::string> junk = {"hello world, this is not dns at all", std::string("\x00\x30\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00junk", 18)};
    for (const auto &payload: junk) {
        EXPECT_EQ(support::parse(support::tcpPacket("0a000001", "0a000002", "c350", "1f95", "00000001", "00000001", "18", payload)).protocol, "TCP");
    }
}

TEST(DecodeAs, ChoosesTheProtocolOfAPort) {
    dissect::Registry r = dissect::Registry::builtin();
    const std::string ntpClient = "23" "00" "06" "ec" + std::string(88, '0');
    EXPECT_EQ(udpTo("2710", ntpClient, r).protocol, "UDP");
    std::string error;
    ASSERT_TRUE(r.decodeAs(false, 10000, "NTP", &error)) << error;
    EXPECT_EQ(udpTo("2710", ntpClient, r).protocol, "NTP");
    EXPECT_EQ(udpTo("2710", ntpClient).protocol, "UDP") << "the shared built-in registry is not changed";

    // replacing a standard port: DHCP's port 67 now decodes as NTP
    ASSERT_TRUE(r.decodeAs(false, 67, "NTP", &error)) << error;
    EXPECT_EQ(udpTo("0043", ntpClient, r).protocol, "NTP");
}

TEST(DecodeAs, TcpStreamProtocolsReplaceThePortsOwnDissector) {
    dissect::Registry r = dissect::Registry::builtin();
    std::string error;
    ASSERT_TRUE(r.decodeAs(true, 53, "HTTP", &error)) << error;       // port 53 now carries HTTP, no longer DNS
    ASSERT_TRUE(r.decodeAs(true, 9090, "Telnet", &error)) << error;
    core::FileProcessor fp(r);
    std::vector<packet::PacketInfo> packets;
    std::string message;
    const std::string path = support::writeTemp("decodeas.pcap", support::pcapBytes({
        support::tcpPacket("0a000001", "0a000002", "c350", "0035", "00000001", "00000001", "18", "GET / HTTP/1.1\r\nHost: x\r\n\r\n"),
        support::tcpPacket("0a000001", "0a000002", "c350", "2382", "00000001", "00000001", "18", "login: "),
    }));
    ASSERT_TRUE(fp.processPcapFile(path, packets, message)) << message;
    EXPECT_EQ(packets[0].protocol, "HTTP");
    EXPECT_EQ(packets[1].protocol, "Telnet");
    packet::PacketInfo d;
    ASSERT_TRUE(core::buildPacketDetails(path, packets[0], d, &packets, &fp.captureInfo(), &r));
    EXPECT_EQ(d.protocol, "HTTP");
    EXPECT_NE(find(d.fields, "Hypertext Transfer Protocol"), nullptr);
    std::remove(path.c_str());
}

TEST(DecodeAs, RejectsWhatDoesNotExist) {
    dissect::Registry r = dissect::Registry::builtin();
    std::string error;
    EXPECT_FALSE(r.decodeAs(false, 1000, "Nonsense", &error));
    EXPECT_NE(error.find("No protocol"), std::string::npos);
    EXPECT_FALSE(r.decodeAs(false, 1000, "HTTP", &error)) << "HTTP has no UDP form";
    EXPECT_FALSE(r.decodeAs(true, 1000, "DHCP", &error)) << "DHCP has no TCP form";
    EXPECT_FALSE(r.decodeAs(true, 0, "HTTP", &error));
    const auto udp = r.protocolNames(false), tcp = r.protocolNames(true);
    EXPECT_NE(std::find(udp.begin(), udp.end(), "DNS"), udp.end());
    EXPECT_EQ(std::find(udp.begin(), udp.end(), "TLS"), udp.end());
    EXPECT_NE(std::find(tcp.begin(), tcp.end(), "TLS"), tcp.end());
    EXPECT_TRUE(std::is_sorted(tcp.begin(), tcp.end()));
}

TEST(Starttls, SmtpSessionSwitchesToTlsInTheSameStream) {
    auto seg = [&](bool fromClient, uint32_t seq, const std::string &data) {
        char s[16];
        std::snprintf(s, sizeof s, "%08x", seq);
        return fromClient ? support::tcpPacket("0a000001", "0a000002", "c350", "0019", s, "00000001", "18", data)
                          : support::tcpPacket("0a000002", "0a000001", "0019", "c350", s, "00000001", "18", data);
    };
    const std::string hello = bytes("160301" "0004" "01000000");   // a TLS record holding the start of a handshake message
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    const std::string path = support::writeTemp("starttls.pcap", support::pcapBytes({
        seg(false, 5000, "220 mail.example.org ESMTP\r\n"),
        seg(true, 1000, "EHLO client\r\n"),
        seg(false, 5027, "250-STARTTLS\r\n250 OK\r\n"),
        seg(true, 1013, "STARTTLS\r\n"),
        seg(false, 5049, "220 Ready to start TLS\r\n"),
        seg(true, 1023, hello),
        seg(false, 5073, bytes("160303" "0004" "02000000")),
    }));
    ASSERT_TRUE(fp.processPcapFile(path, packets, message)) << message;
    for (int i = 0; i < 5; ++i) EXPECT_EQ(packets[i].protocol, "SMTP") << i;
    EXPECT_EQ(packets[5].protocol, "TLS");
    EXPECT_EQ(packets[6].protocol, "TLS");
    std::remove(path.c_str());
}
