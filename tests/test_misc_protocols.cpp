#include <gtest/gtest.h>

#include <functional>
#include <random>

#include <filter/filter.h>

#include "support.h"

using support::hex;

namespace {
    std::string u32(unsigned v) { char b[16]; std::snprintf(b, sizeof b, "%08x", v); return b; }
    std::string zeros(size_t bytes) { return std::string(bytes * 2, '0'); }

    std::string bytes(const std::string &hexText) { auto v = hex(hexText); return std::string(v.begin(), v.end()); }

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto r = find(f.children, prefix)) return r;
        }
        return nullptr;
    }

    bool matches(const std::string &expr, const packet::PacketInfo &p) {
        auto r = filter::Filter::compile(expr);
        EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
        return r.ok && r.filter.matches(p);
    }

    void expectRangesInside(const packet::PacketInfo &p, size_t frameSize) {
        std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
            EXPECT_LE(size_t(f.offset) + f.length, frameSize) << f.text;
            for (const auto &c: f.children) check(c);
        };
        for (const auto &l: p.fields) check(l);
    }

    // ---- DHCP
    std::string dhcpFixed(unsigned op, unsigned xid, const std::string &yiaddr = "00000000") {
        return u32(0) .substr(0, 0) + std::string(op == 1 ? "01" : "02") + "01" "06" "00" + u32(xid) + "0000" "8000" "00000000" + yiaddr +
               "00000000" "00000000" "001122334455" + zeros(10) + zeros(64) + zeros(128);
    }
    packet::PacketInfo dhcp(const std::string &hexPayload, bool reply = false) {
        return support::parse(support::udpPacket(reply ? "0a000001" : "00000000", reply ? "0a000032" : "ffffffff", reply ? "0043" : "0044", reply ? "0044" : "0043", bytes(hexPayload)));
    }

    // ---- ICMP over IPv4 / IPv6
    std::vector<char> ipv4Packet(unsigned proto, const std::string &src, const std::string &dst, const std::string &payloadHex, unsigned ttl = 64) {
        char head[160];
        std::snprintf(head, sizeof head, "001122334455 aabbccddeeff 0800 4500%04zx 0000 0000 %02x%02x 0000 %s %s", 20 + payloadHex.size() / 2, ttl, proto, src.c_str(), dst.c_str());
        return hex(std::string(head) + payloadHex);
    }
    std::vector<char> ipv6Packet(unsigned next, const std::string &payloadHex) {
        char head[160];
        std::snprintf(head, sizeof head, "001122334455 aabbccddeeff 86dd 60000000 %04zx %02x 40 20010db8000000000000000000000001 20010db8000000000000000000000002", payloadHex.size() / 2, next);
        return hex(std::string(head) + payloadHex);
    }
} // namespace

TEST(Dhcp, DiscoverWithOptions) {
    const std::string options = "63825363" "350101" "0c05" + support::hexOf("host1") + "37040103060f" "3d07" "01001122334455" "ff";
    const auto p = dhcp(dhcpFixed(1, 0x3903f326) + options);
    EXPECT_EQ(p.protocol, "DHCP");
    EXPECT_EQ(p.info, "DHCP Discover - Transaction ID 0x3903f326");
    EXPECT_EQ(p.app_type, 1);
    EXPECT_EQ(p.app_text, "host1");
    EXPECT_TRUE(matches("dhcp.type == 1 && dhcp.option.hostname == \"host1\"", p));
    EXPECT_NE(find(p.fields, "Dynamic Host Configuration Protocol (Discover)"), nullptr);
    EXPECT_NE(find(p.fields, "Magic cookie: DHCP"), nullptr);
    EXPECT_NE(find(p.fields, "Option: (53) DHCP Message Type: Discover (1)"), nullptr);
    EXPECT_NE(find(p.fields, "Option: (12) Host Name: host1"), nullptr);
    EXPECT_NE(find(p.fields, "Option: (55) Parameter Request List: 1, 3, 6, 15"), nullptr);
    EXPECT_NE(find(p.fields, "Option: (61) Client identifier: type 1, 00:11:22:33:44:55"), nullptr);
    EXPECT_NE(find(p.fields, "Option: (255) End"), nullptr);
    expectRangesInside(p, 14 + 20 + 8 + 240 + 40);
}

TEST(Dhcp, OfferAckAndOtherTypes) {
    const std::string options = "63825363" "350102" "0104ffffff00" "0304" "0a000001" "0608" "0a000001" "08080808" "330400000e10" "36040a000001" "ff";
    const auto p = dhcp(dhcpFixed(2, 0x1234abcd, "0a000032") + options, true);
    EXPECT_EQ(p.info, "DHCP Offer - Transaction ID 0x1234abcd");
    EXPECT_NE(find(p.fields, "Your (client) IP address: 10.0.0.50"), nullptr);
    EXPECT_NE(find(p.fields, "Option: (1) Subnet Mask: 255.255.255.0"), nullptr);
    EXPECT_NE(find(p.fields, "Option: (3) Router: 10.0.0.1"), nullptr);
    EXPECT_NE(find(p.fields, "Option: (6) Domain Name Server: 10.0.0.1, 8.8.8.8"), nullptr);
    EXPECT_NE(find(p.fields, "Option: (51) IP Address Lease Time: 3600 seconds"), nullptr);
    EXPECT_NE(find(p.fields, "Option: (54) DHCP Server Identifier: 10.0.0.1"), nullptr);
    EXPECT_TRUE(matches("dhcp.type == 2", p));

    for (unsigned t = 3; t <= 8; ++t) {
        const auto r = dhcp(dhcpFixed(1, 1) + "63825363" + "3501" + u32(t).substr(6) + "ff");
        EXPECT_EQ(r.app_type, t);
        static const char *names[] = {"", "", "", "Request", "Decline", "ACK", "NAK", "Release", "Inform"};
        EXPECT_EQ(r.info, std::string("DHCP ") + names[t] + " - Transaction ID 0x1") << t;
    }
}

TEST(Dhcp, NoCookieNoOptionsAndDamagedOptions) {
    const auto bootp = dhcp(dhcpFixed(1, 0xabc));
    EXPECT_EQ(bootp.info, "DHCP Boot Request - Transaction ID 0xabc");
    EXPECT_EQ(find(bootp.fields, "Option:"), nullptr);
    EXPECT_EQ(dhcp(dhcpFixed(2, 7)).info, "DHCP Boot Reply - Transaction ID 0x7");

    const std::string full = dhcpFixed(1, 5) + "63825363" "350101" "0c05" + support::hexOf("host1") + "ff";
    for (size_t cut = 0; cut <= full.size() / 2; ++cut) {
        const auto p = dhcp(full.substr(0, cut * 2));
        if (cut < 236) EXPECT_NE(p.info.find("Malformed"), std::string::npos) << cut;
        expectRangesInside(p, 14 + 20 + 8 + cut);
    }
    // an option claiming more bytes than are left ends the parsing quietly
    const auto lying = dhcp(dhcpFixed(1, 5) + "63825363" "0cff" "6161");
    EXPECT_EQ(lying.protocol, "DHCP");
}

TEST(Ntp, ClientAndServerPackets) {
    const unsigned transmit = 1700000000u + 2208988800u;     // 2023-11-14 22:13:20 UTC in NTP seconds
    const std::string server = "24" "02" "06" "ec" "00000a8c" "00000b00" "0a000001" + zeros(8) + zeros(8) + zeros(8) + u32(transmit) + "80000000";
    const auto p = support::parse(support::udpPacket("0a000002", "0a000001", "007b", "007b", bytes(server)));
    EXPECT_EQ(p.protocol, "NTP");
    EXPECT_EQ(p.info, "NTP Version 4, server");
    EXPECT_EQ(p.app_type, 4);
    EXPECT_EQ(p.app_code, 2);
    EXPECT_EQ(p.app_flags, 4);
    EXPECT_TRUE(matches("ntp && ntp.mode == 4 && ntp.stratum == 2 && ntp.version == 4", p));
    EXPECT_NE(find(p.fields, "Network Time Protocol (server)"), nullptr);
    EXPECT_NE(find(p.fields, "Peer Clock Stratum: 2 (secondary reference)"), nullptr);
    EXPECT_NE(find(p.fields, "Reference ID: 10.0.0.1"), nullptr);
    EXPECT_NE(find(p.fields, "Transmit Timestamp: 2023-11-14 22:13:20.500000 UTC"), nullptr);
    EXPECT_NE(find(p.fields, "Origin Timestamp: Not set"), nullptr);
    EXPECT_NE(find(p.fields, "Peer Clock Precision: -20"), nullptr);

    const std::string client = "23" "00" "00" "00" + zeros(44);
    const auto c = support::parse(support::udpPacket("0a000001", "0a000002", "007b", "007b", bytes(client)));
    EXPECT_EQ(c.info, "NTP Version 4, client");
    EXPECT_NE(find(c.fields, "Peer Clock Stratum: 0 (unspecified or invalid)"), nullptr);

    const std::string gps = "24" "01" "06" "ec" + zeros(8) + "47505300" + zeros(32);
    EXPECT_NE(find(support::parse(support::udpPacket("0a000002", "0a000001", "007b", "007b", bytes(gps))).fields, "Reference ID: GPS"), nullptr) << "stratum 1 reference ids are text";

    const auto shortPacket = support::parse(support::udpPacket("0a000001", "0a000002", "007b", "007b", bytes("2300")));
    EXPECT_NE(shortPacket.info.find("Malformed"), std::string::npos);
}

TEST(Icmp, EchoRequestAndReply) {
    const auto req = support::parse(ipv4Packet(1, "0a000001", "0a000002", "08 00 0000 1234 0001" + support::hexOf("abcdefgh")));
    EXPECT_EQ(req.protocol, "ICMP");
    EXPECT_EQ(req.info, "Echo (ping) request  id=0x1234, seq=1, ttl=64");
    EXPECT_TRUE(matches("icmp.type == 8 && icmp && !icmpv6", req));
    EXPECT_NE(find(req.fields, "Type: 8 (Echo (ping) request)"), nullptr);
    EXPECT_NE(find(req.fields, "Identifier: 0x1234 (4660)"), nullptr);
    EXPECT_NE(find(req.fields, "Data (8 bytes)"), nullptr);
    const auto rep = support::parse(ipv4Packet(1, "0a000002", "0a000001", "00 00 0000 1234 0001", 128));
    EXPECT_EQ(rep.info, "Echo (ping) reply  id=0x1234, seq=1, ttl=128");
    EXPECT_TRUE(matches("icmp.type == 0 && icmp.code == 0", rep));
}

TEST(Icmp, ErrorMessagesQuoteTheOriginalPacket) {
    const std::string inner = "4500001c00000000 4011 0000 0a000002 08080808 c350 0035 0008 0000";   // UDP 50000 -> 53
    const auto unreachable = support::parse(ipv4Packet(1, "08080808", "0a000002", "03 03 0000 00000000" + inner));
    EXPECT_EQ(unreachable.info, "Destination unreachable (Port unreachable) [orig: 10.0.0.2 -> 8.8.8.8 UDP ports 50000 -> 53]");
    EXPECT_TRUE(matches("icmp.type == 3 && icmp.code == 3", unreachable));
    EXPECT_NE(find(unreachable.fields, "Code: 3 (Port unreachable)"), nullptr);
    EXPECT_NE(find(unreachable.fields, "Original packet: 10.0.0.2 -> 8.8.8.8 UDP ports 50000 -> 53"), nullptr);

    const auto ttl = support::parse(ipv4Packet(1, "0a000063", "0a000002", "0b 00 0000 00000000" + inner));
    EXPECT_EQ(ttl.info, "Time-to-live exceeded (TTL expired in transit) [orig: 10.0.0.2 -> 8.8.8.8 UDP ports 50000 -> 53]");

    const auto bare = support::parse(ipv4Packet(1, "0a000063", "0a000002", "03 01 0000 00000000"));
    EXPECT_EQ(bare.info, "Destination unreachable (Host unreachable)") << "no quoted packet available";
    EXPECT_EQ(support::parse(ipv4Packet(1, "0a000063", "0a000002", "2a 00 0000 00000000")).info, "Type 42");
}

TEST(Icmpv6, EchoAndNeighbourDiscovery) {
    const auto echo = support::parse(ipv6Packet(58, "80 00 0000 abcd 0007"));
    EXPECT_EQ(echo.protocol, "ICMPv6");
    EXPECT_EQ(echo.info, "Echo (ping) request  id=0xabcd, seq=7, ttl=64");
    EXPECT_TRUE(matches("icmpv6.type == 128 && icmpv6 && !icmp", echo));

    const auto ns = support::parse(ipv6Packet(58, "87 00 0000 00000000 20010db8000000000000000000000001"));
    EXPECT_EQ(ns.info, "Neighbor solicitation target 2001:db8::1");
    EXPECT_NE(find(ns.fields, "Target Address: 2001:db8::1"), nullptr);
    EXPECT_TRUE(matches("icmpv6.type == 135", ns));

    const auto unreachable = support::parse(ipv6Packet(58, "01 04 0000 00000000"));
    EXPECT_EQ(unreachable.info, "Destination unreachable (Port unreachable)");
}

TEST(MiscProtocols, SurviveRandomCorruption) {
    std::mt19937 rng(17);
    const std::string inner = "4500001c00000000 4011 0000 0a000002 08080808 c350 0035 0008 0000";
    std::vector<std::vector<char>> seeds = {
        ipv4Packet(1, "08080808", "0a000002", "03 03 0000 00000000" + inner),
        ipv4Packet(1, "0a000001", "0a000002", "08 00 0000 1234 0001" + support::hexOf("abcdefgh")),
        ipv6Packet(58, "87 00 0000 00000000 20010db8000000000000000000000001"),
        support::udpPacket("0a000002", "0a000001", "007b", "007b", bytes("24" "02" "06" "ec" + zeros(44))),
        support::udpPacket("0a000001", "ffffffff", "0044", "0043", bytes(dhcpFixed(1, 5) + "63825363" "350101" "0c0568657265" "ff")),
    };
    for (int i = 0; i < 6000; ++i) {
        auto frame = seeds[rng() % seeds.size()];
        frame.resize(rng() % (frame.size() + 1));
        for (unsigned k = rng() % 5; k > 0 && !frame.empty(); --k) frame[rng() % frame.size()] = static_cast<char>(rng());
        packet::PacketParser parser;
        packet::PacketInfo info(1);
        parser.parsePacket(info, frame, (i % 2) ? dissect::ParseMode::Full : dissect::ParseMode::Summary);
        expectRangesInside(info, frame.size());
    }
}

// ---- the summary-only protocols and the name tables ----------------------------------------------------------

namespace {
    packet::PacketInfo tcpTo(const char *dport, const std::string &payload) {
        return support::parse(support::tcpPacket("0a000001", "0a000002", "c350", dport, "00000001", "00000001", "18", payload));
    }
    packet::PacketInfo udpTo(const char *dport, const std::string &payload) {
        return support::parse(support::udpPacket("0a000001", "0a000002", "c350", dport, payload));
    }
}

TEST(SummaryProtocols, TelnetSmtpSnmpAndTheirDataLayers) {
    const auto telnet = tcpTo("0017", "login: root\r\n");
    EXPECT_EQ(telnet.protocol, "Telnet");
    EXPECT_NE(telnet.info.find("[ Telnet data: login: root"), std::string::npos) << telnet.info;
    EXPECT_NE(find(telnet.fields, "Data (13 bytes): login: root.."), nullptr);
    EXPECT_TRUE(matches("telnet", telnet));

    const std::string longText(80, 'a');
    const auto longTelnet = tcpTo("0017", longText);
    EXPECT_NE(longTelnet.info.find(std::string(50, 'a') + "... ]"), std::string::npos) << "only a snippet goes into the Info column";

    const auto smtp = tcpTo("0019", "EHLO imshark\r\n");
    EXPECT_EQ(smtp.protocol, "SMTP");
    EXPECT_EQ(smtp.info, "SMTP data: EHLO imshark\r\n");
    EXPECT_TRUE(matches("smtp", smtp));
    EXPECT_EQ(tcpTo("0019", longText).info, "SMTP data: " + std::string(50, 'a') + "...");

    const auto snmp = udpTo("00a1", std::string(30, 'x'));
    EXPECT_EQ(snmp.protocol, "SNMP");
    EXPECT_TRUE(matches("snmp", snmp));
    EXPECT_EQ(udpTo("00a2", "x").protocol, "SNMP") << "trap port 162";
}

TEST(SummaryProtocols, BgpMessageTypes) {
    auto bgp = [](unsigned type, size_t length = 19) {
        std::string msg(16, '\xff');       // marker
        msg += std::string("\x00\x13", 2); // length 19
        msg += static_cast<char>(type);
        msg.resize(length, '\0');
        return tcpTo("00b3", msg);
    };
    EXPECT_NE(bgp(1).info.find("[ BGP: OPEN ]"), std::string::npos);
    EXPECT_NE(bgp(2).info.find("[ BGP: UPDATE ]"), std::string::npos);
    EXPECT_NE(bgp(3).info.find("[ BGP: NOTIFICATION ]"), std::string::npos);
    EXPECT_NE(bgp(4).info.find("[ BGP: KEEPALIVE ]"), std::string::npos);
    EXPECT_NE(bgp(9).info.find("[ BGP: Unknown ]"), std::string::npos);
    const auto cut = tcpTo("00b3", std::string(10, '\xff'));
    EXPECT_NE(cut.info.find("[ BGP: truncated ]"), std::string::npos);
    EXPECT_EQ(bgp(1).protocol, "BGP");
    EXPECT_TRUE(matches("bgp", bgp(4)));
    EXPECT_NE(find(bgp(4).fields, "Border Gateway Protocol"), nullptr);
}

TEST(IcmpNames, EveryKnownTypeAndCodeHasAName) {
    auto info4 = [](unsigned type, unsigned code) {
        char hexType[48];
        std::snprintf(hexType, sizeof hexType, "%02x %02x 0000 00000000", type, code);
        return support::parse(ipv4Packet(1, "0a000001", "0a000002", hexType)).info;
    };
    for (unsigned t: {0u, 3u, 4u, 5u, 8u, 9u, 10u, 11u, 12u, 13u, 14u, 17u, 18u}) {
        EXPECT_NE(info4(t, 0).rfind("Type ", 0), 0u) << "ICMP type " << t << ": " << info4(t, 0);
    }
    EXPECT_EQ(info4(200, 0), "Type 200");
    const char *unreachable[] = {"Network unreachable", "Host unreachable", "Protocol unreachable", "Port unreachable",
                                 "Fragmentation needed and DF set", "Source route failed"};
    for (unsigned c = 0; c < 6; ++c) EXPECT_NE(info4(3, c).find(unreachable[c]), std::string::npos) << c;
    EXPECT_NE(info4(3, 13).find("administratively filtered"), std::string::npos);
    EXPECT_EQ(info4(3, 99), "Destination unreachable") << "unknown codes add nothing";
    EXPECT_NE(info4(5, 0).find("Redirect for network"), std::string::npos);
    EXPECT_NE(info4(5, 1).find("Redirect for host"), std::string::npos);
    EXPECT_NE(info4(11, 1).find("Fragment reassembly time exceeded"), std::string::npos);

    auto info6 = [](unsigned type, unsigned code) {
        char hexType[48];
        std::snprintf(hexType, sizeof hexType, "%02x %02x 0000 00000000", type, code);
        return support::parse(ipv6Packet(58, hexType)).info;
    };
    for (unsigned t: {1u, 2u, 3u, 4u, 128u, 129u, 130u, 131u, 132u, 133u, 134u, 135u, 136u, 137u, 143u}) {
        EXPECT_NE(info6(t, 0).rfind("Type ", 0), 0u) << "ICMPv6 type " << t;
    }
    EXPECT_EQ(info6(250, 0), "Type 250");
    const char *unreachable6[] = {"No route to destination", "Administratively prohibited", "", "Address unreachable", "Port unreachable"};
    for (unsigned c: {0u, 1u, 3u, 4u}) EXPECT_NE(info6(1, c).find(unreachable6[c]), std::string::npos) << c;
    EXPECT_NE(info6(3, 0).find("Hop limit exceeded"), std::string::npos);
    EXPECT_NE(info6(3, 1).find("Fragment reassembly"), std::string::npos);
}

TEST(IcmpNames, QuotedPacketProtocolNames) {
    auto quoted = [](unsigned proto) {
        char inner[160];
        // the quoted original packet: a bare 20-byte IPv4 header whose protocol byte is the test parameter
        std::snprintf(inner, sizeof inner, "45000014 00000000 40%02x 0000 0a000002 08080808", proto);
        return support::parse(ipv4Packet(1, "08080808", "0a000002", std::string("03 01 0000 00000000") + inner)).info;
    };
    EXPECT_NE(quoted(1).find("ICMP"), std::string::npos);
    EXPECT_NE(quoted(6).find("TCP"), std::string::npos);
    EXPECT_NE(quoted(58).find("ICMPv6"), std::string::npos);
    EXPECT_NE(quoted(47).find("protocol 47"), std::string::npos);
}

TEST(HttpNames, StandardPhrasesWhenTheLineHasNone) {
    struct Case { unsigned code; const char *phrase; };
    const Case cases[] = {{100, "Continue"}, {101, "Switching Protocols"}, {200, "OK"}, {201, "Created"}, {202, "Accepted"},
                          {204, "No Content"}, {206, "Partial Content"}, {301, "Moved Permanently"}, {302, "Found"},
                          {304, "Not Modified"}, {307, "Temporary Redirect"}, {308, "Permanent Redirect"}, {400, "Bad Request"},
                          {401, "Unauthorized"}, {403, "Forbidden"}, {404, "Not Found"}, {405, "Method Not Allowed"},
                          {408, "Request Timeout"}, {429, "Too Many Requests"}, {500, "Internal Server Error"},
                          {502, "Bad Gateway"}, {503, "Service Unavailable"}, {504, "Gateway Timeout"}};
    for (const auto &c: cases) {
        const auto p = tcpTo("c351", "HTTP/1.1 " + std::to_string(c.code) + "\r\n\r\n");
        EXPECT_EQ(p.protocol, "HTTP") << c.code;
        EXPECT_NE(find(p.fields, std::string("Response Phrase (standard): ") + c.phrase), nullptr) << c.code;
    }
    const auto unknown = tcpTo("c351", "HTTP/1.1 299\r\n\r\n");
    EXPECT_EQ(find(unknown.fields, "Response Phrase"), nullptr) << "no invented phrase for unknown codes";
}

TEST(Dhcp, OptionOverloadReadsTheFileAndSnameFields) {
    // fixed header with sname = "Message: from sname" and file = "Message: from file" given as options, End-terminated
    auto field = [&](const std::string &options, size_t size) { return options + zeros(size - options.size() / 2); };
    const std::string sname = field("38" "05" + support::hexOf("snm") + "6161" "ff", 64);                 // option 56, 5 bytes: "snm"+"aa"
    const std::string file = field("0c" "04" + support::hexOf("fhst") + "ff", 128);                         // option 12 hostname "fhst"
    const std::string fixed = std::string("01") + "01" "06" "00" + u32(9) + "0000" "8000" "00000000" "00000000" "00000000" "00000000" "001122334455" + zeros(10);
    const std::string options = "63825363" "350101" "3401" "03" "ff";                                       // overload both
    const auto p = dhcp(fixed + sname + file + options);
    EXPECT_EQ(p.protocol, "DHCP");
    EXPECT_NE(find(p.fields, "Option: (52) Option Overload: the file and sname fields hold options (3)"), nullptr);
    EXPECT_NE(find(p.fields, "Options in the file field (option overload)"), nullptr);
    EXPECT_NE(find(p.fields, "Options in the sname field (option overload)"), nullptr);
    EXPECT_NE(find(p.fields, "Option: (56) Message: snmaa"), nullptr);
    EXPECT_EQ(p.app_text, "fhst") << "an option found in the file field is a real option";
    EXPECT_NE(find(p.fields, "Server host name: options (option overload)"), nullptr);
    expectRangesInside(p, 14 + 20 + 8 + 236 + options.size() / 2);
}

TEST(Dhcp, ServerNameAndBootFileAreShownWhenNotOverloaded) {
    auto text = [&](const std::string &s, size_t size) { return support::hexOf(s) + zeros(size - s.size()); };
    const std::string fixed = std::string("02") + "01" "06" "00" + u32(9) + "0000" "8000" "00000000" "0a000032" "0a000001" "00000000" "001122334455" + zeros(10);
    const auto p = dhcp(fixed + text("tftp.example", 64) + text("pxelinux.0", 128) + "63825363" "350102" "ff", true);
    EXPECT_NE(find(p.fields, "Server host name: tftp.example"), nullptr);
    EXPECT_NE(find(p.fields, "Boot file name: pxelinux.0"), nullptr);
    const auto bare = dhcp(dhcpFixed(1, 1));
    EXPECT_NE(find(bare.fields, "Server host name not given"), nullptr);
}

TEST(IcmpBodies, V4FieldsOfTheLessCommonMessages) {
    const auto frag = support::parse(ipv4Packet(1, "0a000063", "0a000002", "03 04 0000 0000 05dc" + std::string("4500001c00000000 4011 0000 0a000002 08080808 c350 0035 0008 0000")));
    EXPECT_NE(frag.info.find("next-hop mtu 1500"), std::string::npos) << frag.info;
    EXPECT_NE(find(frag.fields, "MTU of next hop: 1500"), nullptr);

    const auto redirect = support::parse(ipv4Packet(1, "0a000063", "0a000002", "05 01 0000 0a000009" + std::string("4500001c00000000 4011 0000 0a000002 08080808 c350 0035 0008 0000")));
    EXPECT_NE(find(redirect.fields, "Gateway address: 10.0.0.9"), nullptr);
    EXPECT_NE(redirect.info.find("[orig: 10.0.0.2 -> 8.8.8.8 UDP"), std::string::npos) << redirect.info;

    const auto pointer = support::parse(ipv4Packet(1, "0a000063", "0a000002", "0c 00 0000 14000000"));
    EXPECT_NE(find(pointer.fields, "Pointer: 20"), nullptr);

    const auto timestamp = support::parse(ipv4Packet(1, "0a000001", "0a000002", "0d 00 0000 1234 0001 00000064 00000000 00000000"));
    EXPECT_NE(find(timestamp.fields, "Originate timestamp: 100 ms since midnight UTC"), nullptr);

    const auto mask = support::parse(ipv4Packet(1, "0a000001", "0a000002", "11 00 0000 1234 0001 ffffff00"));
    EXPECT_NE(find(mask.fields, "Address mask: 255.255.255.0"), nullptr);

    const auto advert = support::parse(ipv4Packet(1, "0a000001", "e0000001", "09 00 0000 01 02 0708 0a000001 00000000"));
    EXPECT_NE(find(advert.fields, "Router address: 10.0.0.1, preference 0"), nullptr);
    EXPECT_NE(find(advert.fields, "Lifetime: 1800 seconds"), nullptr);
}

TEST(IcmpBodies, RouterAdvertisementWithOptions) {
    const std::string options =
        "01 01 001122334455"                                                            // source link-layer address
        "03 04 40 c0 00278d00 00093a80 00000000 20010db8000100000000000000000000"       // prefix 2001:db8:1::/64, L + A
        "05 01 0000 000005dc"                                                            // MTU 1500
        "19 03 0000 00000e10 20010db8000000000000000000000053";                         // RDNSS
    const auto p = support::parse(ipv6Packet(58, "86 00 0000 40 c8 0708 00000000 00000000" + options));
    EXPECT_EQ(p.protocol, "ICMPv6");
    EXPECT_NE(find(p.fields, "Cur hop limit: 64"), nullptr);
    EXPECT_NE(find(p.fields, "Flags: 0xc8, Managed address configuration, Other configuration, Preference high"), nullptr);
    EXPECT_NE(find(p.fields, "Router lifetime: 1800 seconds"), nullptr);
    EXPECT_NE(find(p.fields, "ICMPv6 Option (1) Source link-layer address: 00:11:22:33:44:55"), nullptr);
    EXPECT_NE(find(p.fields, "ICMPv6 Option (3) Prefix information: 2001:db8:1::/64"), nullptr);
    EXPECT_NE(find(p.fields, "Flags: L (on-link) A (autonomous) 0xc0"), nullptr);
    EXPECT_NE(find(p.fields, "Valid lifetime: 2592000 seconds"), nullptr);
    EXPECT_NE(find(p.fields, "ICMPv6 Option (5) MTU: 1500"), nullptr);
    EXPECT_NE(find(p.fields, "ICMPv6 Option (25) Recursive DNS server: 2001:db8::53"), nullptr);
    expectRangesInside(p, 14 + 40 + 16 + options.size() / 2 - std::count(options.begin(), options.end(), ' ') / 2);
}

TEST(IcmpBodies, NeighbourAdvertisementFlagsAndBadOptions) {
    const auto na = support::parse(ipv6Packet(58, "88 00 0000 e0000000 20010db8000000000000000000000001 02 01 aabbccddeeff"));
    EXPECT_NE(find(na.fields, "Flags: 0xe0, Router, Solicited, Override"), nullptr);
    EXPECT_NE(find(na.fields, "ICMPv6 Option (2) Target link-layer address: aa:bb:cc:dd:ee:ff"), nullptr);

    const auto zero = support::parse(ipv6Packet(58, "87 00 0000 00000000 20010db8000000000000000000000001 01 00 000000000000"));
    EXPECT_NE(find(zero.fields, "[Malformed option: length 0]"), nullptr) << "a zero-length option must not loop";

    const auto cut = support::parse(ipv6Packet(58, "87 00 0000 00000000 20010db8000000000000000000000001 01 02 001122"));
    EXPECT_NE(find(cut.fields, "[Option continues past the end of the message]"), nullptr);
}

TEST(IcmpBodies, PacketTooBigQuotesTheIpv6Packet) {
    const std::string inner = "60000000 0008 11 40 20010db8000000000000000000000001 20010db8000000000000000000000002 c350 0035 0008 0000";
    const auto p = support::parse(ipv6Packet(58, "02 00 0000 00000500" + inner));
    EXPECT_NE(p.info.find("Packet too big"), std::string::npos);
    EXPECT_NE(p.info.find("mtu 1280"), std::string::npos) << p.info;
    EXPECT_NE(p.info.find("[orig: 2001:db8::1 -> 2001:db8::2 UDP ports 50000 -> 53]"), std::string::npos) << p.info;
    EXPECT_NE(find(p.fields, "MTU: 1280"), nullptr);
}

TEST(IcmpBodies, MulticastListenerMessages) {
    const auto query = support::parse(ipv6Packet(58, "82 00 0000 2710 0000 ff020000000000000000000000000001 02 7d 0001 20010db8000000000000000000000009"));
    EXPECT_NE(find(query.fields, "Maximum response delay: 10000 ms"), nullptr);
    EXPECT_NE(find(query.fields, "Multicast address: ff02::1"), nullptr);
    EXPECT_NE(find(query.fields, "Flags: S=0, QRV=2"), nullptr);
    EXPECT_NE(find(query.fields, "Source address: 2001:db8::9"), nullptr);

    const auto report = support::parse(ipv6Packet(58, "8f 00 0000 0000 0001 04 00 0001 ff020000000000000000000000000016 20010db8000000000000000000000009"));
    EXPECT_NE(find(report.fields, "Multicast Address Record: CHANGE_TO_EXCLUDE_MODE ff02::16"), nullptr);
    EXPECT_NE(find(report.fields, "Source address: 2001:db8::9"), nullptr);
}

TEST(IcmpBodies, SurviveRandomCorruption) {
    std::mt19937 rng(23);
    std::vector<std::vector<char>> seeds = {
        ipv6Packet(58, "86 00 0000 40 c8 0708 00000000 00000000 01 01 001122334455 03 04 40 c0 00278d00 00093a80 00000000 20010db8000100000000000000000000"),
        ipv6Packet(58, "8f 00 0000 0000 0001 04 00 0001 ff020000000000000000000000000016 20010db8000000000000000000000009"),
        ipv6Packet(58, "82 00 0000 2710 0000 ff020000000000000000000000000001 02 7d 0001 20010db8000000000000000000000009"),
        ipv4Packet(1, "0a000001", "e0000001", "09 00 0000 01 02 0708 0a000001 00000000"),
        ipv4Packet(1, "0a000001", "0a000002", "0d 00 0000 1234 0001 00000064 00000000 00000000"),
    };
    for (int i = 0; i < 8000; ++i) {
        auto frame = seeds[rng() % seeds.size()];
        frame.resize(14 + rng() % (frame.size() - 13));
        for (unsigned k = rng() % 5; k > 0 && frame.size() > 14; --k) frame[14 + rng() % (frame.size() - 14)] = static_cast<char>(rng());
        packet::PacketParser parser;
        packet::PacketInfo info(1);
        parser.parsePacket(info, frame, dissect::ParseMode::Full);
        std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
            EXPECT_LE(size_t(f.offset) + f.length, frame.size()) << f.text;
            for (const auto &c: f.children) check(c);
        };
        for (const auto &l: info.fields) check(l);
    }
}

TEST(Ipv6Extensions, OptionsRoutingAndAuthenticationHeaders) {
    // hop-by-hop: next = ICMPv6, length 0 (8 bytes): router alert (MLD), PadN(0)
    const auto hbh = support::parse(ipv6Packet(0, "3a 00 0502 0000 0100" "80 00 0000 abcd 0007"));
    EXPECT_EQ(hbh.protocol, "ICMPv6");
    EXPECT_NE(find(hbh.fields, "Hop-by-Hop Options (8 bytes)"), nullptr);
    EXPECT_NE(find(hbh.fields, "Router Alert: MLD"), nullptr);
    EXPECT_NE(find(hbh.fields, "PadN (0 bytes)"), nullptr);
    EXPECT_NE(find(hbh.fields, "Type: 5 (skip if unrecognised)"), nullptr);

    // destination options with an unknown option that must be discarded (type 0x80 -> top bits 10)
    const auto dst = support::parse(ipv6Packet(60, "3a 00 8002 0000 0100" "80 00 0000 abcd 0007"));
    EXPECT_NE(find(dst.fields, "Destination Options (8 bytes)"), nullptr);
    EXPECT_NE(find(dst.fields, "Type: 128 (discard and send ICMP if unrecognised)"), nullptr);

    // routing header type 4 (segment routing) with two segments
    const auto srh = support::parse(ipv6Packet(43, "3a 04 04 01 01 00 0000" "20010db8000000000000000000000001" "20010db8000000000000000000000002" "80 00 0000 abcd 0007"));
    EXPECT_NE(find(srh.fields, "Routing Header (40 bytes)"), nullptr);
    EXPECT_NE(find(srh.fields, "Routing Type: Segment Routing (4)"), nullptr);
    EXPECT_NE(find(srh.fields, "Segments Left: 1"), nullptr);
    EXPECT_NE(find(srh.fields, "Segment List[1]: 2001:db8::2"), nullptr);

    // authentication header: length 4 -> 24 bytes
    const auto ah = support::parse(ipv6Packet(51, "3a 04 0000 00001000 00000005" "aabbccdd11223344" "80 00 0000 abcd 0007"));
    EXPECT_NE(find(ah.fields, "Authentication Header (24 bytes)"), nullptr);
    EXPECT_NE(find(ah.fields, "SPI: 0x00001000"), nullptr);
    EXPECT_NE(find(ah.fields, "Integrity Check Value: 12 bytes"), nullptr);

    // damaged: an option longer than its header
    const auto bad = support::parse(ipv6Packet(0, "3a 00 0509 0000 0100" "80 00 0000 abcd 0007"));
    EXPECT_NE(find(bad.fields, "[Option continues past the end of the header]"), nullptr);
}

namespace {
    packet::PacketInfo ntp(const std::string &hexPayload) { return support::parse(support::udpPacket("0a000002", "0a000001", "007b", "007b", bytes(hexPayload))); }
    std::string ntpClient() { return "23" "00" "06" "ec" + zeros(44); }
}

TEST(NtpModes, ControlMessages) {
    const auto request = ntp("16" "02" "0001" "0000" "0000" "0000" "0000");   // version 2, mode 6, read variables
    EXPECT_EQ(request.protocol, "NTP");
    EXPECT_EQ(request.info, "NTP Version 2, control message, read variables request");
    EXPECT_TRUE(matches("ntp.mode == 6 && ntp.ctrl.opcode == 2 && !ntp.stratum", request));

    const std::string text = "version=\"ntpd 4.2.8\"";
    const std::string padded = support::hexOf(text) + zeros(((text.size() + 3) / 4 * 4) - text.size());
    const auto response = ntp("16" "82" "0001" "0000" "0000" "0000" + u32(static_cast<unsigned>(text.size())).substr(4) + padded + u32(7) + zeros(16));
    EXPECT_EQ(response.info, "NTP Version 2, control message, read variables response");
    EXPECT_NE(find(response.fields, "Data: version=\"ntpd 4.2.8\""), nullptr);
    EXPECT_NE(find(response.fields, "Authenticator"), nullptr);
    EXPECT_NE(find(response.fields, "Key ID: 7"), nullptr);

    const auto error = ntp("16" "c2" "0001" "0000" "0000" "0000" "0000");
    EXPECT_NE(error.info.find("(error)"), std::string::npos);
    EXPECT_NE(ntp("16" "02").info.find("Malformed"), std::string::npos);
    const auto lying = ntp("16" "82" "0001" "0000" "0000" "0000" "0100" "6161");
    EXPECT_NE(find(lying.fields, "[Data continues past the end of the message]"), nullptr);
}

TEST(NtpModes, PrivateMessages) {
    const auto p = ntp("17" "00" "03" "00" "0000" "0000");   // version 2, mode 7, implementation 3, request 0 = PEER_LIST
    EXPECT_EQ(p.info, "NTP Version 2, private message, PEER_LIST request");
    EXPECT_TRUE(matches("ntp.mode == 7 && ntp.priv.reqcode == 0", p));
    const auto response = ntp("97" "80" "03" "2a" "0002" "0010" + zeros(32));
    EXPECT_EQ(response.info, "NTP Version 2, private message, REQ_MON_GETLIST_1 response");
    EXPECT_NE(find(response.fields, "Number of data items: 2"), nullptr);
    EXPECT_EQ(find(response.fields, "Data (32 bytes,"), nullptr) << "item count and size agree with the data";
}

TEST(NtpModes, ExtensionFieldsAndAuthenticators) {
    const auto md5 = ntp(ntpClient() + u32(5) + zeros(16));
    EXPECT_NE(find(md5.fields, "Message Authentication Code (MD5)"), nullptr);
    EXPECT_NE(find(md5.fields, "Key ID: 5"), nullptr);
    const auto sha1 = ntp(ntpClient() + u32(6) + zeros(20));
    EXPECT_NE(find(sha1.fields, "Message Authentication Code (SHA-1)"), nullptr);
    const auto nak = ntp(ntpClient() + u32(0));
    EXPECT_NE(find(nak.fields, "Key ID: 0 (crypto-NAK if zero)"), nullptr);

    // one extension field (type 0x0104, 16 bytes) followed by an MD5 MAC
    const auto ext = ntp(ntpClient() + "0104" "0010" + zeros(12) + u32(5) + zeros(16));
    EXPECT_NE(find(ext.fields, "Extension Field: type 0x0104, length 16"), nullptr);
    EXPECT_NE(find(ext.fields, "Message Authentication Code (MD5)"), nullptr);

    const auto bad = ntp(ntpClient() + "0104" "0003" + zeros(30));
    EXPECT_NE(find(bad.fields, "[Malformed extension field]"), nullptr);
    EXPECT_NE(find(ntp(ntpClient() + "aabbcc").fields, "Trailing data (3 bytes)"), nullptr);
}

TEST(NtpModes, SurviveRandomCorruption) {
    std::mt19937 rng(31);
    const std::vector<std::string> seeds = {"16" "82" "0001" "0000" "0000" "0000" "0004" "61616161" + u32(7) + zeros(16), "97" "80" "03" "2a" "0002" "0010" + zeros(32),
                                            ntpClient() + "0104" "0010" + zeros(12) + u32(5) + zeros(16)};
    for (int i = 0; i < 5000; ++i) {
        auto b = bytes(seeds[rng() % seeds.size()]);
        b.resize(rng() % (b.size() + 1));
        for (unsigned k = rng() % 4; k > 0 && !b.empty(); --k) b[rng() % b.size()] = static_cast<char>(rng());
        auto frame = support::udpPacket("0a000002", "0a000001", "007b", "007b", support::hexOf(b));
        packet::PacketParser parser;
        packet::PacketInfo info(1);
        parser.parsePacket(info, frame, dissect::ParseMode::Full);
        std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
            EXPECT_LE(size_t(f.offset) + f.length, frame.size()) << f.text;
            for (const auto &c: f.children) check(c);
        };
        for (const auto &l: info.fields) check(l);
    }
}
