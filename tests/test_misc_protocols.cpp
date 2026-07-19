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
