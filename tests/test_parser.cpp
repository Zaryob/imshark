#include <gtest/gtest.h>

#include <algorithm>
#include <random>

#include "support.h"

using support::hex;
using support::parse;

namespace {
    using packet::Field;

    const Field *findField(const Field &f, const std::string &prefix) {
        if (f.text.rfind(prefix, 0) == 0) return &f;
        for (const auto &c: f.children) {
            if (auto r = findField(c, prefix)) return r;
        }
        return nullptr;
    }

    const Field *findField(const packet::PacketInfo &p, const std::string &prefix) {
        for (const auto &l: p.fields) {
            if (auto r = findField(l, prefix)) return r;
        }
        return nullptr;
    }

    // Every field must lie inside the frame and inside its parent (when the parent has a byte range).
    void expectWithinFrame(const Field &f, size_t frameLen, const Field *parent = nullptr) {
        EXPECT_LE(size_t(f.offset) + f.length, frameLen) << f.text;
        if (parent && parent->length > 0 && f.length > 0) {
            EXPECT_GE(f.offset, parent->offset) << f.text;
            EXPECT_LE(size_t(f.offset) + f.length, size_t(parent->offset) + parent->length) << f.text;
        }
        for (const auto &c: f.children) expectWithinFrame(c, frameLen, &f);
    }
} // namespace


TEST(Parser, Arp) {
    auto p = parse(hex(support::kArpRequest));
    EXPECT_EQ(p.protocol, "ARP");
    EXPECT_EQ(p.source, "00:11:22:33:44:55");
    EXPECT_EQ(p.info, "ARP Request: Who has 10.0.0.2? Tell 10.0.0.1");
}

TEST(Parser, UdpOverIpv4) {
    auto p = parse(hex(std::string(support::kEthIpUdp)));
    EXPECT_EQ(p.source, "10.0.0.1");
    EXPECT_EQ(p.destination, "10.0.0.2");
    EXPECT_EQ(p.l2_size, 14);
    // port 53 is classified as DNS, but the message is empty -> malformed, not a crash
    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_NE(p.info.find("Malformed"), std::string::npos);
}

TEST(Parser, DnsQueryAndCompressedAnswer) {
    // query example.com A, answer uses a compression pointer (0xc00c) back to the question name
    const std::string dns =
        "1234 8180 0001 0001 0000 0000 076578616d706c6503636f6d00 0001 0001"
        "c00c 0001 0001 0000012c 0004 5db8d822";
    const size_t udpLen = 8 + dns.size() / 2;
    char lens[16];
    snprintf(lens, sizeof lens, "%04zx", udpLen);
    char total[16];
    snprintf(total, sizeof total, "%04zx", 20 + udpLen);
    auto p = parse(hex("001122334455 aabbccddeeff 0800 4500" + std::string(total) + "000000004011 0000 08080808 0a000001 0035 c350 " +
                       lens + " 0000 " + dns));
    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_EQ(p.info, "Standard query response 0x1234 A example.com example.com A 93.184.216.34");
}

TEST(Parser, TcpOptionsAndFlags) {
    auto p = parse(hex("001122334455 aabbccddeeff 0800 4500003c123440004006 0000 0a000001 0a000002"
                       "1f90 01bb 00000064 00000000 a002 7210 0000 0000"
                       "020405b4 01 030307 0402 080a 00000001 00000000"));
    EXPECT_EQ(p.protocol, "TCP");
    EXPECT_EQ(p.info, "8080 -> 443 [SYN]  Seq=0 Win=29200 MSS=1460 WS=7 SACK_PERM TSval=1 TSecr=0");
    EXPECT_NE(findField(p, "Flags: 0x2, Don't fragment"), nullptr) << "DF bit";
    EXPECT_NE(findField(p, "Fragment Offset: 0"), nullptr);
}

TEST(Parser, Ipv6WithExtensionHeaders) {
    auto p = parse(hex("001122334455 aabbccddeeff 86dd 60123456 0018 00 40"
                       "20010db8000000000000000000000001 20010db8000000000000000000000002"
                       "3c00 000000000000 1100 000000000000 1234 1235 0008 0000"));
    EXPECT_EQ(p.protocol, "UDP");
    EXPECT_EQ(p.source, "2001:db8::1");
    EXPECT_NE(findField(p, "Version: 6"), nullptr);
    EXPECT_NE(findField(p, "Traffic Class: 0x01"), nullptr);
    EXPECT_NE(findField(p, "Flow Label: 0x23456"), nullptr);
}

TEST(Parser, LinkTypes) {
    const std::string ip = "4500001c00000000401100000a0000010a000002 1234 0035 0008 0000";
    struct Case { const char *name; uint32_t linkType; std::string prefix; uint16_t l2; };
    const Case cases[] = {
        {"vlan", 1, "001122334455aabbccddeeff 8100 0064 0800", 18},
        {"qinq", 1, "001122334455aabbccddeeff 88a8 0064 8100 00c8 0800", 22},
        {"null", 0, "02000000", 4},
        {"null-swapped", 0, "00000002", 4},
        {"loop", 108, "00000002", 4},
        {"raw", 101, "", 0},
        {"sll", 113, "0000 0001 0006 001122334455 0000 0800", 16},
        {"sll2", 276, "0800 0000 00000001 0001 00 06 001122334455 0000", 20},
    };
    for (const auto &c: cases) {
        SCOPED_TRACE(c.name);
        auto p = parse(hex(c.prefix + ip), c.linkType);
        EXPECT_EQ(p.source, "10.0.0.1");
        EXPECT_EQ(p.l2_size, c.l2);
    }
    EXPECT_EQ(parse(hex(std::string("001122334455aabbccddeeff 8100 0064 0800") + ip)).vlan_ids, std::vector<uint16_t>{100});
    EXPECT_EQ(parse(hex(ip), 999).info, "Unsupported link type 999");
}

TEST(Parser, UnknownEtherType) {
    auto p = parse(hex("001122334455 aabbccddeeff 88cc 0207"));
    EXPECT_EQ(p.protocol, "Ethernet");
    EXPECT_EQ(p.info, "EtherType 0x88cc");
}

TEST(Parser, TruncatedFramesAreMalformedNotCrashes) {
    const auto frame = hex("001122334455 aabbccddeeff 0800 4500003c123440004006 0000 0a000001 0a000002 1f90 01bb 00000064 00000000 a002 7210 0000 0000");
    for (size_t cut = 0; cut < frame.size(); ++cut) {
        auto p = parse(std::vector<char>(frame.begin(), frame.begin() + cut));
        if (cut < 14 + 20 + 20) {
            EXPECT_NE(p.info.find("Malformed"), std::string::npos) << "cut at " << cut;
        }
    }
}

// Mutation fuzzing: must never crash or trip sanitizers, whatever the input.
TEST(Parser, RandomisedInputNeverCrashes) {
    std::mt19937 rng(12345);
    const std::vector<std::vector<char>> seeds = {
        hex(support::kArpRequest), hex(std::string(support::kEthIpUdp)),
        hex("001122334455 aabbccddeeff 0800 4500003c123440004006 0000 0a000001 0a000002 1f90 01bb 00000064 00000000 a002 7210 0000 0000 020405b4"),
        hex("001122334455 aabbccddeeff 86dd 60000000 0008 11 40 20010db8000000000000000000000001 20010db8000000000000000000000002 1234 0035 0008 0000"),
    };
    for (int i = 0; i < 20000; ++i) {
        auto data = seeds[rng() % seeds.size()];
        data.resize(rng() % (data.size() + 1));
        for (unsigned flips = rng() % 5; flips > 0 && !data.empty(); --flips) data[rng() % data.size()] = static_cast<char>(rng());
        parse(data, (i % 7 == 0) ? 113 : (i % 11 == 0) ? 101 : 1);
    }
}

// ---- protocol tree (Field) ------------------------------------------------------------------------

TEST(FieldTree, EthernetIpTcpRangesAreAbsolute) {
    // IPv4 with options (ihl = 6) so that the TCP header starts at 14 + 24 = 38, not 34
    auto frame = hex("001122334455 aabbccddeeff 0800 4600003c123440004006 0000 0a000001 0a000002 01010101"
                     "1f90 01bb 00000064 00000000 5002 7210 0000 0000");
    auto p = parse(frame);
    ASSERT_EQ(p.protocol, "TCP");

    ASSERT_GE(p.fields.size(), 4u);
    EXPECT_EQ(p.fields[0].text.rfind("Frame 1", 0), 0u);
    const Field *ip = findField(p, "Internet Protocol Version 4");
    const Field *tcp = findField(p, "Transmission Control Protocol");
    ASSERT_NE(ip, nullptr);
    ASSERT_NE(tcp, nullptr);
    EXPECT_EQ(ip->offset, 14u);
    EXPECT_EQ(ip->length, 24u);
    EXPECT_EQ(tcp->offset, 38u) << "IP options must shift the TCP header";

    const Field *srcPort = findField(*tcp, "Source Port: 8080");
    ASSERT_NE(srcPort, nullptr);
    EXPECT_EQ(srcPort->offset, 38u);
    EXPECT_EQ(srcPort->length, 2u);
    const Field *dst = findField(*ip, "Destination Address: 10.0.0.2");
    ASSERT_NE(dst, nullptr);
    EXPECT_EQ(dst->offset, 14u + 16u);

    for (const auto &l: p.fields) expectWithinFrame(l, frame.size());
}

TEST(FieldTree, ArpDnsAndVlan) {
    auto arp = parse(hex(support::kArpRequest));
    const Field *spa = findField(arp, "Sender IP address: 10.0.0.1");
    ASSERT_NE(spa, nullptr);
    EXPECT_EQ(spa->offset, 14u + 14u);
    EXPECT_EQ(spa->length, 4u);

    auto vlan = parse(hex(std::string("001122334455aabbccddeeff 8100 0064 0800 ") +
                          "4500001c00000000401100000a0000010a000002 1234 1235 0008 0000"));
    const Field *tag = findField(vlan, "802.1Q Virtual LAN, ID: 100");
    ASSERT_NE(tag, nullptr);
    EXPECT_EQ(tag->offset, 14u);
    const Field *ip = findField(vlan, "Internet Protocol Version 4");
    ASSERT_NE(ip, nullptr);
    EXPECT_EQ(ip->offset, 18u);
    const Field *udp = findField(vlan, "User Datagram Protocol");
    ASSERT_NE(udp, nullptr);
    EXPECT_EQ(udp->offset, 38u);
}

TEST(FieldTree, FieldsStayInsideFrameForTruncatedAndRandomInput) {
    const auto frame = hex("001122334455 aabbccddeeff 0800 4500003c123440004006 0000 0a000001 0a000002 1f90 01bb 00000064 00000000 a002 7210 0000 0000 020405b4");
    for (size_t cut = 0; cut <= frame.size(); ++cut) {
        std::vector<char> part(frame.begin(), frame.begin() + cut);
        auto p = parse(part);
        for (const auto &l: p.fields) expectWithinFrame(l, part.size());
    }
    std::mt19937 rng(99);
    for (int i = 0; i < 5000; ++i) {
        auto data = frame;
        data.resize(rng() % (data.size() + 1));
        for (unsigned f = rng() % 4; f > 0 && !data.empty(); --f) data[rng() % data.size()] = static_cast<char>(rng());
        auto p = parse(data);
        for (const auto &l: p.fields) expectWithinFrame(l, data.size());
    }
}

// ---- dissector registry ---------------------------------------------------------------------------

TEST(Registry, CustomDissectorsAreUsedForPortsAndEtherTypes) {
    dissect::Registry registry = dissect::Registry::builtin(); // start from the built-ins and extend
    registry.registerUdpPort(9999, [](dissect::Context &ctx, const char *data, size_t length) {
        ctx.pack.protocol = "MYPROTO";
        ctx.pack.info = "payload=" + std::string(data, length);
        ctx.addLayer("My Protocol", ctx.offsetOf(data), length);
    });
    registry.registerEtherType(0x88B5, [](dissect::Context &ctx, const char *data, size_t length) {
        ctx.pack.protocol = "LOCAL";
        ctx.pack.info = std::to_string(length) + " bytes";
        ctx.addLayer("Local Experimental", ctx.offsetOf(data), length);
    });

    packet::PacketParser parser(registry);
    std::vector<char> udp = hex("001122334455 aabbccddeeff 0800 4500001f00000000401100000a0000010a000002 c350 270f 000b 0000 686921");
    packet::PacketInfo a(1);
    parser.parsePacket(a, udp);
    EXPECT_EQ(a.protocol, "MYPROTO");
    EXPECT_EQ(a.info, "payload=hi!");
    EXPECT_EQ(a.fields.back().text, "My Protocol");
    EXPECT_EQ(a.fields.back().offset, 14u + 20u + 8u);

    std::vector<char> local = hex("001122334455 aabbccddeeff 88b5 deadbeef");
    packet::PacketInfo b(2);
    parser.parsePacket(b, local);
    EXPECT_EQ(b.protocol, "LOCAL");
    EXPECT_EQ(b.info, "4 bytes");

    // The built-in registry is unaffected
    EXPECT_EQ(parse(udp).protocol, "UDP");
    EXPECT_EQ(parse(local).protocol, "Ethernet");
}
