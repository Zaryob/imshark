#include <gtest/gtest.h>

#include <algorithm>
#include <random>

#include <filter/filter.h>
#include <network/connection.h>

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
    EXPECT_EQ(p.info, "Standard query response 0x1234 A example.com A 93.184.216.34");
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

// ---- summary facts used by the display filter -----------------------------------------------------

TEST(SummaryFacts, TcpOverIpv4) {
    auto p = parse(hex("001122334455 aabbccddeeff 0800 4500003c123440004006 0000 0a000001 0a000002"
                       "1f90 01bb 00000064 00000000 a002 7210 0000 0000 020405b4"));
    EXPECT_EQ(p.ether_type, 0x0800);
    EXPECT_EQ(p.ip_version, 4);
    EXPECT_EQ(p.ip_protocol, 6);
    EXPECT_EQ(p.ttl, 64);
    EXPECT_EQ(p.tcp_flags, 0x02) << "the SYN flag; the data offset nibble is not part of it";
    EXPECT_EQ(p.src_port, 8080);
    EXPECT_EQ(p.dst_port, 443);
    EXPECT_NE(p.info.find("Malformed"), std::string::npos) << "the options are cut short in this frame";
}

TEST(SummaryFacts, SynFlagsArePreserved) {
    auto p = parse(hex("001122334455 aabbccddeeff 0800 4500002800000000 4006 0000 0a000001 0a000002 1f90 01bb 00000001 00000000 5002 2000 0000 0000"));
    EXPECT_EQ(p.tcp_flags, 0x02);
}

TEST(SummaryFacts, UdpIpv6VlanArpAndUnknown) {
    auto udp = parse(hex(std::string("001122334455aabbccddeeff 8100 0064 0800 ") +
                         "4500001c00000000 3f11 0000 0a0000010a000002 1234 0035 0008 0000"));
    EXPECT_EQ(udp.ether_type, 0x0800) << "the inner type after the VLAN tag";
    EXPECT_EQ(udp.ip_protocol, 17);
    EXPECT_EQ(udp.ttl, 63);
    EXPECT_EQ(udp.src_port, 0x1234);
    EXPECT_EQ(udp.dst_port, 53);

    auto v6 = parse(hex("001122334455 aabbccddeeff 86dd 60000000 0008 11 40 20010db8000000000000000000000001 20010db8000000000000000000000002 1234 1235 0008 0000"));
    EXPECT_EQ(v6.ip_version, 6);
    EXPECT_EQ(v6.ip_protocol, 17);
    EXPECT_EQ(v6.ttl, 64) << "hop limit";

    auto arp = parse(hex(support::kArpRequest));
    EXPECT_EQ(arp.ether_type, 0x0806);
    EXPECT_EQ(arp.ip_version, 0);
    EXPECT_EQ(arp.src_port, 0);

    auto other = parse(hex("001122334455 aabbccddeeff 88cc 0207"));
    EXPECT_EQ(other.ether_type, 0x88cc);
    EXPECT_EQ(other.ip_protocol, 0);
}

TEST(SummaryFacts, ExtensionHeadersReportTheTransportProtocol) {
    auto p = parse(hex("001122334455 aabbccddeeff 86dd 60000000 0018 00 40 20010db8000000000000000000000001 20010db8000000000000000000000002"
                       "3c00 000000000000 1100 000000000000 1234 1235 0008 0000"));
    EXPECT_EQ(p.ip_protocol, 17) << "not 0 (hop-by-hop) or 60 (destination options)";
}

// ---- TCP analysis at packet level ---------------------------------------------------------------------

namespace {
    // Ethernet + IPv4 + TCP (20-byte header) followed by `payload` bytes of 0x61
    std::string tcpFrame(const char *srcIp, const char *dstIp, const char *sport, const char *dport, const char *seq,
                         const char *ack, const char *flags, size_t payload) {
        char total[8];
        snprintf(total, sizeof total, "%04zx", 40 + payload);
        std::string data;
        for (size_t i = 0; i < payload; ++i) data += "61";
        return std::string("001122334455 aabbccddeeff 0800 4500") + total + "0000 0000 4006 0000 " + srcIp + " " + dstIp + " " + sport + " " +
               dport + " " + seq + " " + ack + " 50" + flags + " 2000 0000 0000 " + data;
    }
} // namespace

TEST(TcpAnalysisPackets, RetransmissionShowsInInfoFiltersAndTree) {
    packet::PacketParser parser;
    auto run = [&](const std::string &frame, int number) {
        packet::PacketInfo info(number);
        std::vector<char> bytes = hex(frame);
        parser.parsePacket(info, bytes);
        return info;
    };
    const auto syn = run(tcpFrame("0a000001", "0a000002", "1388", "0050", "000003e8", "00000000", "02", 0), 1);
    const auto data1 = run(tcpFrame("0a000001", "0a000002", "1388", "0050", "000003e9", "00000001", "18", 10), 2);
    const auto data2 = run(tcpFrame("0a000001", "0a000002", "1388", "0050", "000003e9", "00000001", "18", 10), 3);

    EXPECT_EQ(syn.tcp_analysis, 0);
    EXPECT_EQ(data1.tcp_analysis, 0);
    EXPECT_EQ(data2.tcp_analysis, network::kTcpRetransmission);
    EXPECT_EQ(data2.info.rfind("[TCP Retransmission] 5000 -> 80", 0), 0u) << data2.info;
    EXPECT_NE(findField(data2, "[SEQ/ACK analysis]"), nullptr);
    EXPECT_NE(findField(data2, "This frame is a (suspected) retransmission"), nullptr);
    EXPECT_EQ(findField(data1, "[SEQ/ACK analysis]"), nullptr);

    auto f = filter::Filter::compile("tcp.analysis.retransmission");
    ASSERT_TRUE(f.ok);
    EXPECT_FALSE(f.filter.matches(data1));
    EXPECT_TRUE(f.filter.matches(data2));
    EXPECT_TRUE(filter::Filter::compile("tcp.analysis.flags && !tcp.analysis.lost_segment").filter.matches(data2));
    EXPECT_FALSE(filter::Filter::compile("tcp.analysis.flags").filter.matches(parse(hex(support::kArpRequest)))) << "not TCP";

    // Summary parsing keeps the analysis, and a Replay of the packet in isolation reproduces info and tree
    packet::PacketParser fresh;
    packet::PacketInfo replayed = data2;
    std::vector<char> bytes = hex(tcpFrame("0a000001", "0a000002", "1388", "0050", "000003e9", "00000001", "18", 10));
    fresh.parsePacket(replayed, bytes, dissect::ParseMode::Replay);
    EXPECT_EQ(replayed.info, data2.info);
    EXPECT_EQ(replayed.tcp_analysis, data2.tcp_analysis);
    EXPECT_NE(findField(replayed, "This frame is a (suspected) retransmission"), nullptr);
}

TEST(SummaryFacts, PayloadPositionInsideTheFrame) {
    auto tcp = parse(hex("001122334455 aabbccddeeff 0800 4500003000000000 4006 0000 0a000001 0a000002 1f90 01bb 00000001 00000000 5018 2000 0000 0000 6162636465666768"));
    EXPECT_EQ(tcp.payload_offset, 14u + 20u + 20u);
    EXPECT_EQ(tcp.payload_length, 8u);
    auto udp = parse(hex("001122334455 aabbccddeeff 0800 4500001f00000000 4011 0000 0a000001 0a000002 1234 1235 000b 0000 686921"));
    EXPECT_EQ(udp.payload_offset, 14u + 20u + 8u);
    EXPECT_EQ(udp.payload_length, 3u);
    auto ack = parse(hex("001122334455 aabbccddeeff 0800 4500002800000000 4006 0000 0a000001 0a000002 1f90 01bb 00000001 00000000 5010 2000 0000 0000"));
    EXPECT_EQ(ack.payload_length, 0u);
    EXPECT_EQ(ack.payload_offset, 0u);
    auto vlan = parse(hex("001122334455 aabbccddeeff 8100 0064 0800 4500001f00000000 4011 0000 0a000001 0a000002 1234 1235 000b 0000 686921"));
    EXPECT_EQ(vlan.payload_offset, 14u + 4u + 20u + 8u) << "VLAN tags move the payload";
    auto ethPadded = parse(hex("001122334455 aabbccddeeff 0800 4500002c00000000 4006 0000 0a000001 0a000002 1f90 01bb 00000001 00000000 5018 2000 0000 0000 61626364 00000000"));
    EXPECT_EQ(ethPadded.payload_length, 4u) << "frame padding is not payload";
}
