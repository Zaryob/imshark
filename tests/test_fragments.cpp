#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <numeric>
#include <random>

#include <core.h>
#include <filter/filter.h>
#include <stats/statistics.h>

#include "support.h"

using support::hex;

namespace {
    // A UDP datagram 10.0.0.1:50000 -> 10.0.0.2:53 carrying a DNS query for example.com (37 bytes with the UDP header)
    std::vector<char> udpDatagram() {
        return hex("c350 0035 0025 0000"                                  // UDP header, length 37
                   "1234 0100 0001 0000 0000 0000 076578616d706c6503636f6d00 0001 0001");  // DNS query
    }

    // Ethernet + IPv4 fragment of `payload[offset, offset+len)`; the real offset field is in 8-byte units
    std::vector<char> fragment(const std::vector<char> &payload, size_t offset, size_t len, uint16_t id, bool more,
                               const std::string &src = "0a000001", const std::string &dst = "0a000002", const std::string &proto = "11") {
        char head[160];
        const uint16_t field = static_cast<uint16_t>((more ? 0x2000 : 0) | (offset / 8));
        std::snprintf(head, sizeof head, "001122334455 aabbccddeeff 0800 4500%04zx %04x %04x 40%s 0000 %s %s", 20 + len, id, field, proto.c_str(), src.c_str(), dst.c_str());
        auto frame = hex(head);
        frame.insert(frame.end(), payload.begin() + static_cast<long>(offset), payload.begin() + static_cast<long>(offset + len));
        return frame;
    }

    std::vector<std::vector<char>> threeFragments(uint16_t id = 0x1234) {
        const auto d = udpDatagram(); // 37 bytes: 16 + 16 + 5
        return {fragment(d, 0, 16, id, true), fragment(d, 16, 16, id, true), fragment(d, 32, 5, id, false)};
    }

    struct Loaded {
        std::string path;
        std::vector<packet::PacketInfo> packets;
        explicit Loaded(const std::vector<std::vector<char>> &frames) {
            path = support::writeTemp("fragments.pcap", support::pcapBytes(frames));
            core::FileProcessor fp;
            std::string message;
            EXPECT_TRUE(fp.processPcapFile(path, packets, message)) << message;
        }
        ~Loaded() { std::remove(path.c_str()); }
    };

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto r = find(f.children, prefix)) return r;
        }
        return nullptr;
    }
} // namespace

TEST(Fragments, InOrderDatagramIsReassembledAtTheLastFragment) {
    Loaded cap(threeFragments());
    ASSERT_EQ(cap.packets.size(), 3u);

    for (int i = 0; i < 2; ++i) {
        const auto &p = cap.packets[i];
        EXPECT_EQ(p.protocol, "IPv4") << i;
        EXPECT_EQ(p.ip_frag, 1);
        EXPECT_EQ(p.reassembled_in, 3u);
        EXPECT_NE(p.info.find("Fragmented IP protocol (proto=UDP 17, off=" + std::to_string(i * 16) + ", ID=0x1234)"), std::string::npos) << p.info;
        EXPECT_NE(p.info.find("[Reassembled in #3]"), std::string::npos) << p.info;
    }
    const auto &last = cap.packets[2];
    EXPECT_EQ(last.ip_frag, 2);
    EXPECT_EQ(last.protocol, "DNS") << "the reassembled payload was decoded";
    EXPECT_EQ(last.info, "Standard query 0x1234 A example.com");
    EXPECT_EQ(last.src_port, 50000);
    EXPECT_EQ(last.dst_port, 53);
    EXPECT_EQ(last.payload_length, 29u) << "the DNS message, positioned inside the reassembled datagram (after the UDP header)";
    EXPECT_EQ(last.payload_offset, 8u);
}

TEST(Fragments, EveryArrivalOrderGivesTheSameResultAtTheCompletingPacket) {
    const auto frags = threeFragments();
    std::vector<int> order = {0, 1, 2};
    do {
        std::vector<std::vector<char>> frames;
        for (int i: order) frames.push_back(frags[i]);
        Loaded cap(frames);
        const auto &last = cap.packets[2];
        EXPECT_EQ(last.protocol, "DNS") << order[0] << order[1] << order[2];
        EXPECT_EQ(last.info, "Standard query 0x1234 A example.com");
        EXPECT_EQ(cap.packets[0].reassembled_in, 3u);
        EXPECT_EQ(cap.packets[1].reassembled_in, 3u);
        EXPECT_EQ(cap.packets[0].ip_frag, 1);
        EXPECT_EQ(last.ip_frag, 2);
    } while (std::next_permutation(order.begin(), order.end()));
}

TEST(Fragments, MissingOrDuplicateFragmentsAndInterleavedDatagrams) {
    const auto a = threeFragments(0x1111), b = threeFragments(0x2222);
    {   // the last fragment never arrives
        Loaded cap({a[0], a[1]});
        for (const auto &p: cap.packets) {
            EXPECT_EQ(p.ip_frag, 1);
            EXPECT_EQ(p.info.find("Reassembled"), std::string::npos) << p.info;
        }
    }
    {   // duplicates change nothing
        Loaded cap({a[0], a[0], a[1], a[2]});
        EXPECT_EQ(cap.packets[3].protocol, "DNS");
        EXPECT_EQ(cap.packets[0].reassembled_in, 4u);
        EXPECT_EQ(cap.packets[1].reassembled_in, 4u);
    }
    {   // two datagrams at the same time
        Loaded cap({a[0], b[0], a[1], b[1], b[2], a[2]});
        EXPECT_EQ(cap.packets[4].protocol, "DNS");
        EXPECT_EQ(cap.packets[4].info, "Standard query 0x1234 A example.com");
        EXPECT_EQ(cap.packets[5].protocol, "DNS");
        EXPECT_EQ(cap.packets[0].reassembled_in, 6u) << "datagram A completed by its own last fragment";
        EXPECT_EQ(cap.packets[1].reassembled_in, 5u) << "datagram B completed by packet 5";
        EXPECT_EQ(cap.packets[2].reassembled_in, 6u);
        EXPECT_EQ(cap.packets[3].reassembled_in, 5u);
    }
    {   // same ID but another host: not the same datagram
        auto other = fragment(udpDatagram(), 16, 16, 0x1111, true, "0a000009");
        Loaded cap({a[0], other, a[1], a[2]});
        EXPECT_EQ(cap.packets[3].protocol, "DNS");
        EXPECT_EQ(cap.packets[1].ip_frag, 1);
        EXPECT_EQ(cap.packets[1].reassembled_in, 0u);
    }
}

TEST(Fragments, OnDemandDetailsShowTheReassembledPayloadAndMatchASequentialParse) {
    const auto frags = threeFragments();
    Loaded cap({frags[1], frags[0], frags[2]});   // out of order; packet 3 completes the datagram

    packet::PacketInfo last;
    ASSERT_TRUE(core::buildPacketDetails(cap.path, cap.packets[2], last, &cap.packets));
    EXPECT_EQ(last.protocol, "DNS");
    const auto *layer = find(last.fields, "[Reassembled IPv4 payload (37 bytes) from frames #1, #2, #3]");
    ASSERT_NE(layer, nullptr);
    EXPECT_EQ(layer->length, 0u) << "nothing in the frame to highlight";
    const auto *dns = find(layer->children, "Domain Name System");
    ASSERT_NE(dns, nullptr);
    EXPECT_NE(find(dns->children, "Questions: 1"), nullptr);
    EXPECT_NE(find(last.fields, "[Fragment: offset 32, 5 bytes, last fragment]"), nullptr);

    // the same tree as the one a sequential Full parse builds
    packet::PacketParser sequential;
    packet::PacketInfo full;
    for (size_t i = 0; i < cap.packets.size(); ++i) {
        std::vector<char> frame;
        ASSERT_TRUE(core::readPacketBytes(cap.path, cap.packets[i], frame));
        packet::PacketInfo p(static_cast<int>(i) + 1);
        sequential.parsePacket(p, frame);
        if (i == 2) full = p;
    }
    std::function<bool(const packet::Field &, const packet::Field &)> same = [&](const packet::Field &a, const packet::Field &b) {
        if (a.text != b.text || a.offset != b.offset || a.length != b.length || a.children.size() != b.children.size()) return false;
        for (size_t i = 0; i < a.children.size(); ++i) if (!same(a.children[i], b.children[i])) return false;
        return true;
    };
    ASSERT_EQ(last.fields.size(), full.fields.size());
    for (size_t i = 0; i < full.fields.size(); ++i) EXPECT_TRUE(same(last.fields[i], full.fields[i])) << full.fields[i].text;

    // an earlier fragment: its info names the completing frame, taken from the summary
    packet::PacketInfo first;
    ASSERT_TRUE(core::buildPacketDetails(cap.path, cap.packets[0], first, &cap.packets));
    EXPECT_EQ(first.info, cap.packets[0].info);
    EXPECT_NE(first.info.find("[Reassembled in #3]"), std::string::npos);
    EXPECT_NE(find(first.fields, "[Fragment: offset 16, 16 bytes, more fragments follow]"), nullptr);
    EXPECT_EQ(find(first.fields, "[Reassembled IPv4 payload"), nullptr);

    // without the list of all packets the last fragment still shows what it can
    packet::PacketInfo degraded;
    ASSERT_TRUE(core::buildPacketDetails(cap.path, cap.packets[2], degraded));
    EXPECT_EQ(find(degraded.fields, "[Reassembled IPv4 payload"), nullptr);
}

TEST(Fragments, FiltersAndStatisticsUnderstandFragments) {
    Loaded cap(threeFragments());
    auto count = [&](const std::string &expr) {
        auto r = filter::Filter::compile(expr);
        EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
        int n = 0;
        for (const auto &p: cap.packets) n += r.filter.matches(p);
        return n;
    };
    EXPECT_EQ(count("ip.fragment"), 3);
    EXPECT_EQ(count("ip.reassembled"), 1);
    EXPECT_EQ(count("ip.id == 0x1234"), 3);
    EXPECT_EQ(count("udp"), 1) << "only the reassembled datagram counts as UDP";
    EXPECT_EQ(count("dns"), 1);
    EXPECT_EQ(count("udp.port == 53"), 1);
    EXPECT_EQ(count("ip.proto == 17"), 3);
    EXPECT_EQ(count("ip.fragment && !ip.reassembled"), 2);

    const auto root = stats::protocolHierarchy(cap.packets, nullptr);
    const auto &ip = root.children.at(0).children.at(0);   // Frame > Ethernet > IPv4
    EXPECT_EQ(ip.name, "Internet Protocol Version 4");
    bool fragmentedNode = false, udpNode = false;
    for (const auto &c: ip.children) {
        if (c.name == "Fragmented IP data") { fragmentedNode = true; EXPECT_EQ(c.packets, 2u); }
        if (c.name == "User Datagram Protocol") { udpNode = true; EXPECT_EQ(c.packets, 1u); }
    }
    EXPECT_TRUE(fragmentedNode);
    EXPECT_TRUE(udpNode);
}

TEST(Fragments, BrokenFragmentsNeverCrash) {
    std::mt19937 rng(5);
    const auto frags = threeFragments();
    for (int round = 0; round < 3000; ++round) {
        std::vector<std::vector<char>> frames;
        for (int i = 0; i < 4; ++i) {
            auto f = frags[rng() % frags.size()];
            f.resize(rng() % (f.size() + 1));
            for (unsigned k = rng() % 3; k > 0 && !f.empty(); --k) f[rng() % f.size()] = static_cast<char>(rng());
            frames.push_back(f);
        }
        packet::PacketParser parser;
        int number = 0;
        for (auto &f: frames) {
            packet::PacketInfo p(++number);
            parser.parsePacket(p, f, (round % 2) ? dissect::ParseMode::Full : dissect::ParseMode::Summary);
        }
    }
}

// ---- IPv6 fragments ---------------------------------------------------------------------------------------------

namespace {
    const char *kV6Src = "20010db8000000000000000000000001", *kV6Dst = "20010db8000000000000000000000002";

    // Ethernet + IPv6 [+ extension headers] + Fragment Header + data. `before` is a hex string of headers placed in
    // front of the Fragment Header (their Next Header chain is the caller's business: `firstNext` is the IPv6 header's).
    std::vector<char> frag6(const std::vector<char> &payload, size_t offset, size_t len, uint32_t id, bool more,
                            unsigned announced = 0x11, const std::string &before = "", unsigned firstNext = 44,
                            const std::string &src = kV6Src) {
        char fh[40];
        const uint16_t field = static_cast<uint16_t>(((offset / 8) << 3) | (more ? 1 : 0));
        std::snprintf(fh, sizeof fh, "%02x00 %04x %08x", announced, field, id);
        const std::string headers = before + fh;
        const size_t payloadLen = headers.size() / 2 + len;
        char head[200];
        std::snprintf(head, sizeof head, "001122334455 aabbccddeeff 86dd 60000000 %04zx %02x 40 %s %s", payloadLen, firstNext, src.c_str(), kV6Dst);
        auto frame = hex(std::string(head) + headers);
        frame.insert(frame.end(), payload.begin() + static_cast<long>(offset), payload.begin() + static_cast<long>(offset + len));
        return frame;
    }

    std::vector<std::vector<char>> threeFragments6(uint32_t id = 0xCAFEBABE) {
        const auto d = udpDatagram();   // 37 bytes: 16 + 16 + 5
        return {frag6(d, 0, 16, id, true), frag6(d, 16, 16, id, true), frag6(d, 32, 5, id, false)};
    }
}

TEST(Fragments6, InOrderDatagramIsReassembledAtTheLastFragment) {
    Loaded cap(threeFragments6());
    ASSERT_EQ(cap.packets.size(), 3u);
    for (int i = 0; i < 2; ++i) {
        const auto &p = cap.packets[i];
        EXPECT_EQ(p.protocol, "IPv6") << i;
        EXPECT_EQ(p.ip_frag, 1);
        EXPECT_EQ(p.reassembled_in, 3u);
        EXPECT_EQ(p.ip_id, 0xCAFEBABEu);
        EXPECT_NE(p.info.find("Fragmented IPv6 protocol (proto=UDP 17, off=" + std::to_string(i * 16) + ", ID=0xcafebabe)"), std::string::npos) << p.info;
        EXPECT_NE(p.info.find("[Reassembled in #3]"), std::string::npos) << p.info;
        EXPECT_EQ(p.src_port, 0) << "a fragment never gets invented L4 fields";
    }
    const auto &last = cap.packets[2];
    EXPECT_EQ(last.ip_frag, 2);
    EXPECT_EQ(last.protocol, "DNS");
    EXPECT_EQ(last.info, "Standard query 0x1234 A example.com");
    EXPECT_EQ(last.ip_protocol, 17);
    EXPECT_EQ(last.src_port, 50000);
    EXPECT_EQ(last.dst_port, 53);
}

TEST(Fragments6, EveryArrivalOrderGivesTheSameResult) {
    const auto frags = threeFragments6();
    std::vector<int> order = {0, 1, 2};
    do {
        std::vector<std::vector<char>> frames;
        for (int i: order) frames.push_back(frags[i]);
        Loaded cap(frames);
        EXPECT_EQ(cap.packets[2].protocol, "DNS") << order[0] << order[1] << order[2];
        EXPECT_EQ(cap.packets[2].ip_frag, 2);
        EXPECT_EQ(cap.packets[0].reassembled_in, 3u);
        EXPECT_EQ(cap.packets[1].reassembled_in, 3u);
    } while (std::next_permutation(order.begin(), order.end()));
}

TEST(Fragments6, ANonFirstFragmentIsNeverReadAsAnL4Header) {
    const auto d = udpDatagram();
    // bytes of the middle fragment: "1234 0100 ..." would look like a UDP header if misread
    Loaded cap({frag6(d, 16, 16, 0x77, true)});
    ASSERT_EQ(cap.packets.size(), 1u);
    EXPECT_EQ(cap.packets[0].protocol, "IPv6");
    EXPECT_EQ(cap.packets[0].ip_frag, 1);
    EXPECT_EQ(cap.packets[0].src_port, 0);
    EXPECT_EQ(cap.packets[0].dst_port, 0);
    auto f = filter::Filter::compile("udp || dns || udp.port == 53");
    ASSERT_TRUE(f.ok);
    EXPECT_FALSE(f.filter.matches(cap.packets[0]));
    EXPECT_TRUE(filter::Filter::compile("ipv6.fragment && !ipv6.reassembled").filter.matches(cap.packets[0]));
}

TEST(Fragments6, AtomicFragmentsAreDecodedLikeAWholePacket) {
    const auto d = udpDatagram();
    Loaded cap({frag6(d, 0, 37, 5, false)});            // offset 0, M = 0
    ASSERT_EQ(cap.packets.size(), 1u);
    EXPECT_EQ(cap.packets[0].ip_frag, 0) << "nothing to wait for";
    EXPECT_EQ(cap.packets[0].protocol, "DNS");
    packet::PacketInfo details;
    ASSERT_TRUE(core::buildPacketDetails(cap.path, cap.packets[0], details, &cap.packets));
    EXPECT_NE(find(details.fields, "Fragment Header (atomic fragment, ID 0x00000005)"), nullptr);
}

TEST(Fragments6, ExtensionHeadersBeforeAndInsideTheFragmentedPart) {
    // hop-by-hop (8 bytes) in front of the Fragment Header: unfragmentable part
    const auto d = udpDatagram();
    const std::string hopByHop = "2c00 000000000000";                 // next = 44 (fragment), len 0, padding
    Loaded a({frag6(d, 0, 16, 9, true, 0x11, hopByHop, 0), frag6(d, 16, 16, 9, true, 0x11, hopByHop, 0), frag6(d, 32, 5, 9, false, 0x11, hopByHop, 0)});
    EXPECT_EQ(a.packets[2].protocol, "DNS");
    EXPECT_EQ(a.packets[0].reassembled_in, 3u);

    // a destination options header is the first thing of the fragmentable part: payload = dstopts + UDP
    std::vector<char> inner = hex("1100 000000000000");                 // dest options: next = UDP, 8 bytes
    const auto udp = udpDatagram();
    inner.insert(inner.end(), udp.begin(), udp.end());                  // 8 + 37 bytes
    Loaded b({frag6(inner, 0, 24, 3, true, 60), frag6(inner, 24, 21, 3, false, 60)});
    EXPECT_EQ(b.packets[1].protocol, "DNS") << "the chain inside the reassembled data is walked";
    EXPECT_EQ(b.packets[1].ip_protocol, 17) << "ip_protocol is the final upper layer protocol";
}

TEST(Fragments6, TcpLengthIgnoresExtensionHeaders) {
    // TCP segment with 3 payload bytes behind a hop-by-hop header
    std::vector<char> frame = hex("001122334455 aabbccddeeff 86dd 60000000 001f 00 40 20010db8000000000000000000000001 20010db8000000000000000000000002"
                                  "0600 000000000000"                                      // hop-by-hop, next = TCP
                                  "1f90 01bb 00000001 00000000 5018 2000 0000 0000 616263");
    const auto p = support::parse(frame);
    EXPECT_EQ(p.protocol, "TCP");
    EXPECT_EQ(p.tcp_len, 3u) << "the payload excludes the 8 bytes of the extension header";
    EXPECT_EQ(p.payload_length, 3u);
}

TEST(Fragments6, OverlapsDiscardTheDatagramButDuplicatesAreHarmless) {
    const auto d = udpDatagram();
    auto altered = d;
    for (size_t i = 8; i < 24; ++i) altered[i] = static_cast<char>(altered[i] ^ 0x55);

    {   // exact duplicates are fine
        const auto f = threeFragments6();
        Loaded cap({f[0], f[0], f[1], f[2]});
        EXPECT_EQ(cap.packets[3].protocol, "DNS");
    }
    {   // an overlapping fragment with different bytes (RFC 5722): nothing is reassembled
        Loaded cap({frag6(d, 0, 16, 1, true), frag6(altered, 8, 16, 1, true), frag6(d, 24, 13, 1, false)});
        for (const auto &p: cap.packets) EXPECT_EQ(p.ip_frag, 1);
        EXPECT_NE(cap.packets[1].info.find("Overlapping fragments: datagram discarded"), std::string::npos) << cap.packets[1].info;
        EXPECT_NE(cap.packets[2].protocol, "DNS");
        EXPECT_EQ(cap.packets[0].reassembled_in, 0u);
    }
}

TEST(Fragments6, ReassemblyTimesOutAndIdentifiersCanBeReused) {
    const auto frags = threeFragments6(0x11);
    packet::PacketParser parser;
    auto feed = [&](const std::vector<char> &frame, int number, double time) {
        packet::PacketInfo p(number);
        p.time = time;
        parser.parsePacket(p, frame, dissect::ParseMode::Summary);
        return p;
    };
    feed(frags[0], 1, 0.0);
    feed(frags[1], 2, 1.0);
    const auto late = feed(frags[2], 3, 100.0);          // 100 s after the first fragment: the datagram timed out
    EXPECT_EQ(late.ip_frag, 2 - 1) << "the last fragment alone cannot complete anything";
    EXPECT_NE(late.protocol, "DNS");

    // the same identifier again, long after: a new datagram that completes normally
    feed(frags[0], 4, 200.0);
    feed(frags[1], 5, 200.1);
    const auto fresh = feed(frags[2], 6, 200.2);
    EXPECT_EQ(fresh.protocol, "DNS");
    EXPECT_EQ(fresh.ip_frag, 2);
}

TEST(Fragments6, DetailsOfTheCompletingFragmentMatchASequentialParse) {
    const auto f = threeFragments6();
    Loaded cap({f[2], f[0], f[1]});                       // the datagram completes with packet 3
    packet::PacketInfo details;
    ASSERT_TRUE(core::buildPacketDetails(cap.path, cap.packets[2], details, &cap.packets));
    EXPECT_EQ(details.protocol, "DNS");
    const auto *layer = find(details.fields, "[Reassembled IPv6 payload (37 bytes) from frames #1, #2, #3]");
    ASSERT_NE(layer, nullptr);
    EXPECT_NE(find(layer->children, "Domain Name System"), nullptr);
    EXPECT_NE(find(details.fields, "Fragment Header (fragment, ID 0xcafebabe)"), nullptr);
    EXPECT_NE(find(details.fields, "Offset: 16"), nullptr) << "packet 3 here is the middle fragment (arrival order f2, f0, f1)";

    packet::PacketParser sequential;
    packet::PacketInfo full;
    for (size_t i = 0; i < cap.packets.size(); ++i) {
        std::vector<char> frame;
        ASSERT_TRUE(core::readPacketBytes(cap.path, cap.packets[i], frame));
        packet::PacketInfo p(static_cast<int>(i) + 1);
        sequential.parsePacket(p, frame);
        if (i == 2) full = p;
    }
    std::function<bool(const packet::Field &, const packet::Field &)> same = [&](const packet::Field &a, const packet::Field &b) {
        if (a.text != b.text || a.offset != b.offset || a.length != b.length || a.children.size() != b.children.size()) return false;
        for (size_t i = 0; i < a.children.size(); ++i) if (!same(a.children[i], b.children[i])) return false;
        return true;
    };
    ASSERT_EQ(details.fields.size(), full.fields.size());
    for (size_t i = 0; i < full.fields.size(); ++i) EXPECT_TRUE(same(details.fields[i], full.fields[i])) << full.fields[i].text;
    EXPECT_EQ(details.info, full.info);
}

TEST(Fragments6, TwoDatagramsWithTheSameIdFromDifferentHostsStayApart) {
    const auto d = udpDatagram();
    auto a = threeFragments6(0x42);
    std::vector<std::vector<char>> other = {frag6(d, 16, 16, 0x42, true, 0x11, "", 44, "20010db8000000000000000000000009")};
    Loaded cap({a[0], other[0], a[1], a[2]});
    EXPECT_EQ(cap.packets[3].protocol, "DNS");
    EXPECT_EQ(cap.packets[1].reassembled_in, 0u) << "the other host's fragment is not part of this datagram";
    EXPECT_EQ(cap.packets[0].reassembled_in, 4u);
}

TEST(Fragments6, BrokenFragmentsNeverCrash) {
    std::mt19937 rng(41);
    const auto frags = threeFragments6();
    for (int round = 0; round < 3000; ++round) {
        packet::PacketParser parser;
        int number = 0;
        for (int i = 0; i < 4; ++i) {
            auto f = frags[rng() % frags.size()];
            f.resize(rng() % (f.size() + 1));
            for (unsigned k = rng() % 3; k > 0 && !f.empty(); --k) f[rng() % f.size()] = static_cast<char>(rng());
            packet::PacketInfo p(++number);
            p.time = i;
            parser.parsePacket(p, f, (round % 2) ? dissect::ParseMode::Full : dissect::ParseMode::Summary);
        }
    }
}

TEST(Fragments6, FilterAndStatistics) {
    Loaded cap(threeFragments6());
    auto count = [&](const std::string &expr) {
        auto r = filter::Filter::compile(expr);
        EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
        int n = 0;
        for (const auto &p: cap.packets) n += r.filter.matches(p);
        return n;
    };
    EXPECT_EQ(count("ipv6.fragment"), 3);
    EXPECT_EQ(count("ipv6.reassembled"), 1);
    EXPECT_EQ(count("ipv6.fragment.id == 0xcafebabe"), 3);
    EXPECT_EQ(count("udp"), 1);
    EXPECT_EQ(count("ip.fragment"), 0) << "the IPv4 field does not match IPv6 packets";
    EXPECT_EQ(count("dns && ipv6.addr == 2001:db8::/32"), 1);
}

// ---- reassembled datagrams in Follow Stream ---------------------------------------------------------------------------

#include <stream/follow.h>

namespace {
    std::string streamText(const stream::Stream &s, stream::Direction d) {
        std::string out;
        for (const auto &c: s.chunks) if (c.direction == d) out += c.data;
        return out;
    }

    stream::Stream follow(const Loaded &cap, uint32_t index) {
        stream::Stream s;
        EXPECT_TRUE(stream::reassemble(cap.path, cap.packets, stream::conversationPackets(cap.packets, index), s));
        return s;
    }

    // a UDP datagram from c350 -> 0035 carrying `text`, as raw bytes
    std::vector<char> udpDatagramWith(const std::string &text) {
        std::vector<char> d = hex("c350 0035");
        const uint16_t len = static_cast<uint16_t>(8 + text.size());
        d.push_back(static_cast<char>(len >> 8));
        d.push_back(static_cast<char>(len & 0xff));
        d.push_back(0);
        d.push_back(0);
        d.insert(d.end(), text.begin(), text.end());
        return d;
    }
}

TEST(FollowFragments, UdpDatagramsSplitOverFragmentsIpv4AndIpv6) {
    const std::string big = "0123456789abcdefghijklmnopqrstuvwxyz-fragmented-payload";   // 55 bytes: needs several fragments
    const auto datagram = udpDatagramWith(big);                                             // 63 bytes

    for (bool v6: {false, true}) {
        SCOPED_TRACE(v6 ? "IPv6" : "IPv4");
        std::vector<std::vector<char>> frames;
        if (!v6) {
            frames = {support::udpPacket("0a000001", "0a000002", "c350", "0035", "before"),
                      fragment(datagram, 0, 24, 7, true), fragment(datagram, 24, 24, 7, true), fragment(datagram, 48, 15, 7, false),
                      support::udpPacket("0a000001", "0a000002", "c350", "0035", "after")};
        } else {
            // the IPv6 helper in this file uses fixed addresses; build the plain datagrams to match
            auto plain = [&](const std::string &text) {
                const auto d = udpDatagramWith(text);
                return frag6(d, 0, d.size(), 0, false);   // offset 0, M = 0: an atomic fragment is a whole packet
            };
            frames = {plain("before"), frag6(datagram, 0, 24, 7, true), frag6(datagram, 24, 24, 7, true), frag6(datagram, 48, 15, 7, false), plain("after")};
        }
        Loaded cap(frames);
        ASSERT_EQ(cap.packets.size(), 5u);
        ASSERT_EQ(cap.packets[3].ip_frag, 2);
        EXPECT_EQ(cap.packets[3].payload_length, big.size()) << "relative to the reassembled data";
        EXPECT_EQ(cap.packets[3].payload_offset, 8u) << "right behind the UDP header, not a frame offset";

        const auto s = follow(cap, 3);
        EXPECT_FALSE(s.tcp);
        EXPECT_EQ(s.packets, 3) << "before, the datagram (counted at its last fragment) and after; the earlier fragments are not separate packets";
        EXPECT_EQ(streamText(s, stream::Direction::AtoB), "before" + big + "after");
        ASSERT_EQ(s.chunks.size(), 1u) << "all in one direction";
    }
}

TEST(FollowFragments, ATcpSegmentSplitOverFragments) {
    // TCP header (20 bytes) + payload, as the IP payload of IPv4 fragments (protocol 6)
    std::vector<char> segment = hex("c350 0050 00000001 00000000 5018 2000 0000 0000");
    const std::string text = "fragmented segment payload!";
    segment.insert(segment.end(), text.begin(), text.end());                     // 20 + 27 bytes
    const auto frames = std::vector<std::vector<char>>{
        support::tcpPacket("0a000001", "0a000002", "c350", "0050", "00000000", "00000000", "02"),   // SYN, seq 0 -> data starts at 1
        fragment(segment, 0, 24, 3, true, "0a000001", "0a000002", "06"),
        fragment(segment, 24, 23, 3, false, "0a000001", "0a000002", "06"),
        support::tcpPacket("0a000001", "0a000002", "c350", "0050", "0000001c", "00000000", "18", " and more")};   // seq 28 = 1 + 27
    Loaded cap(frames);
    ASSERT_EQ(cap.packets.size(), 4u);
    EXPECT_EQ(cap.packets[2].protocol, "TCP");
    EXPECT_EQ(cap.packets[2].tcp_len, text.size());
    const auto s = follow(cap, 2);
    EXPECT_TRUE(s.tcp);
    EXPECT_EQ(streamText(s, stream::Direction::AtoB), text + " and more");
    EXPECT_EQ(s.missingBytes, 0u);
}

TEST(FollowFragments, ADatagramWhoseFragmentsAreMissingContributesNothingAndDoesNotCrash) {
    const auto datagram = udpDatagramWith("incomplete");
    Loaded cap({fragment(datagram, 0, 8, 9, true), support::udpPacket("0a000001", "0a000002", "c350", "0035", "plain")});
    const auto s = follow(cap, 1);
    EXPECT_EQ(streamText(s, stream::Direction::AtoB), "plain");
}
