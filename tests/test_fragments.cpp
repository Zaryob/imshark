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
    EXPECT_EQ(last.payload_length, 0u) << "the payload is not contiguous in this frame";
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
