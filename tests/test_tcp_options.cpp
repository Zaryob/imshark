// TCP option decoding: SACK blocks (relative to the acknowledged direction) and Multipath TCP.
#include <gtest/gtest.h>

#include <functional>
#include <random>

#include "support.h"

using support::hex;

namespace {
    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto r = find(f.children, prefix)) return r;
        }
        return nullptr;
    }

    std::string u32(uint32_t v) { char b[16]; std::snprintf(b, sizeof b, "%08x", v); return b; }

    // TCP segment 10.0.0.1:50000 <-> 10.0.0.2:80 with raw option bytes (hex, a multiple of 4 bytes)
    std::vector<char> segment(bool fromClient, uint32_t seq, uint32_t ack, const std::string &flags, const std::string &options = "", const std::string &payload = "") {
        const size_t optBytes = options.size() / 2;
        char total[2 * sizeof(size_t) + 1], off[2 * sizeof(size_t) + 2];
        std::snprintf(total, sizeof total, "%04zx", 40 + optBytes + payload.size());
        std::snprintf(off, sizeof off, "%zx0", 5 + optBytes / 4);
        const std::string src = fromClient ? "0a000001" : "0a000002", dst = fromClient ? "0a000002" : "0a000001";
        return hex("001122334455 aabbccddeeff 0800 4500" + std::string(total) + "0000 0000 4006 0000 " + src + " " + dst + (fromClient ? " c350 0050 " : " 0050 c350 ") +
                   u32(seq) + " " + u32(ack) + " " + off + flags + " 2000 0000 0000 " + options + support::hexOf(payload));
    }

    struct Session {
        packet::PacketParser parser;
        int count = 0;
        packet::PacketInfo feed(const std::vector<char> &frame) {
            packet::PacketInfo info(++count);
            std::vector<char> data = frame;
            parser.parsePacket(info, data, dissect::ParseMode::Full);
            return info;
        }
    };
}

TEST(TcpOptions, SackBlocksAreRelativeToTheAcknowledgedDirection) {
    Session s;
    s.feed(segment(true, 1000, 0, "02"));                       // SYN
    s.feed(segment(false, 5000, 1001, "12"));                   // SYN/ACK
    s.feed(segment(true, 1001, 5001, "10"));                    // ACK
    // the server acknowledges the client's stream up to raw 2001 and reports raw 3001..4001, i.e. relative 2001..3001
    const auto p = s.feed(segment(false, 5001, 2001, "10", "0101" "050a" + u32(3001) + u32(4001) + "0000" "0000"));
    EXPECT_NE(p.info.find("SLE=2001 SRE=3001"), std::string::npos) << p.info;
    EXPECT_NE(find(p.fields, "TCP Option - SACK: 1 block(s)"), nullptr);
}

TEST(TcpOptions, SackBlocksWithoutATrackedConnectionAreRaw) {
    Session s;
    const auto p = s.feed(segment(false, 5001, 2001, "10", "0101" "050a" + u32(3001) + u32(4001) + "0000" "0000"));
    EXPECT_NE(find(p.fields, "SACK block 1:"), nullptr);
    EXPECT_NE(p.info.find("SLE="), std::string::npos) << p.info;
}

TEST(TcpOptions, SackWithTwoBlocksAndMalformedLengths) {
    Session s;
    s.feed(segment(true, 1000, 0, "02"));
    s.feed(segment(false, 5000, 1001, "12"));
    const auto two = s.feed(segment(false, 5001, 1001, "10", "0101" "0512" + u32(1501) + u32(2501) + u32(3501) + u32(4501) + "0000" "0000"));
    EXPECT_NE(find(two.fields, "TCP Option - SACK: 2 block(s)"), nullptr);
    EXPECT_NE(find(two.fields, "SACK block 1: 501-1501 (1000 bytes)"), nullptr);
    EXPECT_NE(find(two.fields, "SACK block 2: 2501-3501 (1000 bytes)"), nullptr);
    EXPECT_NE(find(two.fields, "Left Edge = 501 (relative), 1501 (raw)"), nullptr);

    // length byte 0x0b: not a multiple of 8 after the header
    const auto odd = s.feed(segment(false, 5001, 1001, "10", "0101" "050b" + u32(1501) + u32(2501) + "ff" "00" "0000"));
    EXPECT_NE(find(odd.fields, "[Malformed SACK option"), nullptr);
}

TEST(TcpOptions, CommonOptionsAndMalformedOnes) {
    Session s;
    const auto syn = s.feed(segment(true, 1000, 0, "02", "0204" "05b4" "0103" "0307" "0402" "080a" + u32(7) + u32(0)));
    EXPECT_NE(find(syn.fields, "TCP Option - Maximum segment size: 1460 bytes"), nullptr);
    EXPECT_NE(find(syn.fields, "TCP Option - Window scale: 7 (multiply by 128)"), nullptr);
    EXPECT_NE(find(syn.fields, "TCP Option - SACK permitted"), nullptr);
    EXPECT_NE(find(syn.fields, "TCP Option - Timestamps: TSval 7, TSecr 0"), nullptr);
    EXPECT_NE(find(syn.fields, "TCP Option - No-Operation (NOP)"), nullptr);

    EXPECT_NE(find(s.feed(segment(true, 1001, 0, "10", "0209" "05b4" "0000" "0000")).fields, "[Malformed option: length 9 does not fit]"), nullptr);
    EXPECT_NE(find(s.feed(segment(true, 1001, 0, "10", "0200" "0000" "0000" "0000")).fields, "[Malformed option: length 0 does not fit]"), nullptr);
    EXPECT_NE(find(s.feed(segment(true, 1001, 0, "10", "2202" "0000" "0000" "0000")).fields, "TCP Option - Fast Open: cookie request"), nullptr);
}

TEST(Mptcp, CapableAndJoin) {
    Session s;
    const auto capable = s.feed(segment(true, 1000, 0, "02", "1e0c" "01" "81" "0102030405060708"));   // MP_CAPABLE v1, flags A|H, sender key
    EXPECT_NE(find(capable.fields, "Multipath TCP: Multipath Capable (0)"), nullptr);
    EXPECT_NE(find(capable.fields, "Version: 1"), nullptr);
    EXPECT_NE(find(capable.fields, "Sender's Key: 0102030405060708"), nullptr);
    EXPECT_NE(find(capable.fields, "Flags: checksum required, HMAC-SHA256 0x81"), nullptr);

    const auto join = s.feed(segment(true, 1000, 0, "02", "1e0c" "11" "03" "aabbccdd" "11223344"));    // MP_JOIN SYN, backup, address id 3
    EXPECT_NE(find(join.fields, "Multipath TCP: Join Connection (1)"), nullptr);
    EXPECT_NE(find(join.fields, "Backup: yes"), nullptr);
    EXPECT_NE(find(join.fields, "Address ID: 3"), nullptr);
    EXPECT_NE(find(join.fields, "Receiver's Token: aabbccdd"), nullptr);
    EXPECT_NE(find(join.fields, "Sender's Random Number: 11223344"), nullptr);
}

TEST(Mptcp, DataSequenceSignalAndAddresses) {
    Session s;
    // DSS with data ACK (4 bytes) and a mapping: DSN 4 bytes, subflow seq, data-level length, checksum
    const auto dss = s.feed(segment(true, 1000, 1, "10", "1e14" "20" "05" + u32(100) + u32(5000) + u32(77) + "0400" "abcd"));
    EXPECT_NE(find(dss.fields, "Multipath TCP: Data Sequence Signal (2)"), nullptr);
    EXPECT_NE(find(dss.fields, "Data ACK: 100"), nullptr);
    EXPECT_NE(find(dss.fields, "Data Sequence Number: 5000"), nullptr);
    EXPECT_NE(find(dss.fields, "Subflow Sequence Number: 77"), nullptr);
    EXPECT_NE(find(dss.fields, "Data-level Length: 1024"), nullptr);
    EXPECT_NE(find(dss.fields, "Checksum: 0xabcd"), nullptr);

    const auto add = s.feed(segment(true, 1000, 1, "10", "1e08" "30" "02" "c0a80105" "0000"));          // ADD_ADDR v0, id 2, 192.168.1.5
    EXPECT_NE(find(add.fields, "Multipath TCP: Add Address (3)"), nullptr);
    EXPECT_NE(find(add.fields, "Address: 192.168.1.5"), nullptr);

    const auto remove = s.feed(segment(true, 1000, 1, "10", "1e05" "40" "0204" "0000" "0000"));
    EXPECT_NE(find(remove.fields, "Multipath TCP: Remove Address (4)"), nullptr);

    const auto prio = s.feed(segment(true, 1000, 1, "10", "1e04" "51" "03" "0000" "0000"));
    EXPECT_NE(find(prio.fields, "Multipath TCP: Change Subflow Priority (5)"), nullptr);
}

TEST(TcpOptions, SurviveRandomCorruption) {
    std::mt19937 rng(61);
    const std::vector<std::string> seeds = {
        "0204" "05b4" "0103" "0307" "0402" "080a" + u32(7) + u32(0),
        "0101" "0512" + u32(1501) + u32(2501) + u32(3501) + u32(4501),
        "1e0c" "01" "81" "0102030405060708" "0101" "0101",
        "1e14" "20" "05" + u32(100) + u32(5000) + u32(77) + "0400" "abcd" "0000",
        "1e08" "30" "02" "c0a80105" "0000",
    };
    for (int i = 0; i < 6000; ++i) {
        std::string opts = seeds[rng() % seeds.size()];
        std::vector<char> bytes = hex(opts);
        for (unsigned k = rng() % 5; k > 0 && !bytes.empty(); --k) bytes[rng() % bytes.size()] = static_cast<char>(rng());
        std::string text = support::hexOf(std::string(bytes.begin(), bytes.end()));
        while (text.size() % 8) text += "00";
        if (text.size() > 80) text.resize(80);
        auto frame = segment(rng() % 2, static_cast<uint32_t>(rng()), static_cast<uint32_t>(rng()), "10", text);
        if (rng() % 7 == 0) frame.resize(rng() % (frame.size() + 1));
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
