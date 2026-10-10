#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <memory>
#include <random>

#include <dissect/protocols.h>
#include <filter/filter.h>

#include "support.h"

using support::hex;

namespace {
    std::string bytes(const std::string &hexText) { auto v = hex(hexText); return std::string(v.begin(), v.end()); }

    std::string nameHex(const std::string &name) {
        std::string out;
        size_t start = 0;
        while (start <= name.size()) {
            const size_t dot = name.find('.', start);
            const std::string label = name.substr(start, dot == std::string::npos ? std::string::npos : dot - start);
            if (!label.empty()) {
                char len[2 * sizeof(size_t) + 1];
                std::snprintf(len, sizeof len, "%02zx", label.size());
                out += len + support::hexOf(label);
            }
            if (dot == std::string::npos) break;
            start = dot + 1;
        }
        return out + "00";
    }

    std::string u16(unsigned v) { char b[8]; std::snprintf(b, sizeof b, "%04x", v); return b; }
    std::string u32(unsigned v) { char b[16]; std::snprintf(b, sizeof b, "%08x", v); return b; }

    // a resource record: name (hex, e.g. "c00c"), type, class IN, ttl, rdata (hex)
    std::string rr(const std::string &name, unsigned type, const std::string &rdata, unsigned ttl = 300) {
        return name + u16(type) + "0001" + u32(ttl) + u16(static_cast<unsigned>(rdata.size() / 2)) + rdata;
    }

    const std::string kQuestion = nameHex("example.com") + "0001" + "0001";   // example.com A IN

    // DNS message: id, flags, counts and the already encoded sections
    std::string message(unsigned id, unsigned flags, unsigned qd, unsigned an, unsigned ns, unsigned ar, const std::string &body) {
        return u16(id) + u16(flags) + u16(qd) + u16(an) + u16(ns) + u16(ar) + body;
    }

    packet::PacketInfo viaUdp(const std::string &dnsHex, const char *sport = "c350", const char *dport = "0035") {
        return support::parse(support::udpPacket("0a000001", "08080808", sport, dport, bytes(dnsHex)));
    }

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
} // namespace

TEST(Dns, QueryFillsInfoSummaryFactsAndTree) {
    const auto p = viaUdp(message(0x1234, 0x0100, 1, 0, 0, 0, kQuestion));
    EXPECT_EQ(p.protocol, "DNS");
    EXPECT_EQ(p.info, "Standard query 0x1234 A example.com");
    EXPECT_EQ(p.app_text, "example.com");
    EXPECT_EQ(p.app_type, 1);
    EXPECT_EQ(p.app_flags, 0x0100);
    EXPECT_EQ(p.app_code, 0);

    EXPECT_NE(find(p.fields, "Domain Name System (query)"), nullptr);
    EXPECT_NE(find(p.fields, "Transaction ID: 0x1234"), nullptr);
    EXPECT_NE(find(p.fields, "Flags: 0x0100 Standard query, No error"), nullptr);
    const auto *q = find(p.fields, "example.com: type A, class IN");
    ASSERT_NE(q, nullptr);
    EXPECT_EQ(q->length, 17u) << "13 bytes of name + type + class";
    EXPECT_EQ(q->offset, 14u + 20u + 8u + 12u) << "right after the 12-byte DNS header";
    EXPECT_NE(find(p.fields, "Name: example.com"), nullptr);
    EXPECT_NE(find(p.fields, ".... ...1 .... .... = Recursion desired: Do query recursively"), nullptr);
}

TEST(Dns, ResponseWithCnameChainAndAddress) {
    const std::string answers = rr("c00c", 5, nameHex("alias.example.net")) + rr("c02a", 1, "5db8d822");
    const std::string body = kQuestion + answers;
    // the A record's owner name points at the CNAME target, which starts right after the CNAME header: 12 + 17 + 12
    const std::string msg = message(0x4321, 0x8180, 1, 2, 0, 0, kQuestion + rr("c00c", 5, nameHex("alias.example.net")) + rr("c029", 1, "5db8d822"));
    (void)body;
    const auto p = viaUdp(msg);
    EXPECT_EQ(p.info, "Standard query response 0x4321 A example.com CNAME alias.example.net A 93.184.216.34");
    EXPECT_NE(find(p.fields, "example.com: type CNAME, class IN, alias.example.net"), nullptr);
    EXPECT_NE(find(p.fields, "alias.example.net: type A, class IN, 93.184.216.34"), nullptr) << "a name reached through a compression pointer";
    EXPECT_NE(find(p.fields, "Time to live: 300"), nullptr);
    EXPECT_NE(find(p.fields, "Address: 93.184.216.34"), nullptr);
    EXPECT_NE(find(p.fields, "Answers"), nullptr);
    EXPECT_EQ(find(p.fields, "Authoritative nameservers"), nullptr) << "empty sections are not shown";
}

TEST(Dns, NxdomainWithSoaAuthority) {
    const std::string soa = nameHex("ns.example.com") + nameHex("hostmaster.example.com") + u32(2024010101) + u32(7200) + u32(3600) + u32(1209600) + u32(300);
    const auto p = viaUdp(message(0x0777, 0x8183, 1, 0, 1, 0, nameHex("nope.example.com") + "0001" "0001" + rr("c00c", 6, soa)));
    EXPECT_EQ(p.app_code, 3);
    EXPECT_NE(p.info.find("Standard query response 0x777 No such name A nope.example.com SOA ns.example.com hostmaster.example.com"), std::string::npos) << p.info;
    EXPECT_NE(find(p.fields, "Reply code: No such name (3)"), nullptr);
    EXPECT_NE(find(p.fields, "Authoritative nameservers"), nullptr);
    EXPECT_NE(find(p.fields, "Primary name server: ns.example.com, Responsible authority: hostmaster.example.com, Serial: 2024010101, Minimum TTL: 300"), nullptr);
    EXPECT_TRUE(matches("dns.flags.rcode == 3 && dns.flags.response", p));
    EXPECT_TRUE(matches("dns.qry.name == \"nope.example.com\"", p));
}

TEST(Dns, OtherRecordTypes) {
    const std::string name = nameHex("example.com");
    const std::string body = name + "00ff" "0001"                                         // ANY query
        + rr("c00c", 15, u16(10) + nameHex("mail.example.com"))                           // MX
        + rr("c00c", 16, "05" + support::hexOf("hello") + "03" + support::hexOf("abc"))   // TXT with two strings
        + rr("c00c", 2, nameHex("ns1.example.com"))                                       // NS
        + rr("c00c", 28, "20010db8000000000000000000000001")                              // AAAA
        + rr("c00c", 12, nameHex("host.example.com"))                                     // PTR
        + rr("c00c", 33, u16(1) + u16(2) + u16(443) + nameHex("srv.example.com"))         // SRV
        + rr("c00c", 99, "deadbeef");                                                     // unknown type
    const auto p = viaUdp(message(0x0001, 0x8180, 1, 7, 0, 0, body));
    EXPECT_NE(p.info.find("ANY example.com MX 10 mail.example.com TXT \"hello\" \"abc\" NS ns1.example.com AAAA 2001:db8::1 PTR host.example.com SRV 1 2 443 srv.example.com TYPE99"), std::string::npos) << p.info;
    EXPECT_NE(find(p.fields, "Preference: 10, Mail Exchange: mail.example.com"), nullptr);
    EXPECT_NE(find(p.fields, "TXT: \"hello\" \"abc\""), nullptr);
    EXPECT_NE(find(p.fields, "Name Server: ns1.example.com"), nullptr);
    EXPECT_NE(find(p.fields, "AAAA Address: 2001:db8::1"), nullptr);
    EXPECT_NE(find(p.fields, "Domain Name: host.example.com"), nullptr);
    EXPECT_NE(find(p.fields, "Priority: 1, Weight: 2, Port: 443, Target: srv.example.com"), nullptr);
    EXPECT_NE(find(p.fields, "Data (4 bytes)"), nullptr) << "unknown record types show their raw length";
}

TEST(Dns, AdditionalOptRecordIsNotInTheInfoColumn) {
    const std::string opt = "00" "0029" "1000" "00000000" "0000";   // root name, OPT, UDP size 4096, no rdata
    const auto p = viaUdp(message(0x0002, 0x0100, 1, 0, 0, 1, kQuestion + opt));
    EXPECT_EQ(p.info, "Standard query 0x2 A example.com");
    EXPECT_NE(find(p.fields, "Additional records"), nullptr);
    EXPECT_NE(find(p.fields, "<Root>: type OPT, class CLASS4096, UDP payload size 4096"), nullptr);
}

TEST(Dns, ManyRecordsAreAbbreviatedInTheInfo) {
    std::string body = kQuestion;
    for (int i = 0; i < 12; ++i) body += rr("c00c", 1, "0a00000" + std::to_string(i % 10));
    const auto p = viaUdp(message(0x0003, 0x8180, 1, 12, 0, 0, body));
    EXPECT_NE(p.info.find(" ..."), std::string::npos);
    EXPECT_LT(p.info.size(), 300u);
}

TEST(Dns, OverTcpWithLengthPrefixAndMdns) {
    const std::string msg = message(0x1234, 0x0100, 1, 0, 0, 0, kQuestion);
    const std::string withLength = u16(static_cast<unsigned>(msg.size() / 2)) + msg;
    const auto tcp = support::parse(support::tcpPacket("0a000001", "08080808", "c350", "0035", "00000001", "00000001", "18", bytes(withLength)));
    EXPECT_EQ(tcp.protocol, "DNS");
    EXPECT_EQ(tcp.info, "Standard query 0x1234 A example.com");

    // the message continues in a later segment: this one is a segment of a message to be reassembled
    const std::string cut = u16(500) + msg;
    const auto partial = support::parse(support::tcpPacket("0a000001", "08080808", "c350", "0035", "00000001", "00000001", "18", bytes(cut)));
    EXPECT_NE(partial.info.find("[TCP segment of a reassembled PDU]"), std::string::npos) << partial.info;
    EXPECT_NE(partial.info.find("message continues in later segments"), std::string::npos) << partial.info << " (decoded as far as it goes)";

    const auto mdns = viaUdp(message(0, 0x0000, 1, 0, 0, 0, nameHex("printer.local") + "000c" "0001"), "14e9", "14e9");
    EXPECT_EQ(mdns.protocol, "MDNS");
    EXPECT_EQ(mdns.info, "Standard query 0x0 PTR printer.local");
    EXPECT_TRUE(matches("mdns", mdns));
    EXPECT_FALSE(matches("dns", mdns));
}

TEST(Dns, FilterFields) {
    const auto query = viaUdp(message(0x1234, 0x0100, 1, 0, 0, 0, nameHex("example.com") + "001c" "0001"));
    EXPECT_TRUE(matches("dns && !dns.flags.response", query));
    EXPECT_TRUE(matches("dns.qry.name == \"example.com\" && dns.qry.type == 28", query));
    EXPECT_TRUE(matches("dns.qry.name contains \"exam\"", query));
    EXPECT_TRUE(matches("dns.flags.rcode == 0 && !dns.flags.truncated", query));
    EXPECT_FALSE(matches("dns.qry.type == 1", query));
    EXPECT_FALSE(matches("dns.qry.name", support::parse(support::hex(support::kArpRequest)))) << "not a DNS packet";
}

TEST(Dns, MalformedMessagesAreReportedNotCrashes) {
    const std::string good = message(0x1234, 0x8180, 1, 1, 0, 0, kQuestion + rr("c00c", 1, "5db8d822"));
    for (size_t cut = 0; cut < good.size() / 2; ++cut) {
        const auto p = viaUdp(good.substr(0, cut * 2));
        EXPECT_EQ(p.protocol.rfind("DNS", 0) == 0 || p.protocol == "Malformed", true) << cut;
        if (cut < 12 + 17 + 12 + 4) {
            // anything short of a complete answer must be flagged somewhere
            EXPECT_TRUE(p.info.find("Malformed") != std::string::npos || cut >= 12 + 17 + 12 + 4) << cut << ": " << p.info;
        }
    }
    // a compression pointer pointing at itself must not loop
    const auto loop = viaUdp(message(1, 0x0100, 1, 0, 0, 0, "c00c" "0001" "0001"));
    EXPECT_NE(loop.info.find("Malformed"), std::string::npos);
    // absurd counts with no data behind them
    const auto counts = viaUdp(message(1, 0x8180, 0xffff, 0xffff, 0xffff, 0xffff, ""));
    EXPECT_NE(counts.info.find("Malformed"), std::string::npos);
}

TEST(Dns, TcpHeuristicFramerDoesNotReadPastABufferShorterThanTheLengthField) {
    // found by fuzz_packet: the segment held 0 or 1 payload bytes, and the plausibility check read the 2-byte length
    // anyway (heap-buffer-overflow under ASan). Exact-size heap buffers make the sanitizer see every extra byte read.
    for (size_t size = 0; size < 2; ++size) {
        const std::unique_ptr<char[]> exact(new char[size]);
        std::fill_n(exact.get(), size, '\x08');
        const auto frame = dissect::frameDnsTcpHeuristic(exact.get(), size);
        EXPECT_EQ(frame.kind, dissect::StreamFrame::Kind::NeedMore) << size;
    }
}

TEST(Dns, RandomisedMessagesNeverCrash) {
    std::mt19937 rng(31);
    const std::string seed = message(0x1234, 0x8180, 1, 3, 0, 0, kQuestion + rr("c00c", 5, nameHex("a.example.net")) + rr("c029", 1, "5db8d822") +
                                     rr("c00c", 15, u16(5) + nameHex("mx.example.com")));
    for (int i = 0; i < 4000; ++i) {
        auto data = bytes(seed);
        data.resize(rng() % (data.size() + 1));
        for (unsigned k = rng() % 6; k > 0 && !data.empty(); --k) data[rng() % data.size()] = static_cast<char>(rng());
        auto frame = support::udpPacket("0a000001", "08080808", "c350", "0035", data);
        packet::PacketParser parser;
        packet::PacketInfo info(1);
        parser.parsePacket(info, frame, (i % 2) ? dissect::ParseMode::Full : dissect::ParseMode::Summary);
        for (const auto &l: info.fields) {
            std::function<void(const packet::Field &)> check = [&](const packet::Field &f) {
                EXPECT_LE(size_t(f.offset) + f.length, frame.size());
                for (const auto &c: f.children) check(c);
            };
            check(l);
        }
    }
}

namespace {
    packet::PacketInfo answerWith(unsigned type, const std::string &rdata, unsigned additional = 0, const std::string &extra = "") {
        return viaUdp(message(1, 0x8180, 1, 1, 0, additional, kQuestion + rr("c00c", type, rdata) + extra));
    }
}

TEST(DnsRecords, SoaShowsAllTimers) {
    const auto p = answerWith(6, nameHex("ns.example.com") + nameHex("admin.example.com") + u32(2026010101) + u32(7200) + u32(900) + u32(1209600) + u32(300));
    EXPECT_NE(find(p.fields, "Refresh Interval: 7200 seconds"), nullptr);
    EXPECT_NE(find(p.fields, "Retry Interval: 900 seconds"), nullptr);
    EXPECT_NE(find(p.fields, "Expire limit: 1209600 seconds"), nullptr);
    EXPECT_NE(find(p.fields, "Minimum TTL: 300 seconds"), nullptr);
}

TEST(DnsRecords, EdnsOptionsExtendedRcodeAndDoBit) {
    // OPT: root name, type 41, class = payload size 1232, ttl = ext rcode 1 | version 0 | DO, options: cookie + EDE
    const std::string options = u16(10) + u16(8) + "0102030405060708" + u16(15) + u16(6) + u16(18) + support::hexOf("abcd");
    const std::string opt = "00" + u16(41) + u16(1232) + "01008000" + u16(static_cast<unsigned>(options.size() / 2)) + options;
    const auto p = viaUdp(message(2, 0x8183, 1, 0, 0, 1, kQuestion + opt));
    EXPECT_NE(p.info.find("(extended rcode 19)"), std::string::npos) << p.info;
    EXPECT_NE(find(p.fields, "Higher bits in extended RCODE: 0x01"), nullptr);
    EXPECT_NE(find(p.fields, "DO bit: Accepts DNSSEC security RRs"), nullptr);
    EXPECT_NE(find(p.fields, "Cookie: 0102030405060708"), nullptr);
    EXPECT_NE(find(p.fields, "Extended DNS error 18: abcd"), nullptr);
}

TEST(DnsRecords, DnssecRecords) {
    const auto ds = answerWith(43, u16(60485) + "0802" + std::string(64, 'a'));
    EXPECT_NE(find(ds.fields, "Key Tag: 60485"), nullptr);
    EXPECT_NE(find(ds.fields, "Algorithm: RSASHA256 (8)"), nullptr);
    EXPECT_NE(find(ds.fields, "Digest Type: SHA-256 (2)"), nullptr);
    EXPECT_NE(ds.info.find("60485 RSASHA256 SHA-256"), std::string::npos) << ds.info;

    const auto key = answerWith(48, "0101" "03" "0d" + std::string(128, '1'));
    EXPECT_NE(find(key.fields, "Algorithm: ECDSAP256SHA256 (13)"), nullptr);
    EXPECT_NE(find(key.fields, "Flags: 0x0101 (zone key) (secure entry point)"), nullptr);
    EXPECT_NE(key.info.find("Key Signing Key"), std::string::npos) << key.info;

    // RRSIG covering A, expiration 2026-01-02 03:04:05 (1767323045), inception one day earlier
    const auto sig = answerWith(46, u16(1) + "0802" + u32(300) + u32(1767323045) + u32(1767323045 - 86400) + u16(1234) + nameHex("example.com") + std::string(64, '2'));
    EXPECT_NE(find(sig.fields, "Type Covered: A"), nullptr);
    EXPECT_NE(find(sig.fields, "Signature Expiration: 2026-01-02 03:04:05 UTC"), nullptr);
    EXPECT_NE(find(sig.fields, "Signature Inception: 2026-01-01 03:04:05 UTC"), nullptr);
    EXPECT_NE(find(sig.fields, "Signer's name: example.com"), nullptr);
    EXPECT_NE(find(sig.fields, "Signature: 32 bytes"), nullptr);

    // NSEC: next name + bitmap window 0 with A (1), NS (2), SOA (6), MX (15), RRSIG (46 -> window 0, byte 5)
    const auto nsec = answerWith(47, nameHex("b.example.com") + "00" "06" "620100000002");
    EXPECT_NE(find(nsec.fields, "Next domain name: b.example.com"), nullptr);
    EXPECT_NE(find(nsec.fields, "Record types in bitmap: A NS SOA MX RRSIG"), nullptr);
}

TEST(DnsRecords, SvcbAndHttps) {
    // priority 1, target ".", alpn=h2,h3 port=8443 ipv4hint=192.0.2.1
    const std::string alpn = u16(1) + u16(6) + "02" + support::hexOf("h2") + "02" + support::hexOf("h3");
    const std::string rdata = u16(1) + "00" + alpn + u16(3) + u16(2) + u16(8443) + u16(4) + u16(4) + "c0000201";
    const auto p = answerWith(65, rdata);
    EXPECT_NE(p.info.find("HTTPS 1 <Root> alpn=h2,h3 port=8443 ipv4hint=192.0.2.1"), std::string::npos) << p.info;
    EXPECT_NE(find(p.fields, "SvcParam: alpn=h2,h3"), nullptr);
    EXPECT_NE(find(p.fields, "SvcParam: ipv4hint=192.0.2.1"), nullptr);
    EXPECT_NE(find(p.fields, "ServiceMode: priority 1"), nullptr);

    const auto alias = answerWith(64, u16(0) + nameHex("svc.example.net"));
    EXPECT_NE(find(alias.fields, "AliasMode: priority 0, target svc.example.net"), nullptr);
}

TEST(DnsRecords, UnknownAndDamagedRecordsAreShownAsRawBytes) {
    const auto unknown = answerWith(999, "deadbeef");
    EXPECT_NE(find(unknown.fields, "Data (4 bytes): deadbeef"), nullptr);
    const auto damaged = answerWith(43, "ab");                                   // DS that is too short
    EXPECT_NE(find(damaged.fields, "Data (1 bytes): ab"), nullptr);
    const auto caa = answerWith(257, "00" "05" + support::hexOf("issue") + support::hexOf("ca.test"));
    EXPECT_NE(find(caa.fields, "Tag: issue"), nullptr);
}

TEST(DnsRecords, SurviveRandomCorruption) {
    std::mt19937 rng(41);
    const std::vector<std::string> seeds = {
        message(1, 0x8180, 1, 1, 0, 0, kQuestion + rr("c00c", 46, u16(1) + "0802" + u32(300) + u32(1767323045) + u32(1767236645) + u16(1234) + nameHex("example.com") + std::string(64, '2'))),
        message(1, 0x8180, 1, 1, 0, 0, kQuestion + rr("c00c", 65, u16(1) + "00" + u16(1) + u16(6) + "02" + support::hexOf("h2") + "02" + support::hexOf("h3"))),
        message(1, 0x8180, 1, 1, 0, 1, kQuestion + rr("c00c", 50, "01" "01" + u16(10) + "02" "abcd" "04" "01020304" "00" "02" "4000")),
        message(1, 0x8183, 1, 0, 0, 1, kQuestion + "00" + u16(41) + u16(1232) + "01008000" + u16(8) + u16(10) + u16(4) + "01020304"),
    };
    for (int i = 0; i < 4000; ++i) {
        auto b = bytes(seeds[rng() % seeds.size()]);
        b.resize(rng() % (b.size() + 1));
        for (unsigned k = rng() % 5; k > 0 && !b.empty(); --k) b[rng() % b.size()] = static_cast<char>(rng());
        auto frame = support::udpPacket("0a000001", "08080808", "c350", "0035", support::hexOf(b));
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
