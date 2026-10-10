#include <gtest/gtest.h>

#include <atomic>
#include <cctype>
#include <random>
#include <set>
#include <thread>

#include <core.h>
#include <filter/filter.h>
#include <filter/field_modules.h>
#include <filter/fields.h>

#include "support.h"

using support::hex;
using support::parse;

namespace {
    // A few hand-made packets (Ethernet + IPv4/IPv6 + TCP/UDP)
    const char *kTcpSyn = "001122334455 aabbccddeeff 0800 4500002800000000 4006 0000 0a000001 0a000002"
                          "1f90 01bb 00000001 00000000 5002 2000 0000 0000";               // 10.0.0.1:8080 -> 10.0.0.2:443 SYN
    const char *kTcpAck = "001122334455 aabbccddeeff 0800 4500002800000000 4006 0000 c0a80105 0a000002"
                          "0050 d431 00000001 00000002 5010 2000 0000 0000";               // 192.168.1.5:80 -> :54321 ACK
    const char *kUdpDns = "001122334455 aabbccddeeff 0800 4500001c00000000 4011 0000 0a000001 08080808 c350 0035 0008 0000";
    const char *kIpv6Udp = "001122334455 aabbccddeeff 86dd 60000000 0008 11 40 20010db8000000000000000000000001 20010db8000000000000000000000002 1234 1235 0008 0000";

    bool match(const std::string &expr, const packet::PacketInfo &p, const filter::Context &c = {}) {
        auto r = filter::Filter::compile(expr);
        EXPECT_TRUE(r.ok) << expr << " -> " << r.error.message;
        return r.ok && r.filter.matches(p, c);
    }

    filter::Error failure(const std::string &expr) {
        auto r = filter::Filter::compile(expr);
        EXPECT_FALSE(r.ok) << "'" << expr << "' should not compile";
        return r.error;
    }
} // namespace

TEST(Filter, EmptyExpressionMatchesEverything) {
    const auto p = parse(hex(kTcpSyn));
    for (const char *e: {"", "   ", "\t\n"}) {
        auto r = filter::Filter::compile(e);
        ASSERT_TRUE(r.ok);
        EXPECT_TRUE(r.filter.isEmpty());
        EXPECT_TRUE(r.filter.matches(p));
    }
}

TEST(Filter, ProtocolNames) {
    const auto tcp = parse(hex(kTcpSyn)), udp = parse(hex(kUdpDns)), v6 = parse(hex(kIpv6Udp)), arp = parse(hex(support::kArpRequest));
    EXPECT_TRUE(match("tcp", tcp));
    EXPECT_FALSE(match("udp", tcp));
    EXPECT_TRUE(match("ip", tcp));
    EXPECT_FALSE(match("ipv6", tcp));
    EXPECT_TRUE(match("eth", tcp));
    EXPECT_TRUE(match("udp && dns", udp));
    EXPECT_TRUE(match("ipv6 and udp", v6));
    EXPECT_FALSE(match("ip", v6));
    EXPECT_TRUE(match("arp", arp));
    EXPECT_FALSE(match("ip || tcp || udp", arp));
    EXPECT_TRUE(match("TCP", tcp)) << "names are case-insensitive";
}

TEST(Filter, NumericComparisonsAndSets) {
    const auto syn = parse(hex(kTcpSyn)), ack = parse(hex(kTcpAck));
    EXPECT_TRUE(match("tcp.dstport == 443", syn));
    EXPECT_TRUE(match("tcp.port == 8080", syn)) << "tcp.port is either port";
    EXPECT_TRUE(match("tcp.port == 443", syn));
    EXPECT_FALSE(match("tcp.port == 444", syn));
    EXPECT_TRUE(match("tcp.srcport >= 8080 && tcp.srcport <= 8080", syn));
    EXPECT_TRUE(match("tcp.srcport > 1023", syn));
    EXPECT_TRUE(match("tcp.port lt 100", ack)) << "port 80";
    EXPECT_TRUE(match("tcp.port in {80 443}", ack));
    EXPECT_TRUE(match("tcp.port in {1 2 50..100}", ack)) << "ranges";
    EXPECT_FALSE(match("tcp.port in {1 2 3}", ack));
    EXPECT_TRUE(match("tcp.flags == 0x02", syn));
    EXPECT_TRUE(match("tcp.flags == 2", syn));
    EXPECT_TRUE(match("ip.ttl == 64", syn));
    EXPECT_TRUE(match("ip.proto == 6", syn));
    EXPECT_TRUE(match("frame.len == 54", syn));
    EXPECT_TRUE(match("frame.len > 50 && frame.len < 60", syn));
    EXPECT_TRUE(match("frame.number == 1", syn));
}

TEST(Filter, NotEqualIsTheNegationOfEqual) {
    const auto syn = parse(hex(kTcpSyn)), udp = parse(hex(kUdpDns));
    EXPECT_TRUE(match("tcp.port != 80", syn));
    EXPECT_FALSE(match("tcp.port != 443", syn)) << "one of the ports is 443";
    EXPECT_TRUE(match("tcp.port != 80", udp)) << "absent field: == is false, so != is true";
    EXPECT_FALSE(match("tcp.port == 80", udp));
    EXPECT_FALSE(match("tcp.port > 0", udp)) << "absent fields never satisfy an ordering";
}

TEST(Filter, Flags) {
    const auto syn = parse(hex(kTcpSyn)), ack = parse(hex(kTcpAck)), udp = parse(hex(kUdpDns));
    EXPECT_TRUE(match("tcp.flags.syn", syn));
    EXPECT_FALSE(match("tcp.flags.ack", syn));
    EXPECT_TRUE(match("tcp.flags.ack && !tcp.flags.syn", ack));
    EXPECT_TRUE(match("tcp.flags.syn == 1", syn));
    EXPECT_TRUE(match("tcp.flags.syn == 0", ack));
    EXPECT_TRUE(match("tcp.flags.syn == true", syn));
    EXPECT_FALSE(match("tcp.flags.syn", udp)) << "not TCP at all";
    EXPECT_TRUE(match("!tcp.flags.syn", udp));
}

TEST(Filter, Addresses) {
    const auto syn = parse(hex(kTcpSyn)), ack = parse(hex(kTcpAck)), v6 = parse(hex(kIpv6Udp));
    EXPECT_TRUE(match("ip.src == 10.0.0.1", syn));
    EXPECT_TRUE(match("ip.dst == 10.0.0.2", syn));
    EXPECT_TRUE(match("ip.addr == 10.0.0.2", syn));
    EXPECT_FALSE(match("ip.src == 10.0.0.2", syn));
    EXPECT_TRUE(match("ip.addr == 10.0.0.0/8", syn));
    EXPECT_TRUE(match("ip.addr == 192.168.0.0/16", ack));
    EXPECT_FALSE(match("ip.addr == 192.168.0.0/16", syn));
    EXPECT_TRUE(match("ip.addr == 10.0.0.0/8", ack)) << "the destination is in 10/8";
    EXPECT_TRUE(match("ip.addr != 10.0.0.1", ack));
    EXPECT_FALSE(match("ip.addr != 10.0.0.1", syn));
    EXPECT_TRUE(match("ip.src in {1.1.1.1 192.168.1.0/24}", ack));
    EXPECT_TRUE(match("ipv6.src == 2001:db8::1", v6));
    EXPECT_TRUE(match("ipv6.addr == 2001:db8::/32", v6));
    EXPECT_FALSE(match("ipv6.addr == 2001:db9::/32", v6));
    EXPECT_FALSE(match("ip.addr == 10.0.0.1", v6)) << "IPv4 fields do not match IPv6 packets";
}

TEST(Filter, Text) {
    const auto dns = parse(hex(kUdpDns));
    EXPECT_TRUE(match("protocol == \"UDP\" || protocol == \"DNS\"", dns));
    EXPECT_TRUE(match("info contains \"Malformed\"", dns)) << "the DNS message is empty";
    auto p = parse(hex(kTcpSyn));
    p.info = "GET /index.html HTTP/1.1";
    EXPECT_TRUE(match("info contains \"index\"", p));
    EXPECT_FALSE(match("info contains \"INDEX\"", p)) << "contains is case-sensitive";
    EXPECT_TRUE(match("info matches \"^GET .*html\"", p));
    EXPECT_TRUE(match("info matches \"(?i)^get\"", p)) << "(?i) makes a pattern case-insensitive";
    EXPECT_FALSE(match("info matches \"^POST\"", p));
    EXPECT_TRUE(match("_ws.col.info contains \"HTTP\"", p));
    EXPECT_TRUE(match("info in {\"a\" \"GET /index.html HTTP/1.1\"}", p));
    EXPECT_TRUE(match("info contains \"quote\\\"d\"", [&] { auto q = p; q.info = "a quote\"d"; return q; }()));
}

TEST(Filter, RegexThatIsTooComplexToEvaluateIsNoMatchNotACrash) {
    // found by fuzz_filter: std::regex_search throws regex_error (error_complexity / error_stack) on some pattern and
    // input combinations, which escaped matches() and terminated the program. The expression has a pattern with
    // dozens of empty alternatives.
    const auto bytes = hex("696e666f206d617463686573202228693f7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7ca9aaaaaaaaaaaa027c7c7c7c7c7c7c7c7c667c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7c7ca9aaaaaaaaaaaa027c7c7c7c7c7c7c7c7c6672616d652e74696d655f65706f6368207c7c7c20317c7c3e7c7c7c7c7c7c7c7c7c7c7c7c8a8383837c7c7c7c7c7c7c7c7c7c7c7ca9aaaaaaaaaaaa027c7c7c7c7c7c7c7c7c66727c295e666561726d62637024206165722e7422");
    const auto compiled = filter::Filter::compile(std::string(bytes.begin(), bytes.end()));
    if (!compiled.ok) GTEST_SKIP() << "this standard library rejects the pattern at compile time";
    auto p = parse(hex(kTcpSyn));
    p.info = "GET /index.html HTTP/1.1";
    EXPECT_NO_THROW((void) compiled.filter.matches(p));
}

TEST(Filter, LogicAndPrecedence) {
    const auto syn = parse(hex(kTcpSyn));
    EXPECT_TRUE(match("udp || tcp && ip.ttl == 64", syn)) << "&& binds tighter than ||";
    EXPECT_FALSE(match("(udp || tcp) && ip.ttl == 1", syn));
    EXPECT_TRUE(match("!(udp || arp)", syn));
    EXPECT_TRUE(match("not udp and not arp", syn));
    EXPECT_TRUE(match("!!tcp", syn));
    EXPECT_TRUE(match("((((tcp))))", syn));
    EXPECT_TRUE(match("tcp.port==443&&ip.addr==10.0.0.0/8", syn)) << "no spaces needed around operators";
    EXPECT_TRUE(match("tcp.dstport eq 443 and ip.ttl ne 1", syn));
}

TEST(Filter, TimeFields) {
    packet::PacketInfo a = parse(hex(kTcpSyn)), b = a;
    a.time = 1.0;
    b.time = 3.5;
    filter::Context ctx;
    ctx.previous = &a;
    ctx.captureStartEpoch = 1700000000.0;
    EXPECT_TRUE(match("frame.time_delta > 2.4 && frame.time_delta < 2.6", b, ctx));
    EXPECT_TRUE(match("frame.time_relative == 3.5", b, ctx));
    EXPECT_TRUE(match("frame.time_epoch > 1700000003", b, ctx));
    EXPECT_TRUE(match("frame.time_delta == 0", a)) << "no previous packet";
}

TEST(Filter, MalformedPackets) {
    // full 20-byte TCP header whose data offset (15 words = 60 bytes) does not fit into the packet
    const auto badOffset = parse(hex("001122334455 aabbccddeeff 0800 4500002800000000 4006 0000 0a000001 0a000002"
                                     "1f90 01bb 00000001 00000000 f002 2000 0000 0000"));
    EXPECT_TRUE(match("malformed", badOffset));
    EXPECT_TRUE(match("tcp.port == 443 && tcp.flags.syn", badOffset)) << "ports/flags are recorded before validation";

    // a header cut short: detected as malformed, nothing to filter on
    const auto cut = parse(hex("001122334455 aabbccddeeff 0800 4500003c123440004006 0000 0a000001 0a000002 1f90 01bb"));
    EXPECT_TRUE(match("malformed", cut));
    EXPECT_TRUE(match("tcp", cut));
    EXPECT_FALSE(match("tcp.port == 443", cut));
    EXPECT_FALSE(match("malformed", parse(hex(kTcpSyn))));
}

TEST(Filter, ErrorsCarryAPosition) {
    struct Case { const char *expr; const char *messagePart; size_t position; };
    const Case cases[] = {
        {"tcpp", "Unknown field", 0},
        {"tcp && foo", "Unknown field", 7},
        {"tcp.port ==", "Missing value", 11},
        {"tcp.port == abc", "Expected a number", 12},
        {"(tcp", "Missing closing ')'", 4},
        {"tcp)", "Unexpected ')'", 3},
        {"tcp &&", "ends unexpectedly", 6},
        {"tcp & udp", "did you mean '&&'", 4},
        {"tcp = 1", "did you mean '=='", 4},
        {"info == GET", "must be quoted", 8},
        {"info == \"abc", "Unterminated string", 8},
        {"ip.addr == 1.2.3", "not a valid IP", 11},
        {"ip.addr == ::1", "IPv6 address used with an IPv4 field", 11},
        {"ipv6.addr == 10.0.0.1", "IPv4 address used with an IPv6 field", 13},
        {"ip.addr > 1.2.3.4", "cannot be compared with < or >", 8},
        {"tcp.port contains 5", "only work on text fields", 9},
        {"tcp.port in 80", "Expected '{'", 12},
        {"tcp.port in {80", "Missing closing '}'", 15},
        {"tcp.port in {}", "Empty set", 9},
        {"tcp.port in {9..1}", "Invalid range", 13},
        {"tcp.port == -5", "Expected a number", 12},
        {"info matches \"(\"", "Invalid regular expression", 13},
        {"tcp @ udp", "Unexpected character '@'", 4},
        {"tcp.port == 99999999999999999999999", "Expected a number", 12},
        {"frame.time_delta == x", "Expected a number", 20},
    };
    for (const auto &c: cases) {
        SCOPED_TRACE(c.expr);
        const auto e = failure(c.expr);
        EXPECT_NE(e.message.find(c.messagePart), std::string::npos) << e.message;
        EXPECT_EQ(e.position, c.position);
    }
}

TEST(Filter, FieldTableIsConsistent) {
    const auto infos = filter::fieldInfos();
    ASSERT_GT(infos.size(), 30u);
    std::set<std::string> seen;
    std::string previous;
    for (const auto &f: infos) {
        EXPECT_TRUE(seen.insert(f.name).second) << "duplicate field " << f.name;
        EXPECT_LT(previous, f.name) << "table must stay sorted";
        previous = f.name;
        EXPECT_EQ(f.name, [&] { std::string l = f.name; for (auto &c: l) c = static_cast<char>(std::tolower(c)); return l; }());
        EXPECT_FALSE(f.description.empty()) << f.name;
        auto r = filter::Filter::compile(f.name); // every field works as a bare presence test
        EXPECT_TRUE(r.ok) << f.name << ": " << r.error.message;
    }
}

TEST(Filter, GarbageNeverCrashes) {
    std::mt19937 rng(11);
    const char *pieces[] = {"tcp", "ip.addr", "==", "!=", "<", "(", ")", "{", "}", "&&", "||", "!", "\"", "10.0.0.1", "::", "in", "contains",
                            "matches", "80", "0x", "..", "/", "-", "and", "or", "not", "info", "\\", " ", "frame.len", "99999999999999999999"};
    const auto p = parse(hex(kTcpSyn));
    for (int i = 0; i < 20000; ++i) {
        std::string expr;
        for (int n = rng() % 10; n > 0; --n) expr += pieces[rng() % (sizeof(pieces) / sizeof(*pieces))] + std::string(rng() % 2 ? " " : "");
        auto r = filter::Filter::compile(expr);
        if (r.ok) r.filter.matches(p);
    }
}

TEST(Filter, WorksOnTheSampleCapture) {
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(fp.processPcapFile(IMSHARK_TEST_DATA_DIR "/sample.pcap", packets, message));

    auto indices = [&](const std::string &expr) {
        auto r = filter::Filter::compile(expr);
        EXPECT_TRUE(r.ok) << expr << ": " << r.error.message;
        std::vector<int> out;
        filter::Context ctx;
        for (size_t i = 0; i < packets.size(); ++i) {
            ctx.previous = i ? &packets[i - 1] : nullptr;
            if (r.filter.matches(packets[i], ctx)) out.push_back(static_cast<int>(i));
        }
        return out;
    };
    using V = std::vector<int>;
    EXPECT_EQ(indices("arp"), (V{0, 1}));
    EXPECT_EQ(indices("icmp"), (V{2, 3}));
    EXPECT_EQ(indices("dns"), (V{4, 5}));
    EXPECT_EQ(indices("tcp"), (V{6, 7, 8, 9, 10, 11, 15}));
    EXPECT_EQ(indices("udp"), (V{4, 5, 12, 13}));
    EXPECT_EQ(indices("ipv6"), (V{12}));
    EXPECT_EQ(indices("vlan"), (V{13}));
    EXPECT_EQ(indices("vlan.id == 100"), (V{13}));
    EXPECT_EQ(indices("malformed"), (V{15}));
    EXPECT_EQ(indices("tcp.flags.syn"), (V{6, 7}));
    EXPECT_EQ(indices("tcp.flags.syn && !tcp.flags.ack"), (V{6}));
    EXPECT_EQ(indices("tcp.flags.fin"), (V{10}));
    EXPECT_EQ(indices("tcp.port == 80"), (V{6, 7, 8, 9, 10}));
    EXPECT_EQ(indices("tcp.port == 25"), (V{11}));
    EXPECT_EQ(indices("smtp"), (V{11}));
    EXPECT_EQ(indices("udp.port == 53"), (V{4, 5}));
    EXPECT_EQ(indices("eth.type == 0x88cc"), (V{14}));
    EXPECT_EQ(indices("ip.addr == 8.8.8.8"), (V{4, 5}));
    EXPECT_EQ(indices("frame.number >= 15"), (V{14, 15}));
    EXPECT_EQ(indices("tcp.seq == 1 && tcp.len > 0"), (V{9}));
    EXPECT_EQ(indices("info contains \"example.com\""), (V{4, 5}));
    EXPECT_EQ(indices("frame.time_delta == 0"), (V{0}));
    V allButFirst;
    for (int i = 1; i < 16; ++i) allButFirst.push_back(i);
    EXPECT_EQ(indices("frame.time_delta > 0.2 && frame.time_delta < 0.3"), allButFirst);
}

TEST(Filter, DynamicFieldRegistration) {
    const auto tcp = parse(hex(kTcpSyn));
    EXPECT_EQ(filter::findField("myproto.magic"), nullptr);

    EXPECT_TRUE(filter::registerField({
        "myproto.magic",
        filter::FieldType::Unsigned,
        [](const packet::PacketInfo &p, const filter::Context &, filter::Values &out) {
            if (p.src_port == 8080) out.addU(42);
        },
        "My custom protocol magic field"
    }));

    const auto *def = filter::findField("myproto.magic");
    ASSERT_NE(def, nullptr);
    EXPECT_EQ(std::string(def->name), "myproto.magic");
    EXPECT_TRUE(match("myproto.magic == 42", tcp));
    EXPECT_FALSE(match("myproto.magic == 99", tcp));
}

// B4: the fields of the protocols that used to register themselves from inside their dissector must exist in a process
// that has not dissected a single packet. gtest_discover_tests runs every test in its own process, so this one is fresh
// as long as it does not parse anything first.
TEST(FilterFields, ProtocolFieldsExistBeforeAnyPacketIsDissected) {
    for (const char *expr: {"igmp.type == 17", "igmp", "igmp.group == \"224.0.0.1\"", "ospf.version == 2", "ospf.type == 1", "ospf",
                            "ospf.router_id == \"1.2.3.4\"", "ospf.area_id == \"0.0.0.0\"", "ike", "ike.version == 2", "ike.exchange_type == 34",
                            "esp", "esp.spi == 1", "esp.sequence == 7", "ah", "ah.spi == 1", "ah.sequence == 1",
                            "sctp.vtag == 1", "sctp.chunk_type == 0", "sctp.port == 38412", "ldap", "ldap.message_id == 1",
                            "ldap.protocol_op == 0", "ldap.name == \"cn=x\""}) {
        const auto f = filter::Filter::compile(expr);
        EXPECT_TRUE(f.ok) << expr;
    }
}

TEST(FilterFields, PointersStayValidWhenFieldsAreRegistered) {
    const filter::FieldDef *ttl = filter::findField("ip.ttl");
    const filter::FieldDef *igmp = filter::findField("igmp.type");
    ASSERT_NE(ttl, nullptr);
    ASSERT_NE(igmp, nullptr);
    static const char *const names[] = {"stab.a", "stab.b", "stab.c", "stab.d", "stab.e", "stab.f", "stab.g", "stab.h"};
    const filter::FieldDef *first = nullptr;
    for (const char *name: names) {
        ASSERT_TRUE(filter::registerField({name, filter::FieldType::Boolean, [](const packet::PacketInfo &, const filter::Context &, filter::Values &o) { o.addU(1); }, "stability probe"}));
        if (first == nullptr) first = filter::findField(name);
    }
    // the pointers taken before, and the first registered one, still point at the same live definitions
    EXPECT_EQ(filter::findField("ip.ttl"), ttl);
    EXPECT_EQ(filter::findField("igmp.type"), igmp);
    EXPECT_EQ(filter::findField("stab.a"), first);
    EXPECT_STREQ(ttl->name, "ip.ttl");
    EXPECT_STREQ(igmp->name, "igmp.type");
    EXPECT_STREQ(first->name, "stab.a");
}

TEST(FilterFields, NamesAreUniqueAndDuplicateRegistrationIsRejected) {
    const auto before = filter::allFields();
    // sctp.port is built in; a second definition (what sctp.cpp used to register) must be refused
    EXPECT_FALSE(filter::registerField({"sctp.port", filter::FieldType::Unsigned, [](const packet::PacketInfo &, const filter::Context &, filter::Values &) {}, "dup"}));
    EXPECT_FALSE(filter::registerField({"ospf.version", filter::FieldType::Unsigned, [](const packet::PacketInfo &, const filter::Context &, filter::Values &) {}, "dup"}));
    EXPECT_TRUE(filter::registerField({"dupcheck.once", filter::FieldType::Unsigned, [](const packet::PacketInfo &, const filter::Context &, filter::Values &) {}, "first"}));
    EXPECT_FALSE(filter::registerField({"dupcheck.once", filter::FieldType::Unsigned, [](const packet::PacketInfo &, const filter::Context &, filter::Values &) {}, "second"}));
    EXPECT_STREQ(filter::findField("dupcheck.once")->description, "first");
    EXPECT_FALSE(filter::registerField({"", filter::FieldType::Unsigned, [](const packet::PacketInfo &, const filter::Context &, filter::Values &) {}, "empty name"}));

    const auto after = filter::allFields();
    EXPECT_EQ(after.size(), before.size() + 1);
    std::set<std::string> seen;
    for (const auto &f: after) EXPECT_TRUE(seen.insert(f.name).second) << "duplicate field name " << f.name;
}

TEST(FilterFields, ConcurrentRegistrationAndLookup) {
    static const char *const names[] = {"conc.0", "conc.1", "conc.2", "conc.3", "conc.4", "conc.5", "conc.6", "conc.7"};
    std::vector<std::thread> threads;
    std::atomic<int> registered{0};
    for (int t = 0; t < 4; ++t) {
        threads.emplace_back([&] {
            for (const char *name: names) {
                if (filter::registerField({name, filter::FieldType::Boolean, [](const packet::PacketInfo &, const filter::Context &, filter::Values &o) { o.addU(1); }, "conc"})) ++registered;
                const auto *f = filter::findField("tcp.port");
                if (f == nullptr || std::string(f->name) != "tcp.port") ADD_FAILURE() << "lookup failed";
                filter::allFields();
            }
        });
    }
    for (auto &t: threads) t.join();
    EXPECT_EQ(registered.load(), 8);   // every name won by exactly one thread
    for (const char *name: names) EXPECT_NE(filter::findField(name), nullptr);
}


// ---- the field registry (B4): modules register into a FieldRegistry, duplicates and incomplete rows are refused

namespace {
    void noValue(const packet::PacketInfo &, const filter::Context &, filter::Values &) {}
}

TEST(FieldRegistry, RefusesDuplicatesAndIncompleteDefinitionsAndSaysSo) {
    filter::FieldRegistry r;
    EXPECT_TRUE(r.add({"x.one", filter::FieldType::Unsigned, noValue, "first"}));
    EXPECT_FALSE(r.add({"x.one", filter::FieldType::String, noValue, "second"}));
    EXPECT_FALSE(r.add({"", filter::FieldType::Unsigned, noValue, "no name"}));
    EXPECT_FALSE(r.add({nullptr, filter::FieldType::Unsigned, noValue, "null name"}));
    EXPECT_FALSE(r.add({"x.two", filter::FieldType::Unsigned, nullptr, "no extractor"}));
    EXPECT_EQ(r.size(), 1u);
    ASSERT_EQ(r.problems().size(), 4u);
    EXPECT_EQ(r.problems()[0], "duplicate field name: x.one");
    EXPECT_STREQ(r.sorted()[0].description, "first");
}

TEST(FieldRegistry, SortedReturnsFieldsByName) {
    filter::FieldRegistry r;
    r.addAll({{"b.b", filter::FieldType::Unsigned, noValue, "b"}, {"a.a", filter::FieldType::Unsigned, noValue, "a"}, {"c.c", filter::FieldType::Unsigned, noValue, "c"}});
    const auto s = r.sorted();
    ASSERT_EQ(s.size(), 3u);
    EXPECT_STREQ(s[0].name, "a.a");
    EXPECT_STREQ(s[2].name, "c.c");
}

TEST(FieldRegistry, TheBuiltInModulesRegisterWithoutAnyProblem) {
    // the same call that builds the table, on a registry of its own: no duplicate between modules, nothing incomplete
    filter::FieldRegistry r;
    filter::registerBuiltinFields(r);
    EXPECT_TRUE(r.problems().empty()) << (r.problems().empty() ? "" : r.problems()[0]);
    EXPECT_EQ(r.size(), filter::builtinFields().size());
}
