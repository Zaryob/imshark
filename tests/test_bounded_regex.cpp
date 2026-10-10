#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

#include <filter/bounded_regex.h>
#include <filter/filter.h>
#include <packet/packet_info.h>

namespace {
    using filter::BoundedRegex;
    using Outcome = BoundedRegex::Outcome;

    BoundedRegex regex(const std::string &pattern) {
        auto r = BoundedRegex::compile(pattern);
        EXPECT_TRUE(r.ok) << pattern << " -> " << r.message;
        return r.regex;
    }

    struct Timed {
        Outcome outcome;
        double seconds;
    };

    Timed timedSearch(const std::string &pattern, const std::string &text) {
        const auto re = regex(pattern);
        const auto t0 = std::chrono::steady_clock::now();
        const Outcome o = re.search(text);
        return {o, std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count()};
    }
} // namespace

TEST(BoundedRegex, OrdinaryPatternsBehaveLikeBefore) {
    EXPECT_EQ(regex("^GET .*html").search("GET /index.html HTTP/1.1"), Outcome::Match);
    EXPECT_EQ(regex("^POST").search("GET /"), Outcome::NoMatch);
    EXPECT_EQ(regex("[0-9]+$").search("Len=1234"), Outcome::Match);
    EXPECT_EQ(regex("(foo|bar)baz").search("xxbarbazxx"), Outcome::Match);
    EXPECT_EQ(regex("\\bLOOKUP\\b").search("PUTFH,LOOKUP,GETATTR"), Outcome::Match);
    EXPECT_EQ(regex("\\bWRITE\\b").search("PUTFH,LOOKUP,GETATTR"), Outcome::NoMatch);
    EXPECT_EQ(regex("a\\.b").search("axb"), Outcome::NoMatch);
    EXPECT_EQ(regex("abc").search("ABC"), Outcome::NoMatch) << "case sensitive by default";
    EXPECT_EQ(regex("(?i)abc").search("xABCx"), Outcome::Match);
    EXPECT_EQ(regex("").search("anything"), Outcome::Match);
}

TEST(BoundedRegex, InvalidPatternsReportMessageAndOffset) {
    const auto r = BoundedRegex::compile("ab(cd");
    EXPECT_FALSE(r.ok);
    EXPECT_FALSE(r.message.empty());
    EXPECT_EQ(r.offset, 5u);
    EXPECT_FALSE(BoundedRegex::compile("[a-").ok);
    EXPECT_FALSE(BoundedRegex::compile("*a").ok);
    EXPECT_EQ(BoundedRegex().search("x"), Outcome::NoMatch) << "a default constructed regex never matches";
}

TEST(BoundedRegex, CatastrophicPatternsAreCutOffQuickly) {
    const std::string a(5000, 'a');
    const std::string x(5000, 'x');
    struct Case {
        const char *pattern;
        std::string text;
    };
    const Case cases[] = {
        {"(a|aa)+$", a + "b"},
        {"(a+)+[bc]", a},
        {"(x+x+)+[yz]", x},
        {"^(a*)*$", a + "b"},
        {"(a|a?)+$", a + "!"},
    };
    for (const auto &c: cases) {
        SCOPED_TRACE(c.pattern);
        const auto t = timedSearch(c.pattern, c.text);
        EXPECT_EQ(t.outcome, Outcome::LimitExceeded);
        EXPECT_LT(t.seconds, 1.0);
    }
}

TEST(BoundedRegex, FuzzerReproducerFinishesFast) {
    // the pattern libFuzzer found (fuzz_filter input `info matches "<pattern>`) that ran for over 10 s in libstdc++
    // std::regex; it may be rejected at compile time or hit the work limit, but it must come back at once
    const std::string pattern = "\x28\x69\x3f\x7c\x7c\x7f\x7c\x7c\x7c\x7c\x7c\x7c\x69\x6b\x65\x2e\xcf\x6d\x65\x73\x73\x61\x67\x65\x5f\x69\x64\x7c\x7c\x28\x7c\x7c\x7c\x7c\x69\x6b\x65\x2e\xcf\x6d\x65\x73\x73\x61\x67\x65\x5f\x69\x64\x7c\x7c\x28\xff\xff\xff\xff\xaa\xaa\xaa\xaa\x7c\xa9\xaa\xaa\xaa\xaa\xaa\xab\x02\x7c\x7c\x7c\x7c\x7c\x7c\x7c\x7c\x7c\x66\x72\x7c\x29\x5e\x66\x65\x61\x72\x6d\x62\x63\x60\x83\xff\xff\xff\xff\xaa\xaa\xaa\xaa\x7c\xa9\xaa\xaa\xaa\xaa\xaa\xab\x02\x7c\x7c\x7c\x7c\x7c\x7c\x7c\x7c\x7c\x66\x72\x7c\x29\x2b\x2b\x2b\x5e\x66\x65\x61\x72\x6d\x62\x63\x70\x83\x83\x7c\x7c\x7c\x7c\x7c\x7c\x7c\x7c\x73\x63\x74\x70\x7c\x7c\x7c\x7c\xa9\xaa\xaa\xaa\xaa\xaa\xaa\x02\x7c\x7c\x7c\x7c\x7c\x7c\x7c\x7c\x7c\x29\x5e\x66";
    const auto t0 = std::chrono::steady_clock::now();
    const auto compiled = BoundedRegex::compile(pattern);
    if (compiled.ok) {
        for (const std::string &text: {std::string(3000, 'f') + "ike.\xcf" "message_id" + std::string(3000, '|'), std::string(4000, 'a'),
                                       std::string("fearmbcp") + std::string(2000, '|') + "sctp"}) {
            compiled.regex.search(text);
        }
    }
    EXPECT_LT(std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(), 1.0);
}

TEST(BoundedRegex, BinaryAndInvalidUtf8ValuesAreSearchedWithoutError) {
    std::string binary;
    for (int i = 0; i < 256; ++i) binary.push_back(static_cast<char>(i));
    binary += "\xff\xfe\xc3\x28 tail";
    binary.push_back('\0');
    binary += "after-nul";
    EXPECT_EQ(regex("tail").search(binary), Outcome::Match);
    EXPECT_EQ(regex("after-nul$").search(binary), Outcome::Match) << "an embedded NUL does not end the value";
    EXPECT_EQ(regex("\\xff\\xfe").search(binary), Outcome::Match);
    EXPECT_EQ(regex("zzz").search(binary), Outcome::NoMatch);
    EXPECT_EQ(regex("^.").search("\xc3"), Outcome::Match) << "a truncated UTF-8 sequence is just a byte";
    EXPECT_EQ(regex("x").search(std::string_view()), Outcome::NoMatch);
}

TEST(BoundedRegex, LongValuesAreSearchedWholeWhenThePatternIsSimple) {
    const std::string big = std::string(200000, 'a') + "b";
    EXPECT_EQ(regex("^a*b$").search(big), Outcome::Match);
    EXPECT_EQ(regex("b$").search(big), Outcome::Match);
}

TEST(BoundedRegex, ConcurrentSearchesOnOneCompiledPattern) {
    const auto re = regex("^(GET|POST) /[a-z]+/(\\d+)\\.html$");
    const auto bad = regex("(a+)+[bc]");
    std::vector<std::thread> threads;
    std::atomic<int> failures{0};
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&, t] {
            for (int i = 0; i < 2000; ++i) {
                const std::string hit = "GET /abc/" + std::to_string(i * 8 + t) + ".html";
                if (re.search(hit) != Outcome::Match) ++failures;
                if (re.search(hit + "x") != Outcome::NoMatch) ++failures;
                if (i % 200 == 0 && bad.search(std::string(300, 'a')) != Outcome::LimitExceeded) ++failures;
            }
        });
    }
    for (auto &th: threads) th.join();
    EXPECT_EQ(failures.load(), 0);
}

TEST(FilterRegexLimits, ComplexPatternCountsAsNoMatchAndIsTallied) {
    const auto compiled = filter::Filter::compile("info matches \"(a+)+[bc]\"");
    ASSERT_TRUE(compiled.ok);
    packet::PacketInfo p;
    p.info = std::string(4000, 'a');
    EXPECT_EQ(compiled.filter.regexLimitHits(), 0u);
    const auto t0 = std::chrono::steady_clock::now();
    EXPECT_FALSE(compiled.filter.matches(p));
    EXPECT_FALSE(compiled.filter.matches(p));
    EXPECT_LT(std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count(), 1.0);
    EXPECT_EQ(compiled.filter.regexLimitHits(), 2u);
    compiled.filter.resetRegexLimitHits();
    EXPECT_EQ(compiled.filter.regexLimitHits(), 0u);
    p.info = "aaab";
    EXPECT_TRUE(compiled.filter.matches(p));
    EXPECT_EQ(compiled.filter.regexLimitHits(), 0u);
}

TEST(FilterRegexLimits, CompileErrorPointsIntoThePattern) {
    const std::string expr = "info matches \"ab(cd\"";
    const auto r = filter::Filter::compile(expr);
    ASSERT_FALSE(r.ok);
    EXPECT_NE(r.error.message.find("Invalid regular expression"), std::string::npos) << r.error.message;
    EXPECT_EQ(r.error.position, expr.find("ab(cd") + 5) << "the end of the pattern, where the group is still open";
}

TEST(FilterRegexLimits, ConcurrentMatchingOnOneFilter) {
    const auto compiled = filter::Filter::compile("info matches \"^GET /(a|b)+ \" || info matches \"(x+x+)+[yz]\"");
    ASSERT_TRUE(compiled.ok);
    std::vector<std::thread> threads;
    std::atomic<int> failures{0};
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&] {
            packet::PacketInfo hit, miss;
            hit.info = "GET /abab HTTP/1.1";
            miss.info = std::string(500, 'x');
            for (int i = 0; i < 300; ++i) {
                if (!compiled.filter.matches(hit)) ++failures;
                if (compiled.filter.matches(miss)) ++failures;
            }
        });
    }
    for (auto &th: threads) th.join();
    EXPECT_EQ(failures.load(), 0);
    EXPECT_EQ(compiled.filter.regexLimitHits(), 8u * 300u);
}
