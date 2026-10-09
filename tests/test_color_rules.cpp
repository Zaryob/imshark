#include <gtest/gtest.h>

#include <ui/color_rules.h>

#include "support.h"

using support::hex;
using support::parse;

namespace {
    const char *kTcpSyn = "001122334455 aabbccddeeff 0800 4500002800000000 4006 0000 0a000001 0a000002 1f90 01bb 00000001 00000000 5002 2000 0000 0000";
    const char *kTcpRst = "001122334455 aabbccddeeff 0800 4500002800000000 4006 0000 0a000001 0a000002 1f90 01bb 00000001 00000000 5004 2000 0000 0000";
    const char *kTcpAck = "001122334455 aabbccddeeff 0800 4500002800000000 4006 0000 0a000001 0a000002 1f90 01bb 00000001 00000000 5010 2000 0000 0000";
    const char *kUdp = "001122334455 aabbccddeeff 0800 4500001c00000000 4011 0000 0a000001 0a000002 1234 1235 0008 0000";

    std::string matched(const ui::CompiledColorRules &rules, const char *frame) {
        const auto *r = rules.match(parse(hex(frame)), {});
        return r ? r->name : "";
    }
} // namespace

TEST(ColorRules, DefaultsCompileAndTheFirstMatchWins) {
    ui::CompiledColorRules rules(ui::defaultColorRules());
    EXPECT_TRUE(rules.problems().empty());
    EXPECT_EQ(matched(rules, kTcpRst), "TCP reset") << "RST beats the generic TCP rule";
    EXPECT_EQ(matched(rules, kTcpSyn), "TCP SYN/FIN");
    EXPECT_EQ(matched(rules, kTcpAck), "TCP");
    EXPECT_EQ(matched(rules, kUdp), "UDP");
    EXPECT_EQ(matched(rules, support::kArpRequest), "ARP");
    EXPECT_EQ(matched(rules, "001122334455 aabbccddeeff 88b5 0207"), "") << "no rule for unknown EtherTypes";
    EXPECT_EQ(matched(rules, "001122334455 aabbccddeeff 0800 4500003c123440004006 0000 0a000001 0a000002 1f90 01bb"), "Malformed packet");
}

TEST(ColorRules, DisabledInvalidAndEmptyRulesAreSkipped) {
    std::vector<ui::ColorRule> list = {
        {false, "off", "tcp", 0x111111, 0x222222},
        {true, "broken", "tcp &&", 0x333333, 0x444444},
        {true, "empty", "", 0x555555, 0x666666},
        {true, "ok", "tcp", 0x777777, 0x888888},
    };
    ui::CompiledColorRules rules(list);
    EXPECT_EQ(matched(rules, kTcpAck), "ok");
    ASSERT_EQ(rules.problems().size(), 1u);
    EXPECT_NE(rules.problems()[0].find("broken"), std::string::npos);
    EXPECT_EQ(ui::CompiledColorRules().match(parse(hex(kTcpAck)), {}), nullptr) << "no rules, no colors";
}

TEST(ColorRules, RulesSeeTheFilterContext) {
    std::vector<ui::ColorRule> list = {{true, "slow", "frame.time_delta > 1", 0x123456, 0x654321}};
    ui::CompiledColorRules rules(list);
    auto a = parse(hex(kTcpAck)), b = a;
    a.time = 0;
    b.time = 2.5;
    filter::Context ctx;
    ctx.previous = &a;
    ASSERT_NE(rules.match(b, ctx), nullptr);
    EXPECT_EQ(rules.match(b, ctx)->background, 0x123456u);
    EXPECT_EQ(rules.match(a, {}), nullptr);
}

TEST(ColorRules, SerializeRoundTrip) {
    ui::ColorRule r{false, "My rule", "tcp.port == 80 && info contains \"x y\"", 0xABCDEF, 0x010203};
    ui::ColorRule back;
    ASSERT_TRUE(ui::parseColorRule(ui::serializeColorRule(r), back));
    EXPECT_EQ(back, r);

    ui::ColorRule tricky{true, "tab\there\nnew", "tcp\t&&\nudp", 0, 0xFFFFFF};
    ASSERT_TRUE(ui::parseColorRule(ui::serializeColorRule(tricky), back));
    EXPECT_EQ(back.name, "tab here new") << "separators are replaced so one rule stays one line";
    EXPECT_EQ(back.expression, "tcp && udp");

    ui::ColorRule unused;
    for (const char *bad: {"", "1", "1\tZZZZZZ\t000000\tn\te", "2\t000000\t000000\tn\te", "1\t00000\t000000\tn\te", "1\t000000\t000000\tonly-name"}) {
        EXPECT_FALSE(ui::parseColorRule(bad, unused)) << bad;
    }
}

TEST(ColorRules, TcpAnalysisProblemsGetTheirOwnColor) {
    ui::CompiledColorRules rules(ui::defaultColorRules());
    packet::PacketInfo retrans = parse(hex(kTcpAck));
    retrans.tcp_analysis = 1; // retransmission
    const auto *r = rules.match(retrans, {});
    ASSERT_NE(r, nullptr);
    EXPECT_EQ(r->name, "TCP problem");
    retrans.tcp_analysis = 64; // window update: not a problem
    EXPECT_EQ(rules.match(retrans, {})->name, "TCP");
    retrans.tcp_analysis = 32; // keep-alive: not a problem either
    EXPECT_EQ(rules.match(retrans, {})->name, "TCP");
}

TEST(ColorRules, DarkThemeRowsKeepTheirHueAndStayReadable) {
    for (const auto &rule: ui::defaultColorRules()) {
        const auto dark = ui::rowColorsFor(rule, true);
        EXPECT_GE(ui::contrastRatio(dark.foreground, dark.background), 4.5) << rule.name;
        const auto light = ui::rowColorsFor(rule, false);
        EXPECT_EQ(light.background, rule.background) << "the light theme draws the stored colors";
        EXPECT_EQ(light.foreground, rule.foreground);
    }
    // pastel rules become dark tints instead of staying light
    ui::ColorRule pastel{true, "p", "tcp", 0xE7E6FF, 0x12272E};
    EXPECT_LT(ui::relativeLuminance(ui::rowColorsFor(pastel, true).background), 0.1);
    // user rules with arbitrary colors are still made readable
    for (uint32_t bg: {0x000000u, 0xFFFFFFu, 0x808080u, 0xFFFF00u, 0x00FF00u, 0xFF0000u}) {
        for (uint32_t fg: {0x000000u, 0xFFFFFFu, 0x808080u}) {
            const auto colors = ui::rowColorsFor({true, "x", "tcp", bg, fg}, true);
            EXPECT_GE(ui::contrastRatio(colors.foreground, colors.background), 4.5) << std::hex << bg << " " << fg;
        }
    }
}

TEST(ColorRules, SelectedRowIsReadableInBothThemes) {
    for (bool dark: {true, false}) {
        const auto colors = ui::selectedRowColors(dark);
        EXPECT_GE(ui::contrastRatio(colors.foreground, colors.background), 4.5);
    }
}
