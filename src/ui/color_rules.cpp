#include "color_rules.h"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <cstdlib>

std::vector<ui::ColorRule> ui::defaultColorRules() {
    // Same idea as Wireshark's defaults: problems stand out, protocols get soft pastel backgrounds.
    return {
        {true, "Malformed packet", "malformed", 0x12272E, 0xFC0000},
        {true, "TCP reset", "tcp.flags.rst", 0xA40000, 0xFFFFFF},
        {true, "TCP problem", "tcp.analysis.flags && !tcp.analysis.window_update && !tcp.analysis.keep_alive", 0x4B1A1A, 0xFFD0D0},
        {true, "TCP SYN/FIN", "tcp.flags.syn || tcp.flags.fin", 0xA0A0A0, 0x12272E},
        {true, "ICMP", "icmp || icmpv6", 0xFCE0FF, 0x12272E},
        {true, "ARP", "arp", 0xD6E8FF, 0x12272E},
        {true, "UDP", "udp", 0xDAEEFF, 0x12272E},
        {true, "TCP", "tcp", 0xE7E6FF, 0x12272E},
    };
}

namespace {
    uint32_t mixColor(uint32_t from, uint32_t to, double amount) { // amount 0 = from, 1 = to
        uint32_t out = 0;
        for (int shift = 16; shift >= 0; shift -= 8) {
            const double a = (from >> shift) & 0xFF, b = (to >> shift) & 0xFF;
            out |= static_cast<uint32_t>(std::lround(a + (b - a) * amount)) << shift;
        }
        return out;
    }

    // Moves `fg` toward white (or black on a light background) until the text is readable on `bg`.
    uint32_t readableOn(uint32_t fg, uint32_t bg) {
        const uint32_t target = ui::relativeLuminance(bg) < 0.4 ? 0xFFFFFF : 0x000000;
        for (int step = 0; step < 30 && ui::contrastRatio(fg, bg) < 4.5; ++step) fg = mixColor(fg, target, 0.15);
        return fg;
    }
} // namespace

double ui::relativeLuminance(uint32_t rgb) {
    auto channel = [](uint32_t v) {
        const double c = v / 255.0;
        return c <= 0.03928 ? c / 12.92 : std::pow((c + 0.055) / 1.055, 2.4);
    };
    return 0.2126 * channel((rgb >> 16) & 0xFF) + 0.7152 * channel((rgb >> 8) & 0xFF) + 0.0722 * channel(rgb & 0xFF);
}

double ui::contrastRatio(uint32_t a, uint32_t b) {
    const double la = relativeLuminance(a), lb = relativeLuminance(b);
    return (std::max(la, lb) + 0.05) / (std::min(la, lb) + 0.05);
}

ui::RowColors ui::rowColorsFor(const ColorRule &rule, bool dark) {
    RowColors colors{rule.background & 0xFFFFFF, rule.foreground & 0xFFFFFF};
    if (!dark) return colors;
    // Strong rules (reset, malformed...) are already dark and keep their identity; pastels become tints of the window.
    if (relativeLuminance(colors.background) >= 0.12) {
        colors.background = mixColor(kDarkWindowBg, colors.background, 0.30);
        colors.foreground = 0xE6EBF0;
    }
    colors.foreground = readableOn(colors.foreground, colors.background);
    return colors;
}

ui::RowColors ui::selectedRowColors(bool dark) {
    return dark ? RowColors{0x1F5F78, 0xF4F8FB} : RowColors{0x0E7490, 0xFFFFFF};
}

ui::CompiledColorRules::CompiledColorRules(const std::vector<ColorRule> &rules) {
    for (const auto &rule: rules) {
        if (!rule.enabled) continue;
        auto result = filter::Filter::compile(rule.expression);
        if (!result.ok) {
            problems_.push_back(rule.name + ": " + result.error.message);
            continue;
        }
        if (result.filter.isEmpty()) continue; // an empty expression would color everything; ignore it
        entries_.push_back({rule, result.filter});
    }
}

const ui::ColorRule *ui::CompiledColorRules::match(const packet::PacketInfo &packet, const filter::Context &context) const {
    for (const auto &e: entries_) {
        if (e.filter.matches(packet, context)) return &e.rule;
    }
    return nullptr;
}

std::string ui::serializeColorRule(const ColorRule &rule) {
    auto clean = [](std::string s) {
        for (auto &c: s) if (c == '\t' || c == '\n' || c == '\r') c = ' ';
        return s;
    };
    char colors[32];
    std::snprintf(colors, sizeof(colors), "%06X\t%06X", rule.background & 0xFFFFFF, rule.foreground & 0xFFFFFF);
    return std::string(rule.enabled ? "1" : "0") + "\t" + colors + "\t" + clean(rule.name) + "\t" + clean(rule.expression);
}

bool ui::parseColorRule(const std::string &line, ColorRule &out) {
    std::vector<std::string> parts;
    size_t start = 0;
    for (int i = 0; i < 4; ++i) { // the expression (last part) may not contain tabs, so 4 cuts are enough
        const size_t tab = line.find('\t', start);
        if (tab == std::string::npos) return false;
        parts.push_back(line.substr(start, tab - start));
        start = tab + 1;
    }
    parts.push_back(line.substr(start));
    if (parts[0] != "0" && parts[0] != "1") return false;
    auto hexColor = [](const std::string &s, uint32_t &value) {
        if (s.size() != 6) return false;
        char *end = nullptr;
        value = static_cast<uint32_t>(std::strtoul(s.c_str(), &end, 16));
        return end == s.c_str() + 6;
    };
    ColorRule r;
    r.enabled = parts[0] == "1";
    if (!hexColor(parts[1], r.background) || !hexColor(parts[2], r.foreground)) return false;
    r.name = parts[3];
    r.expression = parts[4];
    out = r;
    return true;
}
