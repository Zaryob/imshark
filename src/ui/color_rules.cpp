#include "color_rules.h"

#include <cstdio>
#include <cstdlib>

std::vector<ui::ColorRule> ui::defaultColorRules() {
    // Same idea as Wireshark's defaults: problems stand out, protocols get soft pastel backgrounds.
    return {
        {true, "Malformed packet", "malformed", 0x12272E, 0xFC0000},
        {true, "TCP reset", "tcp.flags.rst", 0xA40000, 0xFFFFFF},
        {true, "TCP SYN/FIN", "tcp.flags.syn || tcp.flags.fin", 0xA0A0A0, 0x12272E},
        {true, "ICMP", "icmp || icmpv6", 0xFCE0FF, 0x12272E},
        {true, "ARP", "arp", 0xD6E8FF, 0x12272E},
        {true, "UDP", "udp", 0xDAEEFF, 0x12272E},
        {true, "TCP", "tcp", 0xE7E6FF, 0x12272E},
    };
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
