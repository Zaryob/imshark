#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <filter/filter.h>
#include <packet/packet_info.h>

namespace ui {
    /// A coloring rule: packets matching `expression` (a display filter) are drawn with these colors.
    struct ColorRule {
        bool enabled = true;
        std::string name;
        std::string expression;
        uint32_t background = 0xFFFFFF; // 0xRRGGBB
        uint32_t foreground = 0x12272E;

        bool operator==(const ColorRule &o) const {
            return enabled == o.enabled && name == o.name && expression == o.expression &&
                   background == o.background && foreground == o.foreground;
        }
    };

    /// Built-in rules, in priority order (the first matching rule wins).
    std::vector<ColorRule> defaultColorRules();

    /// Rules with their expressions compiled once.
    class CompiledColorRules {
    public:
        CompiledColorRules() = default;
        explicit CompiledColorRules(const std::vector<ColorRule> &rules);

        /// First enabled rule matching the packet, or nullptr.
        const ColorRule *match(const packet::PacketInfo &packet, const filter::Context &context) const;

        /// One message per rule whose expression does not compile ("<name>: <error>").
        const std::vector<std::string> &problems() const { return problems_; }

    private:
        struct Entry {
            ColorRule rule;
            filter::Filter filter;
        };
        std::vector<Entry> entries_; // only enabled rules with a valid expression
        std::vector<std::string> problems_;
    };

    /// Serialisation for the settings file: one line per rule, tab separated:
    /// enabled, background hex, foreground hex, name, expression.
    std::string serializeColorRule(const ColorRule &rule);
    bool parseColorRule(const std::string &line, ColorRule &out);
} // namespace ui
