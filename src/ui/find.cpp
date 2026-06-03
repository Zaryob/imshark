#include "find.h"

#include <algorithm>
#include <cctype>

#include <filter/filter.h>

namespace {
    bool icontains(const std::string &haystack, const std::string &lowerNeedle) {
        if (lowerNeedle.empty()) return true;
        return std::search(haystack.begin(), haystack.end(), lowerNeedle.begin(), lowerNeedle.end(), [](char a, char b) {
                   return std::tolower(static_cast<unsigned char>(a)) == b;
               }) != haystack.end();
    }
} // namespace

ui::FindResult ui::findPacket(const std::vector<packet::PacketInfo> &packets, const std::vector<uint32_t> &order,
                              double captureStartEpoch, FindMode mode, const std::string &query, int fromPosition, bool forward) {
    FindResult result;
    const int n = static_cast<int>(order.size());
    if (n == 0 || query.empty()) return result;

    filter::Filter compiled;
    std::string needle;
    if (mode == FindMode::Filter) {
        auto r = filter::Filter::compile(query);
        if (!r.ok) {
            result.error = r.error.message + " (at position " + std::to_string(r.error.position + 1) + ")";
            return result;
        }
        compiled = r.filter;
    } else {
        needle = query;
        for (auto &c: needle) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }

    auto matches = [&](int position) {
        const auto &p = packets[order[position]];
        if (mode == FindMode::Text) {
            return icontains(p.info, needle) || icontains(p.protocol, needle) || icontains(p.source, needle) ||
                   icontains(p.destination, needle);
        }
        filter::Context context;
        context.captureStartEpoch = captureStartEpoch;
        context.previous = order[position] ? &packets[order[position] - 1] : nullptr;
        return compiled.matches(p, context);
    };

    // visit every row once, starting next to `fromPosition`, wrapping around
    for (int step = 1; step <= n; ++step) {
        const int position = forward ? (fromPosition + step + n) % n : ((fromPosition - step) % n + n) % n;
        // from -1 going forward the first row is visited first; from -1 going backward the last one
        const int pos = fromPosition < 0 ? (forward ? step - 1 : n - step) : position;
        if (matches(pos)) {
            result.position = pos;
            return result;
        }
    }
    return result;
}
