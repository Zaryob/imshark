#include "find.h"

#include <algorithm>
#include <cctype>
#include <cstdint>

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
                              double captureStartEpoch, FindMode mode, const std::string &query, int fromPosition, bool forward,
                              const packet::EthernetAddressTable *ethernet) {
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
        context.ethernet = ethernet;
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

std::optional<ui::ByteNeedle> ui::parseHexNeedle(const std::string &text, std::string &error) {
    std::string digits;
    for (size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == ' ' || c == ':' || c == '-' || c == '\t') continue;
        if (c == '0' && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X')) { ++i; continue; }
        if (!std::isxdigit(static_cast<unsigned char>(c))) {
            error = std::string("'") + c + "' is not a hex digit";
            return std::nullopt;
        }
        digits += c;
    }
    if (digits.empty()) {
        error = "Enter the bytes to look for, e.g. de ad be ef";
        return std::nullopt;
    }
    if (digits.size() % 2 != 0) {
        error = "Odd number of hex digits (bytes are two digits each)";
        return std::nullopt;
    }
    ByteNeedle needle;
    for (size_t i = 0; i < digits.size(); i += 2) {
        needle.bytes.push_back(static_cast<uint8_t>(std::stoi(digits.substr(i, 2), nullptr, 16)));
    }
    return needle;
}

ui::ByteNeedle ui::textNeedle(const std::string &text) {
    ByteNeedle n;
    n.ignoreCase = true;
    for (char c: text) n.bytes.push_back(static_cast<uint8_t>(c));
    return n;
}

bool ui::frameContains(const std::vector<char> &frame, const ByteNeedle &needle) {
    if (needle.bytes.empty() || frame.size() < needle.bytes.size()) return false;
    const auto lower = [](unsigned char c) { return static_cast<unsigned char>(std::tolower(c)); };
    return std::search(frame.begin(), frame.end(), needle.bytes.begin(), needle.bytes.end(), [&](char a, uint8_t b) {
               return needle.ignoreCase ? lower(static_cast<unsigned char>(a)) == lower(b) : static_cast<uint8_t>(a) == b;
           }) != frame.end();
}

ui::FindResult ui::findBytes(const std::string &capturePath, const std::vector<packet::PacketInfo> &packets,
                             const std::vector<uint32_t> &order, const ByteNeedle &needle, int fromPosition, bool forward,
                             core::ScanControl *control, bool *cancelled) {
    FindResult result;
    if (cancelled) *cancelled = false;
    const int n = static_cast<int>(order.size());
    if (n == 0 || needle.bytes.empty()) return result;

    // visit the rows once, starting next to `fromPosition`, wrapping around
    std::vector<uint32_t> visiting;
    visiting.reserve(static_cast<size_t>(n));
    for (int step = 1; step <= n; ++step) {
        const int pos = fromPosition < 0 ? (forward ? step - 1 : n - step)
                                         : (forward ? (fromPosition + step) % n : ((fromPosition - step) % n + n) % n);
        visiting.push_back(order[pos]);
    }

    int64_t matchIndex = -1;
    const bool completed = core::scanPackets(capturePath, packets, visiting, [&](const packet::PacketInfo &p, const std::vector<char> &frame) {
        if (!frameContains(frame, needle)) return true;
        matchIndex = &p - packets.data(); // `p` is a reference into `packets`
        return false;
    }, control);

    if (matchIndex >= 0) {
        const auto it = std::find(order.begin(), order.end(), static_cast<uint32_t>(matchIndex));
        if (it != order.end()) result.position = static_cast<int>(it - order.begin());
        return result;
    }
    if (!completed) {
        if (control && control->cancelRequested) { if (cancelled) *cancelled = true; }
        else result.error = "The capture file could not be read";
    }
    return result;
}
