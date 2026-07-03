#include "ip_reassembly.h"

#include <algorithm>

bool network::assembleIpv4Payload(const std::vector<IpFragment> &fragments, std::vector<char> &payload) {
    // total size from the last fragment
    uint64_t total = 0;
    bool haveLast = false;
    for (const auto &f: fragments) {
        if (!f.moreFragments) {
            const uint64_t end = static_cast<uint64_t>(f.offset) + f.data.size();
            if (!haveLast || end > total) total = end;
            haveLast = true;
        }
    }
    if (!haveLast || total == 0 || total > (1ull << 20) * 64) return false; // the IPv4 maximum is 65535; be generous but bounded

    std::vector<char> out(static_cast<size_t>(total));
    std::vector<bool> filled(static_cast<size_t>(total), false);
    for (const auto &f: fragments) {
        if (f.offset >= total) continue;
        const size_t n = std::min<uint64_t>(f.data.size(), total - f.offset);
        for (size_t i = 0; i < n; ++i) {
            if (!filled[f.offset + i]) { // the first copy of a byte wins
                out[f.offset + i] = f.data[i];
                filled[f.offset + i] = true;
            }
        }
    }
    if (std::find(filled.begin(), filled.end(), false) != filled.end()) return false; // a hole
    payload = std::move(out);
    return true;
}

network::IpReassembler::Result network::IpReassembler::add(const std::string &key, const IpFragment &fragment) {
    Result result;
    auto it = sets_.find(key);
    if (it == sets_.end()) {
        // make room: drop the oldest incomplete datagrams
        while (!sets_.empty() && (sets_.size() >= kMaxPending || totalBytes_ + fragment.data.size() > kMaxPendingBytes)) {
            auto oldest = std::min_element(sets_.begin(), sets_.end(), [](const auto &a, const auto &b) { return a.second.order < b.second.order; });
            totalBytes_ -= oldest->second.bytes;
            sets_.erase(oldest);
        }
        it = sets_.emplace(key, Set{}).first;
        it->second.order = counter_++;
    }

    Set &set = it->second;
    set.fragments.push_back(fragment);
    set.bytes += fragment.data.size();
    totalBytes_ += fragment.data.size();

    if (assembleIpv4Payload(set.fragments, result.payload)) {
        result.complete = true;
        for (const auto &f: set.fragments) result.fragmentNumbers.push_back(f.packetNumber);
        std::sort(result.fragmentNumbers.begin(), result.fragmentNumbers.end());
        result.fragmentNumbers.erase(std::unique(result.fragmentNumbers.begin(), result.fragmentNumbers.end()), result.fragmentNumbers.end());
        totalBytes_ -= set.bytes;
        sets_.erase(it);
    }
    return result;
}
