#include "datagram_reassembly.h"

#include <algorithm>
#include <cstring>

void network::DatagramReassembler::evictOldest(const std::string *keep) {
    auto oldest = sets_.end();
    for (auto it = sets_.begin(); it != sets_.end(); ++it) {
        if (keep && it->first == *keep) continue;
        if (oldest == sets_.end() || it->second.order < oldest->second.order) oldest = it;
    }
    if (oldest == sets_.end()) return;
    totalBytes_ -= oldest->second.bytes;
    sets_.erase(oldest);
    ++evicted_;
}

network::DatagramReassembler::Result network::DatagramReassembler::add(const std::string &key, const DatagramFragment &fragment) {
    Result result;

    // forget messages whose reassembly time has run out
    for (auto it = sets_.begin(); it != sets_.end();) {
        if (fragment.time - it->second.firstTime > timeout_) {
            totalBytes_ -= it->second.bytes;
            it = sets_.erase(it);
            ++timedOut_;
        } else {
            ++it;
        }
    }

    const uint64_t begin = fragment.offset, end = begin + fragment.data.size();
    const uint32_t total = fragment.totalLength;
    if (total > kMaxMessageBytes || end > total || (fragment.data.empty() && total != 0)) {
        result.rejected = true;
        return result;
    }

    auto it = sets_.find(key);
    if (it != sets_.end() && it->second.total != total) {
        // the first fragment fixed the total length: the whole message is unreliable
        totalBytes_ -= it->second.bytes;
        sets_.erase(it);
        result.totalConflict = true;
        return result;
    }

    if (it == sets_.end()) {
        while (!sets_.empty() && (sets_.size() >= kMaxPending || totalBytes_ + fragment.data.size() > kMaxPendingBytes))
            evictOldest(nullptr);
        it = sets_.emplace(key, Set{}).first;
        it->second.total = total;
        it->second.order = counter_++;
        it->second.firstTime = fragment.time;
    } else {
        // the new bytes of an existing message may not push the total over the budget either
        while (sets_.size() > 1 && totalBytes_ + fragment.data.size() > kMaxPendingBytes)
            evictOldest(&key);
    }

    Set &set = it->second;
    // lay the fragment over what is stored: bytes already present keep their first copy (and are compared),
    // the gaps are filled
    uint64_t pos = begin;
    auto seg = set.segments.upper_bound(fragment.offset);
    if (seg != set.segments.begin()) --seg;     // the segment that may start before the fragment
    while (pos < end) {
        while (seg != set.segments.end() && static_cast<uint64_t>(seg->first) + seg->second.size() <= pos) ++seg;
        if (seg != set.segments.end() && seg->first <= pos) {
            // inside a stored segment
            const uint64_t segEnd = static_cast<uint64_t>(seg->first) + seg->second.size();
            const uint64_t n = std::min(end, segEnd) - pos;
            if (std::memcmp(seg->second.data() + (pos - seg->first), fragment.data.data() + (pos - begin), static_cast<size_t>(n)) != 0) {
                set.conflict = true;
                result.conflictingOverlap = true;
            }
            pos += n;
        } else {
            // a gap up to the next segment (or the end of the fragment)
            const uint64_t gapEnd = seg == set.segments.end() ? end : std::min<uint64_t>(end, seg->first);
            const auto first = fragment.data.begin() + static_cast<std::ptrdiff_t>(pos - begin);
            set.segments.emplace(static_cast<uint32_t>(pos), std::vector<char>(first, first + static_cast<std::ptrdiff_t>(gapEnd - pos)));
            set.bytes += gapEnd - pos;
            totalBytes_ += gapEnd - pos;
            pos = gapEnd;
        }
    }
    if (std::find(set.packets.begin(), set.packets.end(), fragment.packetNumber) == set.packets.end())
        set.packets.push_back(fragment.packetNumber);

    if (set.bytes == set.total) {
        result.complete = true;
        result.message.reserve(set.total);
        for (const auto &s: set.segments) result.message.insert(result.message.end(), s.second.begin(), s.second.end());
        result.packetNumbers = std::move(set.packets);
        result.conflictingOverlap = set.conflict;
        totalBytes_ -= set.bytes;
        sets_.erase(it);
    }
    return result;
}
