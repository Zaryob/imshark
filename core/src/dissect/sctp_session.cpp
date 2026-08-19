#include "sctp_session.h"

#include <algorithm>

namespace dissect {
    namespace {
        constexpr size_t kRefBytes = 64;         // one entry of the reference map
        constexpr size_t kFragmentOverhead = 96; // one held fragment besides its bytes
        constexpr size_t kKeyOverhead = 160;     // a pending / done entry besides its key text
        constexpr size_t kStreamBytes = 96;

        // is `seq` inside [first, last], counted modulo 2^32 (TSNs wrap)?
        bool inRange(uint32_t seq, uint32_t first, uint32_t last) { return static_cast<uint32_t>(seq - first) <= static_cast<uint32_t>(last - first); }
    } // namespace

    std::string SctpTable::directionKey(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort) {
        return srcIp + ":" + std::to_string(srcPort) + ">" + dstIp + ":" + std::to_string(dstPort);
    }

    // Ordered DATA is told apart by the SSN; unordered DATA has none, its fragments follow each other by TSN alone; I-DATA has the
    // MID in both cases (RFC 8260 keeps separate MID counters for ordered and unordered messages).
    std::string SctpTable::messageKey(const std::string &direction, const SctpFragment &f) {
        const bool useSsn = f.idata || !f.unordered;
        return direction + "/" + std::to_string(f.stream) + (f.idata ? "i" : "d") + (f.unordered ? "u" : "o") + std::to_string(useSsn ? f.ssn : 0);
    }

    void SctpTable::clear() {
        refs_.clear();
        pending_.clear();
        byAge_.clear();
        done_.clear();
        messages_.clear();
        streams_.clear();
        directions_.clear();
        reassembler_ = network::DatagramReassembler();
        memory_ = 0;
        counter_ = 0;
        evicted_ = 0;
    }

    const SctpFragmentRef *SctpTable::fragment(uint32_t packet, uint16_t position) const {
        const auto it = refs_.find(refKey(packet, position));
        return it == refs_.end() ? nullptr : &it->second;
    }

    bool SctpTable::storeRef(uint64_t key, const SctpFragmentRef &ref, size_t maxMemory) {
        if (memory_ + kRefBytes > maxMemory) return false;
        refs_[key] = ref;
        memory_ += kRefBytes;
        return true;
    }

    void SctpTable::dropPending(std::unordered_map<std::string, Pending>::iterator it) {
        const Pending &p = it->second;
        memory_ -= std::min(memory_, it->first.size() + kKeyOverhead + static_cast<size_t>(p.bytes) + p.fragments.size() * kFragmentOverhead);
        byAge_.erase(p.age);
        pending_.erase(it);
    }

    // Drops the oldest incomplete messages (never `keep`) until `need` more bytes fit.
    bool SctpTable::makeRoom(size_t need, size_t maxMemory, const std::string &keep, bool &evicted) {
        while (memory_ + need > maxMemory) {
            auto victim = byAge_.begin();
            if (victim != byAge_.end() && victim->second == keep) ++victim;
            if (victim == byAge_.end()) return false;
            dropPending(pending_.find(victim->second));
            ++evicted_;
            evicted = true;
        }
        return true;
    }

    SctpTable::AddResult SctpTable::addFragment(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, const SctpFragment &f,
                                                size_t maxMemory, std::vector<uint32_t> &earlierPackets) {
        AddResult result;
        const uint64_t rk = refKey(f.packet, f.position);
        if (refs_.count(rk)) return result;   // seen before (the packet was dissected twice)

        const std::string key = messageKey(directionKey(srcIp, srcPort, dstIp, dstPort), f);
        SctpFragmentRef ref;
        auto finish = [&](const SctpFragmentRef &r) {
            result.kept = storeRef(rk, r, maxMemory);
            return result;
        };

        if (f.size > network::DatagramReassembler::kMaxMessageBytes) {
            ref.flags = SctpFragmentRef::kRejected;
            return finish(ref);
        }
        // a fragment of the message completed last under this key: a retransmission
        if (const auto d = done_.find(key); d != done_.end()) {
            for (const Done &r: d->second) {
                if (!inRange(f.sequence, r.first, r.last)) continue;
                ref.flags = SctpFragmentRef::kRetransmission;
                ref.original = r.packet;
                return finish(ref);
            }
        }

        auto it = pending_.find(key);
        if (it != pending_.end()) {
            const auto held = it->second.fragments.find(f.sequence);
            if (held != it->second.fragments.end()) {
                ref.flags = SctpFragmentRef::kRetransmission;
                ref.original = held->second.packet;
                if (held->second.bytes.size() != f.size || (f.size && held->second.bytes.compare(0, f.size, f.data, f.size) != 0)) ref.flags |= SctpFragmentRef::kConflict;
                return finish(ref);
            }
            if (it->second.bytes + f.size > network::DatagramReassembler::kMaxMessageBytes) {
                ref.flags = SctpFragmentRef::kRejected;
                return finish(ref);
            }
        }

        // room for the reference, the fragment and (new key) the entry
        const size_t need = kRefBytes + f.size + kFragmentOverhead + (it == pending_.end() ? key.size() + kKeyOverhead : 0);
        if (!makeRoom(need, maxMemory, key, result.evicted)) {
            result.kept = false;
            return result;
        }
        it = pending_.find(key);   // eviction cannot drop `key`, but be safe about iterator validity
        if (it == pending_.end()) {
            it = pending_.emplace(key, Pending{}).first;
            it->second.age = ++counter_;
            it->second.stream = f.stream;
            it->second.ssn = f.ssn;
            it->second.idata = f.idata;
            it->second.unordered = f.unordered;
            byAge_[it->second.age] = key;
            memory_ += key.size() + kKeyOverhead;
        }
        Pending &p = it->second;
        Held h;
        h.packet = f.packet;
        h.position = f.position;
        h.begin = f.begin;
        h.end = f.end;
        h.ppid = f.ppid;
        h.lo = h.hi = f.sequence;
        if (f.size) h.bytes.assign(f.data, f.size);
        p.fragments.emplace(f.sequence, std::move(h));
        p.bytes += f.size;
        memory_ += f.size + kFragmentOverhead;

        // the run of neighbours around this fragment, joined in O(1) through the end points of the runs: complete when the run
        // starts with the B bit and ends with the E bit
        Held &self = p.fragments.at(f.sequence);
        uint32_t first = f.sequence, last = f.sequence;
        if (!self.begin) {
            const auto prev = p.fragments.find(f.sequence - 1);
            if (prev != p.fragments.end() && !prev->second.end) first = prev->second.lo;
        }
        if (!self.end) {
            const auto next = p.fragments.find(f.sequence + 1);
            if (next != p.fragments.end() && !next->second.begin) last = next->second.hi;
        }
        p.fragments.at(first).hi = last;
        p.fragments.at(last).lo = first;
        const bool complete = p.fragments.at(first).begin && p.fragments.at(last).end;
        if (!complete) return finish(ref);

        // complete: put the message together (B2 does it with the offsets the chain now gives)
        SctpMessage m;
        m.stream = p.stream;
        m.ssn = p.ssn;
        m.idata = p.idata;
        m.unordered = p.unordered;
        m.ppid = p.fragments.at(first).ppid;
        const std::string chainKey = key + "#" + std::to_string(first);
        uint64_t total = 0;
        for (uint32_t s = first;; ++s) {
            total += p.fragments.at(s).bytes.size();
            if (s == last) break;
        }
        std::unordered_set<uint32_t> seenPackets;
        bool ok = total <= network::DatagramReassembler::kMaxMessageBytes;
        uint64_t offset = 0;
        for (uint32_t s = first; ok; ++s) {
            const Held &h = p.fragments.at(s);
            if (seenPackets.insert(h.packet).second) m.packets.push_back(h.packet);
            if (!h.bytes.empty()) {
                network::DatagramFragment df;
                df.offset = static_cast<uint32_t>(offset);
                df.totalLength = static_cast<uint32_t>(total);
                df.data.assign(h.bytes.begin(), h.bytes.end());
                df.packetNumber = h.packet;
                df.time = f.time;
                const auto r = reassembler_.add(chainKey, df);
                if (r.rejected || r.totalConflict) ok = false;
                else if (r.complete) m.data.assign(r.message.begin(), r.message.end());
            }
            offset += h.bytes.size();
            if (s == last) break;
        }
        if (ok && total && m.data.size() != total) ok = false;

        // the chain leaves the pending state either way
        std::vector<uint64_t> chainRefs;
        for (uint32_t s = first;; ++s) {
            const Held &h = p.fragments.at(s);
            chainRefs.push_back(refKey(h.packet, h.position));
            if (s == last) break;
        }
        for (uint32_t s = first;; ++s) {
            const Held &h = p.fragments.at(s);
            memory_ -= std::min(memory_, h.bytes.size() + kFragmentOverhead);
            p.bytes -= h.bytes.size();
            p.fragments.erase(s);
            if (s == last) break;
        }
        if (p.fragments.empty()) dropPending(it);

        if (!ok) {
            ref.flags = SctpFragmentRef::kRejected;
            for (uint64_t k: chainRefs) { auto r = refs_.find(k); if (r != refs_.end()) r->second.flags |= SctpFragmentRef::kRejected; }
            return finish(ref);
        }

        for (uint32_t pk: m.packets) if (pk != f.packet) earlierPackets.push_back(pk);
        for (uint64_t k: chainRefs) { auto r = refs_.find(k); if (r != refs_.end()) r->second.completedIn = f.packet; }
        memory_ += m.data.size() + m.packets.size() * sizeof(uint32_t) + 96;
        messages_.push_back(std::move(m));
        ref.flags = SctpFragmentRef::kCompletesHere;
        ref.completedIn = f.packet;
        ref.message = static_cast<uint32_t>(messages_.size() - 1);
        // remember the range; ranges that touch merge, so a stream in order stays one range
        const bool newKey = done_.find(key) == done_.end();
        if (newKey) memory_ += key.size() + kKeyOverhead;
        auto &ranges = done_[key];
        Done nd{first, last, f.packet};
        for (bool merged = true; merged;) {
            merged = false;
            for (auto r = ranges.begin(); r != ranges.end(); ++r) {
                if (static_cast<uint32_t>(r->last + 1) == nd.first) nd.first = r->first;
                else if (static_cast<uint32_t>(nd.last + 1) == r->first) nd.last = r->last;
                else continue;
                ranges.erase(r);
                memory_ -= std::min(memory_, sizeof(Done));
                merged = true;
                break;
            }
        }
        ranges.push_back(nd);
        memory_ += sizeof(Done);
        if (ranges.size() > kMaxDonePerKey) {      // forgotten ranges: their retransmissions would look new
            ranges.erase(ranges.begin());
            memory_ -= std::min(memory_, sizeof(Done));
            result.evicted = true;
        }
        return finish(ref);
    }

    bool SctpTable::noteData(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, uint16_t stream, size_t bytes, bool endsMessage,
                             uint32_t packet, uint16_t position, size_t maxMemory) {
        const std::string dir = directionKey(srcIp, srcPort, dstIp, dstPort);
        const uint64_t at = refKey(packet, position);
        auto d = directions_.find(dir);
        if (d != directions_.end() && d->second.any && at <= d->second.lastNoted) return true;   // counted before
        const std::string key = dir + "/" + std::to_string(stream);
        auto s = streams_.find(key);
        size_t need = 0;
        if (s == streams_.end()) need += key.size() + kStreamBytes;
        if (d == directions_.end()) need += dir.size() + kStreamBytes;
        if (memory_ + need > maxMemory) return false;
        if (d == directions_.end()) d = directions_.emplace(dir, Direction{}).first;
        if (s == streams_.end()) {
            s = streams_.emplace(key, SctpStreamStats{}).first;
            ++d->second.streams;
        }
        memory_ += need;
        d->second.lastNoted = at;
        d->second.any = true;
        ++s->second.chunks;
        s->second.bytes += bytes;
        if (endsMessage) ++s->second.messages;
        return true;
    }

    const SctpStreamStats *SctpTable::stream(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, uint16_t stream) const {
        const auto it = streams_.find(directionKey(srcIp, srcPort, dstIp, dstPort) + "/" + std::to_string(stream));
        return it == streams_.end() ? nullptr : &it->second;
    }

    size_t SctpTable::streamCount(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort) const {
        const auto it = directions_.find(directionKey(srcIp, srcPort, dstIp, dstPort));
        return it == directions_.end() ? 0 : it->second.streams;
    }
} // namespace dissect
