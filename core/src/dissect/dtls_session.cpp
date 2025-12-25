#include "dtls_session.h"

#include <algorithm>
#include <cstring>

namespace dissect {
    namespace {
        // memory charged per entry: the payload plus the hash node overhead
        constexpr size_t kSessionCost = sizeof(DtlsSession) + 160;
        constexpr size_t kFragmentCost = sizeof(uint64_t) + sizeof(DtlsFragmentRef) + 48;
        constexpr size_t kOutcomeCost = sizeof(uint64_t) + sizeof(DtlsRecordOutcome) + 48;
        constexpr size_t kDoneCost = sizeof(DtlsFragmentRef) + 96;

        uint64_t fnv1a(const char *p, size_t n) {
            uint64_t h = 1469598103934665603ull;
            for (size_t i = 0; i < n; ++i) h = (h ^ static_cast<uint8_t>(p[i])) * 1099511628211ull;
            return h;
        }
    } // namespace

    std::string DtlsTable::connectionKey(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, unsigned &direction) {
        const std::string a = srcIp + "/" + std::to_string(srcPort), b = dstIp + "/" + std::to_string(dstPort);
        direction = a <= b ? 0 : 1;
        return direction == 0 ? a + "|" + b : b + "|" + a;
    }

    bool DtlsTable::addHello(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, const DtlsHelloFacts &facts,
                             size_t maxMemory) {
        unsigned direction = 0;
        const std::string key = connectionKey(srcIp, srcPort, dstIp, dstPort, direction);
        const auto latest = latest_.find(key);
        bool create = latest == latest_.end();
        if (!create) {
            const DtlsSession &s = sessions_[latest->second];
            create = (facts.client && s.hasClientRandom && s.clientRandom != facts.random) ||
                     (!facts.client && s.hasServerRandom && s.serverRandom != facts.random);
        }
        uint32_t id = create ? 0 : latest->second;
        if (create) {
            const size_t cost = kSessionCost + key.size();
            if (memory() + cost > maxMemory) return false;
            id = static_cast<uint32_t>(sessions_.size());
            sessions_.emplace_back();
            latest_[key] = id;
            memory_ += cost;
        }
        DtlsSession &s = sessions_[id];
        if (facts.client) {
            if (!s.hasClientRandom) { s.clientRandom = facts.random; s.hasClientRandom = true; }
            s.clientDirection = static_cast<int8_t>(direction);
        } else {
            if (!s.hasServerRandom) { s.serverRandom = facts.random; s.hasServerRandom = true; }
            if (s.clientDirection < 0) s.clientDirection = static_cast<int8_t>(1 - direction);
            s.version = facts.version;
            s.cipherSuite = facts.cipherSuite;
        }
        return true;
    }

    uint32_t DtlsTable::find(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, unsigned *direction) const {
        unsigned d = 0;
        const auto it = latest_.find(connectionKey(srcIp, srcPort, dstIp, dstPort, d));
        if (direction) *direction = d;
        return it == latest_.end() ? kDtlsNone : it->second;
    }

    const DtlsFragmentRef *DtlsTable::fragment(uint32_t packet, uint16_t position) const {
        const auto it = fragments_.find(positionKey(packet, position));
        return it == fragments_.end() ? nullptr : &it->second;
    }

    const DtlsRecordOutcome *DtlsTable::outcome(uint32_t packet, uint16_t position) const {
        const auto it = outcomes_.find(positionKey(packet, position));
        return it == outcomes_.end() ? nullptr : &it->second;
    }

    bool DtlsTable::addOutcome(uint32_t packet, uint16_t position, const DtlsRecordOutcome &outcome, size_t maxMemory) {
        const uint64_t key = positionKey(packet, position);
        if (outcomes_.count(key)) return true;
        if (memory() + kOutcomeCost > maxMemory) return false;
        outcomes_.emplace(key, outcome);
        memory_ += kOutcomeCost;
        return true;
    }

    // A message is whole: notes it as the latest of its key and flags it when it equals the one before (a retransmission).
    void DtlsTable::complete(const std::string &key, const DtlsFragment &f, const char *body, size_t size, DtlsFragmentRef &ref) {
        ref.flags |= DtlsFragmentRef::kCompletesHere;
        const uint64_t hash = fnv1a(body, size);
        const auto it = done_.find(key);
        if (it != done_.end()) {
            if (it->second.hash == hash && it->second.length == size && it->second.type == f.type) {
                ref.flags |= DtlsFragmentRef::kRetransmission;
                ref.retransmissionOf = it->second.packet;
                return;
            }
            it->second = Done{hash, static_cast<uint32_t>(size), f.type, f.packet};   // another message under the same key: the new one counts
            return;
        }
        done_.emplace(key, Done{hash, static_cast<uint32_t>(size), f.type, f.packet});
        memory_ += kDoneCost + key.size();
    }

    bool DtlsTable::addFragment(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, const DtlsFragment &f,
                                size_t maxMemory, std::vector<uint32_t> &earlierPackets) {
        earlierPackets.clear();
        const uint64_t position = positionKey(f.packet, f.position);
        if (fragments_.count(position)) return true;
        if (memory() + kFragmentCost + f.size > maxMemory) return false;

        const std::string key = srcIp + "/" + std::to_string(srcPort) + ">" + dstIp + "/" + std::to_string(dstPort) + "#" + std::to_string(f.epoch) + "." +
                                std::to_string(f.messageSeq);
        DtlsFragmentRef ref;
        if (f.offset == 0 && f.size == f.length) {                // the whole message in one fragment: nothing to reassemble
            ref.flags |= DtlsFragmentRef::kWhole;
            ref.completedIn = f.packet;
            complete(key, f, f.data, f.size, ref);
            fragments_.emplace(position, ref);
            memory_ += kFragmentCost;
            return true;
        }

        if (!reassembler_.pending(key)) {                          // the earlier fragments of a message that timed out or was evicted
            const auto stale = pending_.find(key);
            if (stale != pending_.end()) {
                memory_ -= std::min(memory_, stale->second.size() * sizeof(uint64_t) + key.size() + 64);
                pending_.erase(stale);
            }
        }
        network::DatagramFragment df;
        df.offset = f.offset;
        df.totalLength = f.length;
        df.data.assign(f.data, f.data + f.size);
        df.packetNumber = f.packet;
        df.time = f.time;
        network::DatagramReassembler::Result result = reassembler_.add(key, df);

        fragments_.emplace(position, ref);
        memory_ += kFragmentCost;
        DtlsFragmentRef &mine = fragments_[position];
        if (result.rejected) mine.flags |= DtlsFragmentRef::kRejected;
        if (result.totalConflict) {
            mine.flags |= DtlsFragmentRef::kTotalConflict;
            const auto it = pending_.find(key);
            if (it != pending_.end()) {
                memory_ -= std::min(memory_, it->second.size() * sizeof(uint64_t) + key.size() + 64);
                pending_.erase(it);
            }
        }
        if (result.conflictingOverlap) mine.flags |= DtlsFragmentRef::kConflict;
        if (result.rejected || result.totalConflict) return true;

        auto &waiting = pending_[key];
        if (waiting.empty()) memory_ += key.size() + 64;
        waiting.push_back(position);
        memory_ += sizeof(uint64_t);
        if (!result.complete) return true;

        // the message is whole: every fragment that went into it learns where
        DtlsMessage m;
        m.body.assign(result.message.begin(), result.message.end());
        m.packets = result.packetNumbers;
        memory_ += m.body.size() + m.packets.size() * sizeof(uint32_t) + 64;
        for (uint64_t p: waiting) {
            fragments_[p].completedIn = f.packet;
            const uint32_t packet = static_cast<uint32_t>(p >> 16);
            if (packet != f.packet && std::find(earlierPackets.begin(), earlierPackets.end(), packet) == earlierPackets.end()) earlierPackets.push_back(packet);
        }
        memory_ -= std::min(memory_, waiting.size() * sizeof(uint64_t) + key.size() + 64);
        pending_.erase(key);
        DtlsFragmentRef &done = fragments_[position];
        done.message = static_cast<uint32_t>(messages_.size());
        complete(key, f, m.body.data(), m.body.size(), done);
        if (result.conflictingOverlap) done.flags |= DtlsFragmentRef::kConflict;
        messages_.push_back(std::move(m));
        return true;
    }

    void DtlsTable::clear() {
        sessions_.clear();
        latest_.clear();
        fragments_.clear();
        pending_.clear();
        done_.clear();
        messages_.clear();
        outcomes_.clear();
        reassembler_ = network::DatagramReassembler();
        memory_ = 0;
    }
} // namespace dissect
