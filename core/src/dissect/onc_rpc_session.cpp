#include "onc_rpc_session.h"

#include <algorithm>

namespace dissect {

namespace {

std::string portKey(const std::string &ip, uint16_t port, bool udp) { return ip + ":" + std::to_string(port) + (udp ? "/udp" : "/tcp"); }

} // namespace

std::string rpcConversationKey(const std::string &ipA, uint16_t portA, const std::string &ipB, uint16_t portB, bool &fromLow) {
    const std::string a = ipA + ":" + std::to_string(portA), b = ipB + ":" + std::to_string(portB);
    fromLow = a < b;
    return fromLow ? a + "|" + b : b + "|" + a;
}

void RpcTable::clear() {
    notes_.clear();
    assemblies_.clear();
    records_.clear();
    calls_.clear();
    callOrder_.clear();
    callCounter_ = 0;
    ports_.clear();
    memory_ = 0;
}

const RpcNote *RpcTable::note(uint32_t packet, int64_t seq) const {
    const auto it = notes_.find(NoteKey{packet, seq < 0 ? UINT32_MAX : static_cast<uint32_t>(seq)});
    return it == notes_.end() ? nullptr : &it->second;
}

const RpcMappedProgram *RpcTable::program(const std::string &ip, uint16_t port, bool udp, uint32_t packet) const {
    if (ports_.empty()) return nullptr;
    const auto it = ports_.find(portKey(ip, port, udp));
    if (it == ports_.end()) return nullptr;
    for (auto e = it->second.rbegin(); e != it->second.rend(); ++e) if (e->from <= packet) return &*e;
    return nullptr;
}

const RpcNote *RpcTable::observeFragment(const std::string &stream, uint32_t packet, int64_t seq, std::string_view body, bool last, uint32_t endSeq,
                                         size_t maxMemory, bool &lost) {
    const NoteKey key{packet, seq < 0 ? UINT32_MAX : static_cast<uint32_t>(seq)};
    if (const auto existing = notes_.find(key); existing != notes_.end()) return &existing->second;

    const auto reserve = [&](size_t bytes) {
        if (memory_ + bytes > maxMemory) { lost = true; return false; }
        memory_ += bytes;
        return true;
    };
    const auto release = [&](size_t bytes) { memory_ -= std::min(memory_, bytes); };

    RpcNote n;
    const bool standalone = seq < 0 || stream.empty();   // no stream state to follow (a datagram, or a segment the stream table did not frame)
    if (standalone) {
        n.flags = RpcNote::kCompletes;
        n.fragments = 1;
    } else {
        auto it = assemblies_.find(stream);
        if (it != assemblies_.end() && it->second.nextSeq != static_cast<uint32_t>(seq)) {
            // the stream does not continue where the open record ended (bytes given up, a new connection on the same ports): it is gone
            release(it->second.cost + it->first.capacity() + 64);
            assemblies_.erase(it);
            it = assemblies_.end();
            n.flags |= RpcNote::kDropped;
        }
        if (it == assemblies_.end()) {   // the first fragment of a record
            if (last) {
                n.flags |= RpcNote::kCompletes;
                n.fragments = 1;
            } else {
                n.flags |= RpcNote::kFragment;
                if (assemblies_.size() >= kMaxAssemblies) {   // forget an arbitrary open record: its last fragment will not be assembled
                    release(assemblies_.begin()->second.cost + assemblies_.begin()->first.capacity() + 64);
                    assemblies_.erase(assemblies_.begin());
                    lost = true;
                }
                const size_t kept = std::min(body.size(), kMaxKeptBytes);
                const size_t cost = kept + stream.capacity() + sizeof(Assembly) + 64;
                if (reserve(cost)) {
                    Assembly a;
                    a.bytes.assign(body.data(), kept);
                    a.total = static_cast<uint32_t>(body.size());
                    a.fragments = 1;
                    a.nextSeq = endSeq;
                    a.packets.push_back(packet);
                    a.cost = kept + sizeof(Assembly) + 64;
                    assemblies_.emplace(stream, std::move(a));
                }
            }
        } else {   // a later fragment
            Assembly &a = it->second;
            n.flags |= RpcNote::kFragment | RpcNote::kContinuation;
            if (a.fragments >= kMaxFragments || static_cast<size_t>(a.total) + body.size() > kMaxRecordBytes) {
                release(a.cost + it->first.capacity() + 64);
                assemblies_.erase(it);
                n.flags |= RpcNote::kDropped;
                lost = true;
            } else {
                const size_t room = a.bytes.size() < kMaxKeptBytes ? kMaxKeptBytes - a.bytes.size() : 0;
                const size_t kept = std::min(body.size(), room);
                if (kept && !reserve(kept)) {
                    release(a.cost + it->first.capacity() + 64);
                    assemblies_.erase(it);
                    n.flags |= RpcNote::kDropped;
                } else {
                    a.cost += kept;
                    a.lastStart = a.total;
                    a.bytes.append(body.data(), kept);
                    a.total += static_cast<uint32_t>(body.size());
                    ++a.fragments;
                    a.nextSeq = endSeq;
                    a.packets.push_back(packet);
                    if (last) {
                        RpcRecord r;
                        r.bytes = std::move(a.bytes);
                        r.total = a.total;
                        r.lastStart = a.lastStart;
                        r.fragments = a.fragments;
                        r.packets = std::move(a.packets);
                        release(a.cost + it->first.capacity() + 64);
                        assemblies_.erase(it);
                        const size_t cost = sizeof(RpcRecord) + r.bytes.capacity() + r.packets.size() * sizeof(uint32_t) + 64;
                        n.flags |= RpcNote::kCompletes;
                        n.fragments = r.fragments;
                        if (reserve(cost)) {
                            n.record = static_cast<uint32_t>(records_.size());
                            records_.push_back(std::move(r));
                        } else {
                            n.fragments = 0;   // the record could not be kept: no message to decode
                        }
                    }
                }
            }
        }
    }
    if (!reserve(noteCost(n))) return nullptr;
    return &notes_.emplace(key, std::move(n)).first->second;
}

const RpcNote *RpcTable::observeMessage(const std::string &conversation, bool fromLow, uint32_t packet, int64_t seq, const RpcMessage &msg, size_t maxMemory, bool &lost) {
    const auto nit = notes_.find(NoteKey{packet, seq < 0 ? UINT32_MAX : static_cast<uint32_t>(seq)});
    if (nit == notes_.end()) return nullptr;
    RpcNote &n = nit->second;
    if (n.flags & (RpcNote::kMatched | RpcNote::kRetransmission)) return &n;   // asked before
    if (n.prog || n.vers || n.proc) return &n;
    if (!(n.flags & RpcNote::kCompletes)) return &n;

    const auto release = [&](size_t bytes) { memory_ -= std::min(memory_, bytes); };
    const std::string ckey = conversation + '\x01' + std::to_string(msg.xid);
    const auto copyCall = [&](const Call &c) {
        n.prog = c.prog; n.vers = c.vers; n.proc = c.proc;
        n.mapProg = c.mapProg; n.mapVers = c.mapVers; n.mapProt = c.mapProt;
        n.netid = c.netid;
        if (c.wrapped) n.flags |= RpcNote::kWrapped;
    };

    auto it = calls_.find(ckey);
    if (msg.call) {
        if (it != calls_.end() && it->second.fromLow == fromLow && it->second.prog == msg.prog && it->second.vers == msg.vers && it->second.proc == msg.proc) {
            n.flags |= RpcNote::kMatched | RpcNote::kRetransmission;
            n.callPacket = it->second.packet;
            copyCall(it->second);
            return &n;
        }
        if (it != calls_.end()) {   // another call that reuses the xid: it replaces the old one
            release(callCost(it->first, it->second));
            calls_.erase(it);
        }
        while (calls_.size() >= kMaxCalls && !callOrder_.empty()) {   // the oldest call: its reply will show without it
            const auto old = calls_.find(callOrder_.front().first);
            if (old != calls_.end() && old->second.order == callOrder_.front().second) {
                release(callCost(old->first, old->second));
                calls_.erase(old);
                lost = true;
            }
            callOrder_.pop_front();
        }
        Call c;
        c.packet = packet; c.prog = msg.prog; c.vers = msg.vers; c.proc = msg.proc; c.fromLow = fromLow;
        c.mapProg = msg.mapProg; c.mapVers = msg.mapVers; c.mapProt = msg.mapProt; c.netid = msg.netid; c.wrapped = msg.wrapped;
        c.order = ++callCounter_;
        c.note = NoteKey{packet, seq < 0 ? UINT32_MAX : static_cast<uint32_t>(seq)};
        const size_t cost = callCost(ckey, c);
        n.prog = msg.prog; n.vers = msg.vers; n.proc = msg.proc;
        n.mapProg = msg.mapProg; n.mapVers = msg.mapVers; n.mapProt = msg.mapProt; n.netid = msg.netid;
        if (msg.wrapped) n.flags |= RpcNote::kWrapped;
        if (memory_ + cost > maxMemory) { lost = true; return &n; }
        memory_ += cost;
        callOrder_.emplace_back(ckey, c.order);
        calls_.emplace(ckey, std::move(c));
        return &n;
    }
    if (it != calls_.end() && it->second.fromLow != fromLow) {
        Call &c = it->second;
        n.flags |= RpcNote::kMatched;
        n.callPacket = c.packet;
        copyCall(c);
        if (c.replies++ > 0) n.flags |= RpcNote::kDuplicateReply;
        else if (const auto cn = notes_.find(c.note); cn != notes_.end()) cn->second.replyPacket = packet;
    }
    return &n;
}

void RpcTable::learnPorts(uint32_t packet, const std::string &serverIp, const std::vector<RpcMapping> &mappings, size_t maxMemory, bool &lost) {
    const auto reserve = [&](size_t bytes) {
        if (memory_ + bytes > maxMemory) { lost = true; return false; }
        memory_ += bytes;
        return true;
    };
    for (const RpcMapping &m: mappings) {
        if (m.prog == 0 || m.port == 0 || m.port > 65535 || (m.prot != 6 && m.prot != 17)) continue;
        std::vector<std::string> hosts;
        if (!serverIp.empty()) hosts.push_back(serverIp);
        if (!m.host.empty() && m.host != "0.0.0.0" && m.host != "::" && m.host != serverIp) hosts.push_back(m.host);
        for (const std::string &host: hosts) {
            const std::string pkey = portKey(host, static_cast<uint16_t>(m.port), m.prot == 17);
            auto pit = ports_.find(pkey);
            if (pit == ports_.end()) {
                if (ports_.size() >= kMaxPorts) { lost = true; continue; }
                if (!reserve(pkey.capacity() + sizeof(std::vector<RpcMappedProgram>) + 64)) continue;
                pit = ports_.emplace(pkey, std::vector<RpcMappedProgram>{}).first;
            }
            auto &list = pit->second;
            RpcMappedProgram e{packet, m.prog, m.vers};
            if (!list.empty()) {
                RpcMappedProgram &back = list.back();
                if (back.prog == 0) continue;                                       // already ambiguous
                if (back.prog == m.prog) {
                    if (back.vers == m.vers || back.vers == 0) continue;            // the version is already known / already "several"
                    if (back.from == packet) { back.vers = 0; continue; }           // one answer lists several versions of the program
                    e.vers = 0;                                                     // another version behind a known port
                } else {
                    if (back.from == packet) { back.prog = 0; back.vers = 0; continue; }   // one answer lists several programs behind the port
                    e.prog = 0;                                                     // another program behind a known port: ambiguous from here on
                    e.vers = 0;
                }
            }
            if (reserve(sizeof(RpcMappedProgram) + 32)) list.push_back(e);
        }
    }
}

} // namespace dissect
