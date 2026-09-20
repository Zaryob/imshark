#include "dcerpc_session.h"

#include <algorithm>
#include <cstdio>
#include <cstring>

namespace dissect {

namespace {

uint16_t le16(const uint8_t *p) { return static_cast<uint16_t>(p[0] | (p[1] << 8)); }
uint16_t be16(const uint8_t *p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
uint32_t le32(const uint8_t *p) { return static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) | (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24); }
uint32_t be32(const uint8_t *p) { return (static_cast<uint32_t>(p[0]) << 24) | (static_cast<uint32_t>(p[1]) << 16) | (static_cast<uint32_t>(p[2]) << 8) | p[3]; }

// bounds-checked reader of the NDR stub; alignment is relative to the start of the stub data
struct Ndr {
    const uint8_t *p;
    size_t size;
    bool little;
    size_t pos = 0;
    bool ok = true;

    size_t left() const { return pos <= size ? size - pos : 0; }
    void align4() { pos = (pos + 3) & ~static_cast<size_t>(3); if (pos > size) ok = false; }
    uint32_t u32() {
        if (!ok || left() < 4) { ok = false; return 0; }
        const uint32_t v = little ? le32(p + pos) : be32(p + pos);
        pos += 4;
        return v;
    }
    const uint8_t *bytes(size_t n) {
        if (!ok || left() < n) { ok = false; return nullptr; }
        const uint8_t *r = p + pos;
        pos += n;
        return r;
    }
};

std::string ipText(const uint8_t *b) {
    char buf[20];
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", b[0], b[1], b[2], b[3]);
    return buf;
}

// tower_t of a non-null referent: conformance (max_count), tower_length, the octets, padding to 4
bool readTower(Ndr &r, std::vector<DceTower> &towers) {
    r.align4();
    const uint32_t maxCount = r.u32(), length = r.u32();
    if (!r.ok || length != maxCount || length > r.left()) { r.ok = false; return false; }
    const uint8_t *octets = r.bytes(length);
    r.align4();
    DceTower t;
    if (!octets || !parseEpmTower(octets, length, t)) return false;   // an unreadable tower: skip it, the layout is intact
    towers.push_back(std::move(t));
    return true;
}

std::string endpointKey(const std::string &ip, uint16_t port, bool udp) { return ip + ":" + std::to_string(port) + (udp ? "/udp" : "/tcp"); }

} // namespace

std::string dceFormatUuid(const uint8_t *b, bool littleEndian) {
    char buf[48];
    uint32_t d1;
    uint16_t d2, d3;
    if (littleEndian) {
        d1 = le32(b);
        d2 = le16(b + 4);
        d3 = le16(b + 6);
    } else {
        d1 = be32(b);
        d2 = be16(b + 4);
        d3 = be16(b + 6);
    }
    std::snprintf(buf, sizeof buf, "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x", d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]);
    return buf;
}

bool parseEpmTower(const uint8_t *data, size_t size, DceTower &out) {
    if (!data || size < 2) return false;
    const unsigned floors = le16(data);
    if (floors == 0 || floors > 16) return false;
    size_t pos = 2;
    for (unsigned i = 0; i < floors; ++i) {
        if (size - pos < 2) return false;
        const size_t lhsLen = le16(data + pos);
        pos += 2;
        if (size - pos < lhsLen || lhsLen == 0) return false;
        const uint8_t *lhs = data + pos;
        pos += lhsLen;
        if (size - pos < 2) return false;
        const size_t rhsLen = le16(data + pos);
        pos += 2;
        if (size - pos < rhsLen) return false;
        const uint8_t *rhs = data + pos;
        pos += rhsLen;
        const uint8_t id = lhs[0];
        if (i == 0) {   // the interface floor: 0x0D, UUID, major version; minor version on the right
            if (id != 0x0D || lhsLen != 19 || rhsLen < 2) return false;
            out.uuid = dceFormatUuid(lhs + 1, true);
            out.version = static_cast<uint32_t>(le16(lhs + 17)) | (static_cast<uint32_t>(le16(rhs)) << 16);
        } else if (i == 1) {
            continue;   // the transfer syntax
        } else if (id == 0x0B || id == 0x0A) {
            continue;   // the RPC protocol floor (connection-oriented / datagram) and its minor version
        } else if (id == 0x07 && rhsLen == 2) {
            out.port = be16(rhs);
            out.protocol = "ncacn_ip_tcp";
        } else if (id == 0x08 && rhsLen == 2) {
            out.port = be16(rhs);
            out.udp = true;
            out.protocol = "ncadg_ip_udp";
        } else if (id == 0x09 && rhsLen == 4) {
            out.host = ipText(rhs);
        } else if (id == 0x1F && rhsLen == 2) {
            out.port = be16(rhs);
            out.protocol = "ncacn_http";
        } else if (id == 0x0F || id == 0x10 || (id == 0x11 && out.protocol.empty())) {   // a pipe tower ends with the NetBIOS host floor: the pipe stays
            size_t n = 0;
            while (n < rhsLen && rhs[n] != 0 && n < 128) ++n;
            out.address.assign(reinterpret_cast<const char *>(rhs), n);
            out.protocol = id == 0x0F ? "ncacn_np" : id == 0x10 ? "ncalrpc" : "ncacn_nb_nb";
        }
    }
    return !out.uuid.empty();
}

bool parseEpmAnswer(uint16_t opnum, bool little, const uint8_t *data, size_t size, std::vector<DceTower> &towers) {
    if (!data || (opnum != 2 && opnum != 3)) return false;
    Ndr r{data, size, little};
    r.bytes(20);                                   // entry_handle: attributes + UUID
    r.u32();                                       // num_towers / num_ents
    const uint32_t maxCount = r.u32(), offset = r.u32(), actual = r.u32();
    if (!r.ok || offset != 0 || actual > maxCount || actual > r.left() / 4 || actual > 4096) return false;
    std::vector<uint32_t> referents;
    for (uint32_t i = 0; i < actual && r.ok; ++i) {
        if (opnum == 3) {   // twr_p_t towers[]: one pointer per element
            referents.push_back(r.u32());
        } else {            // ept_entry_t: object UUID, tower pointer, annotation (a varying string: offset, length, bytes)
            r.bytes(16);
            referents.push_back(r.u32());
            const uint32_t aOffset = r.u32(), aLength = r.u32();
            if (!r.ok || aOffset > 64 || aLength > 64 || aLength > r.left()) return false;
            r.bytes(aLength);
            r.align4();
        }
    }
    for (uint32_t i = 0; i < referents.size() && r.ok; ++i) {
        if (referents[i] == 0) continue;
        if (towers.size() >= DceRpcTable::kMaxTowers) { break; }
        readTower(r, towers);
    }
    return r.ok;
}

void DceRpcTable::clear() {
    streams_.clear();
    calls_.clear();
    assemblies_.clear();
    notes_.clear();
    messages_.clear();
    endpoints_.clear();
    memory_ = 0;
}

const DceNote *DceRpcTable::note(uint32_t packet, int64_t seq, uint8_t index) const {
    const auto it = notes_.find(NoteKey{packet, static_cast<uint32_t>(seq), index});
    return it == notes_.end() ? nullptr : &it->second;
}

const DceContext *DceRpcTable::context(const std::string &stream, uint16_t id) const {
    const auto s = streams_.find(stream);
    if (s == streams_.end()) return nullptr;
    const auto c = s->second.contexts.find(id);
    return c == s->second.contexts.end() ? nullptr : &c->second;
}

const DceMappedEndpoint *DceRpcTable::endpoint(const std::string &ip, uint16_t port, bool udp, uint32_t packet) const {
    if (endpoints_.empty()) return nullptr;
    const auto it = endpoints_.find(endpointKey(ip, port, udp));
    if (it == endpoints_.end()) return nullptr;
    for (auto e = it->second.rbegin(); e != it->second.rend(); ++e) if (e->from <= packet) return &*e;
    return nullptr;
}

void DceRpcTable::dropAssembly(std::unordered_map<std::string, Assembly>::iterator it) {
    memory_ -= std::min(memory_, it->second.cost + it->first.capacity() + 64);
    assemblies_.erase(it);
}

const DceNote *DceRpcTable::observe(const std::string &stream, uint32_t packet, int64_t seq, uint8_t index, const DcePdu &pdu, std::string_view stub,
                                    const std::string &serverIp, const std::string &fallbackInterface, size_t maxMemory, bool &lost) {
    const NoteKey key{packet, static_cast<uint32_t>(seq), index};
    if (const auto existing = notes_.find(key); existing != notes_.end()) return &existing->second;

    const auto reserve = [&](size_t bytes) {
        if (memory_ + bytes > maxMemory) { lost = true; return false; }
        memory_ += bytes;
        return true;
    };
    const auto release = [&](size_t bytes) { memory_ -= std::min(memory_, bytes); };
    const auto contextCost = [](const DceContext &c) { return sizeof(DceContext) + 64 + c.uuid.capacity(); };

    DceNote n;
    n.type = pdu.type;
    const bool isRequest = pdu.type == kDceRequest;
    const bool isAnswer = pdu.type == kDceResponse || pdu.type == kDceFault;
    const std::string callKey = stream + '\x01' + std::to_string(pdu.callId);

    // ---- presentation contexts ----------------------------------------------------------------------------------------
    if ((pdu.type == kDceBind || pdu.type == kDceAlterContext) && !pdu.contexts.empty()) {
        auto sit = streams_.find(stream);
        if (sit == streams_.end() && reserve(stream.capacity() + sizeof(Stream) + 64)) sit = streams_.emplace(stream, Stream{}).first;
        if (sit != streams_.end()) {
            Stream &s = sit->second;
            if (const auto old = s.proposed.find(pdu.callId); old != s.proposed.end()) {
                for (const auto &c: old->second) release(contextCost(c));
                s.proposed.erase(old);
            }
            if (s.proposed.size() >= kMaxProposalsPerStream) {   // the oldest unanswered Bind will not be matched any more
                for (const auto &c: s.proposed.begin()->second) release(contextCost(c));
                s.proposed.erase(s.proposed.begin());
                lost = true;
            }
            size_t cost = 0;
            for (const auto &c: pdu.contexts) cost += contextCost(c);
            if (reserve(cost)) s.proposed.emplace(pdu.callId, pdu.contexts);
        }
    } else if (pdu.type == kDceBindAck || pdu.type == kDceAlterContextResp) {
        const auto sit = streams_.find(stream);
        if (sit != streams_.end()) {
            Stream &s = sit->second;
            if (const auto prop = s.proposed.find(pdu.callId); prop != s.proposed.end()) {
                for (size_t i = 0; i < prop->second.size() && i < pdu.results.size(); ++i) {
                    if (pdu.results[i] != 0) continue;
                    const DceContext &c = prop->second[i];
                    if (const auto old = s.contexts.find(c.id); old != s.contexts.end()) { release(contextCost(old->second)); s.contexts.erase(old); }
                    if (reserve(contextCost(c))) s.contexts.emplace(c.id, c);
                }
                for (const auto &c: prop->second) release(contextCost(c));
                s.proposed.erase(prop);
            }
        }
    }

    // ---- interface, call ----------------------------------------------------------------------------------------------
    if (pdu.type == kDceRequest || isAnswer) {
        n.opnum = pdu.opnum;
        if (pdu.connectionless) {
            n.iface = pdu.interfaceUuid;
            n.ifVersion = pdu.interfaceVersion;
        } else if (const DceContext *c = context(stream, pdu.contextId)) {
            n.iface = c->uuid;
            n.ifVersion = c->version;
        } else {
            n.flags |= DceNote::kUnknownContext;
        }
        const auto cit = calls_.find(callKey);
        if (isAnswer && cit != calls_.end()) {
            n.flags |= DceNote::kMatched;
            n.requestPacket = cit->second.packet;
            if (!pdu.connectionless) n.opnum = cit->second.opnum;
            if (n.iface.empty()) { n.iface = cit->second.iface; n.ifVersion = cit->second.version; n.flags &= static_cast<uint16_t>(~DceNote::kUnknownContext); }
        }
        if (n.iface.empty() && !fallbackInterface.empty()) { n.iface = fallbackInterface; n.flags |= DceNote::kAssumed; }
        if (isRequest) {
            Call c{pdu.opnum, n.iface, n.ifVersion, packet};
            const size_t cost = sizeof(Call) + callKey.capacity() + c.iface.capacity() + 64;
            if (cit != calls_.end()) {
                release(sizeof(Call) + cit->first.capacity() + cit->second.iface.capacity() + 64);
                calls_.erase(cit);
            } else if (calls_.size() >= kMaxCalls) {   // forget an arbitrary old call: its response will show without the opnum
                const auto victim = calls_.begin();
                release(sizeof(Call) + victim->first.capacity() + victim->second.iface.capacity() + 64);
                calls_.erase(victim);
                lost = true;
            }
            if (reserve(cost)) calls_.emplace(callKey, std::move(c));
        }
    }

    // ---- fragments ------------------------------------------------------------------------------------------------------
    if (isRequest || isAnswer) {
        const bool multi = !(pdu.first && pdu.last);
        if (multi) n.flags |= DceNote::kFragment;
        const bool wantEpm = isAnswer && pdu.type == kDceResponse && n.iface == kDceEpmUuid && !pdu.encrypted && (n.opnum == 2 || n.opnum == 3) && (pdu.connectionless || (n.flags & DceNote::kMatched));
        const std::string akey = callKey + (isRequest ? 'Q' : 'R');
        bool complete = false;
        std::string whole;
        size_t totalBytes = stub.size();
        std::vector<uint32_t> packets{packet};
        std::vector<NoteKey> earlier;
        if (!multi) {
            complete = true;
        } else {
            auto ait = assemblies_.find(akey);
            if (ait != assemblies_.end() && pdu.first && !pdu.connectionless) { dropAssembly(ait); ait = assemblies_.end(); }   // the call id starts over
            if (ait == assemblies_.end()) {
                if (!pdu.connectionless && !pdu.first) {
                    n.flags |= DceNote::kMissingStart;
                } else {
                    if (assemblies_.size() >= kMaxAssemblies) { dropAssembly(assemblies_.begin()); lost = true; }
                    Assembly a;
                    a.keepBytes = wantEpm;
                    a.little = pdu.little;
                    a.cost = sizeof(Assembly);
                    if (reserve(a.cost + akey.capacity() + 64)) ait = assemblies_.emplace(akey, std::move(a)).first;
                }
            }
            if (ait != assemblies_.end()) {
                Assembly &a = ait->second;
                const uint32_t number = pdu.connectionless ? pdu.fragment : a.next;
                if (a.parts.count(number)) {
                    n.flags |= DceNote::kDuplicate;
                } else {
                    Part part;
                    part.size = static_cast<uint32_t>(stub.size());
                    part.packet = packet;
                    if (a.keepBytes) part.bytes.assign(stub.data(), stub.size());
                    const size_t cost = sizeof(Part) + 64 + part.bytes.capacity() + sizeof(NoteKey);
                    if (a.bytes + stub.size() > kMaxMessageBytes || a.parts.size() >= kMaxFragments || !reserve(cost)) {
                        lost = true;
                        dropAssembly(ait);
                        ait = assemblies_.end();
                        n.flags |= DceNote::kMissingStart;
                    } else {
                        a.cost += cost;
                        a.bytes += stub.size();
                        a.parts.emplace(number, std::move(part));
                        a.notes.push_back(key);
                        if (!pdu.connectionless) ++a.next;
                        if (pdu.last) a.lastFragment = number;
                        if (a.lastFragment >= 0 && a.parts.size() == static_cast<size_t>(a.lastFragment) + 1) {
                            complete = true;
                            totalBytes = a.bytes;
                            packets.clear();
                            for (const auto &[no, p]: a.parts) {
                                packets.push_back(p.packet);
                                if (a.keepBytes) whole += p.bytes;
                            }
                            earlier = a.notes;
                            earlier.pop_back();   // this PDU's own note
                            dropAssembly(ait);
                        }
                    }
                }
            }
        }
        if (complete) {
            for (const NoteKey &k: earlier) {
                if (const auto en = notes_.find(k); en != notes_.end()) { en->second.completedIn = packet; en->second.flags |= DceNote::kCompletedLater; }
            }
            std::vector<DceTower> towers;
            bool epm = false;
            if (wantEpm) {
                const std::string_view data = multi ? std::string_view(whole) : stub;
                epm = true;
                parseEpmAnswer(n.opnum, pdu.little, reinterpret_cast<const uint8_t *>(data.data()), data.size(), towers);
            }
            if (multi || !towers.empty()) {
                DceMessage m;
                m.bytes = static_cast<uint32_t>(std::min<size_t>(totalBytes, UINT32_MAX));
                m.fragments = static_cast<uint16_t>(std::min<size_t>(packets.size(), UINT16_MAX));
                m.packets = packets;
                m.epm = epm;
                m.towers = towers;
                size_t cost = sizeof(DceMessage) + packets.size() * sizeof(uint32_t) + 64;
                for (const auto &t: towers) cost += sizeof(DceTower) + t.uuid.capacity() + t.protocol.capacity() + t.host.capacity() + t.address.capacity();
                if (reserve(cost)) {
                    n.message = static_cast<uint32_t>(messages_.size());
                    n.flags |= DceNote::kCompletes;
                    messages_.push_back(std::move(m));
                }
            }
            // what the endpoint mapper told: the host asked (and the host in the tower, if it names another) now speaks DCE/RPC on that port
            for (const DceTower &t: towers) {
                if (t.port == 0 || (t.protocol != "ncacn_ip_tcp" && t.protocol != "ncadg_ip_udp")) continue;
                std::vector<std::string> hosts;
                if (!serverIp.empty()) hosts.push_back(serverIp);
                if (!t.host.empty() && t.host != "0.0.0.0" && t.host != serverIp) hosts.push_back(t.host);
                for (const std::string &host: hosts) {
                    const std::string ekey = endpointKey(host, t.port, t.udp);
                    auto eit = endpoints_.find(ekey);
                    if (eit == endpoints_.end()) {
                        if (!reserve(ekey.capacity() + sizeof(std::vector<DceMappedEndpoint>) + 64)) continue;
                        eit = endpoints_.emplace(ekey, std::vector<DceMappedEndpoint>{}).first;
                    }
                    auto &list = eit->second;
                    DceMappedEndpoint e{packet, t.uuid, t.version};
                    if (!list.empty()) {
                        DceMappedEndpoint &back = list.back();
                        if (back.uuid == t.uuid && back.version == t.version) continue;
                        if (back.uuid.empty()) continue;                                  // already ambiguous
                        if (back.from == packet) { back.uuid.clear(); back.version = 0; continue; }   // one answer lists several interfaces behind the port
                        e.uuid.clear();                                                   // another interface behind a known port: ambiguous from here on
                        e.version = 0;
                    }
                    if (reserve(sizeof(DceMappedEndpoint) + 32 + e.uuid.capacity())) list.push_back(std::move(e));
                }
            }
        }
    }

    if (!reserve(noteCost(n))) return nullptr;
    return &notes_.emplace(key, std::move(n)).first->second;
}

} // namespace dissect
