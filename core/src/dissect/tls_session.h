#pragma once

// TLS connections as the load pass sees them. For every TLS connection (identified by its endpoints) this records what a
// later decryption step needs and cannot get from the single packet it is asked about:
//
//   - the client random and the server random of the handshake (the client random is the key into tls::KeyStore),
//   - the negotiated version (TLS 1.3 comes from the supported_versions extension of the ServerHello) and cipher suite,
//   - per direction, the index of every TLS record: the first message of a direction starts at record 0 and the
//     index grows by one per record. TLS record sequence numbers follow from it without replaying the capture: a
//     record's sequence number is its index minus the index of the first record under its keys (for TLS 1.2 the
//     record after the ChangeCipherSpec of that direction, see TlsDirection::changeCipherSpecs).
//
// Records are counted per TCP *message* as the stream reassembly cuts it out of the byte stream (see tcp_streams.h):
// the load pass registers each message once (SessionTables::addTlsMessage), keyed by the number of the packet that
// completed it and the relative sequence number of its first byte. Replay of one packet looks the message up with
// exactly that key (SessionTables::findTlsMessage), so a packet's details never depend on state outside the tables.
//
// Limits: a missing segment (capture loss) makes the indices of that direction unreliable from there on, which is
// flagged in TlsDirection::gap. Connections that reuse the same four endpoints in one capture are told apart by a SYN
// (SessionTables::markTlsRestart), by a hello with another random, or by a restarted sequence space. Session data beyond
// the table's memory budget is dropped and reported through the "tls" entry of SessionTables::stateLostTables().

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "tls_summary.h"

namespace dissect {
    using TlsRandom = std::array<uint8_t, 32>;           // ClientHello.random / ServerHello.random
    constexpr uint32_t kTlsNoRecord = 0xFFFFFFFFu;

    enum class TlsRole { Unknown, Client, Server };

    /// One direction of a TLS connection. `directions[0]` is the traffic sent by the endpoint that sorts first
    /// ("address/port" text order), `directions[1]` the other; TlsSession::roleOf() translates to client / server.
    struct TlsDirection {
        static constexpr size_t kMaxChangeCipherSpecs = 8;

        uint32_t records = 0;                     // records seen so far = the index the next record gets
        bool gap = false;                         // a TCP message is missing in this direction: later indices may be off
        uint32_t helloRecord = kTlsNoRecord;      // index of the record that carried this direction's hello message
        std::vector<uint32_t> changeCipherSpecs;  // indices of the ChangeCipherSpec records (the first kMaxChangeCipherSpecs)
        bool haveNext = false;                    // bookkeeping for gap / duplicate detection:
        uint32_t nextSeq = 0;                     //   relative sequence number where the next message must start
    };

    struct TlsSession {
        bool hasClientRandom = false, hasServerRandom = false;
        TlsRandom clientRandom{}, serverRandom{};
        uint16_t version = 0;                     // negotiated: 0x0303 = TLS 1.2, 0x0304 = TLS 1.3 (0 = no ServerHello seen)
        uint16_t cipherSuite = 0;                 // ServerHello's choice (0 = none seen)
        bool helloRetryRequest = false;           // the server answered with a HelloRetryRequest first (TLS 1.3)
        int8_t clientDirection = -1;              // index into `directions` of the client's traffic (-1 = not known)
        bool earlyData = false;                   // the ClientHello offered early data (TLS 1.3 0-RTT)
        TlsInner inner = TlsInner::Unknown;       // what the decrypted application data is dissected as (decided on the first data)
        std::string alpn;                         // the protocol the server selected: ServerHello (TLS 1.2) or EncryptedExtensions (TLS 1.3)
        TlsDirection directions[2];

        TlsRole roleOf(unsigned direction) const {
            if (clientDirection < 0 || direction > 1) return TlsRole::Unknown;
            return direction == static_cast<unsigned>(clientDirection) ? TlsRole::Client : TlsRole::Server;
        }
        const TlsDirection *client() const { return clientDirection < 0 ? nullptr : &directions[clientDirection]; }
        const TlsDirection *server() const { return clientDirection < 0 ? nullptr : &directions[1 - clientDirection]; }
    };

    /// Where one registered TCP message sits: its session, direction and the records it holds
    /// (indices firstRecord .. firstRecord + records - 1 of that direction).
    struct TlsMessageRef {
        uint32_t session = 0;                     // index for SessionTables::tlsSession()
        uint8_t direction = 0;                    // index into TlsSession::directions
        uint32_t firstRecord = 0;
        uint32_t records = 0;
        uint32_t firstOutcome = kTlsNoRecord;     // index of the first of `records` decryption outcomes (tls_decrypt.h), if any
    };

    /// Where SessionTables::addTlsMessage put one message (filled for the decryption step that follows it).
    struct TlsAddResult {
        bool registered = false;                  // false: a repeat of a message seen before, frozen tables or no room
        uint32_t session = 0;
        uint8_t direction = 0;
        uint32_t firstRecord = 0;
        bool gapBefore = false;                   // data of this direction is missing right before this message
    };

    /// What the TLS dissector found in one TCP message (input of SessionTables::addTlsMessage).
    struct TlsMessageFacts {
        uint32_t packet = 0;                      // number of the packet that completed the message
        uint32_t startSeq = 0;                    // relative sequence number of its first byte
        uint32_t length = 0;                      // message length in bytes
        uint32_t records = 0;                     // TLS records in it
        std::vector<uint32_t> changeCipherSpecs;  // record positions inside the message (0-based) of ChangeCipherSpec records
        bool clientHello = false, serverHello = false;
        uint32_t helloRecord = 0;                 // position of the record holding the hello inside the message
        TlsRandom random{};                       // the hello's random
        uint16_t version = 0;                     // ServerHello: negotiated version
        uint16_t cipherSuite = 0;                 // ServerHello: chosen suite
        bool helloRetryRequest = false;           // ServerHello that is a HelloRetryRequest
        bool earlyData = false;                   // ClientHello with the early_data extension
        std::string alpn;                         // ServerHello: the selected application protocol (TLS 1.2)
    };

    /// The sessions and the message index. Memory is accounted by the owner (SessionTables).
    class TlsSessionTable {
    public:
        /// Registers one message. Returns false if the memory budget `maxMemory` did not allow storing everything (the
        /// per-direction counters still advance when only the message reference did not fit). A message that was
        /// registered before (same packet and start) is ignored.
        bool add(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort,
                 const TlsMessageFacts &facts, size_t maxMemory, TlsAddResult *result = nullptr) {
            if (result) *result = TlsAddResult{};
            unsigned direction = 0;
            const std::string key = connectionKey(srcIp, srcPort, dstIp, dstPort, direction);
            const uint64_t messageKey = (static_cast<uint64_t>(facts.packet) << 32) | facts.startSeq;
            if (messages_.count(messageKey)) return true;

            uint32_t id = 0;
            bool create = true;
            const bool restart = takeRestart(key, direction, facts.startSeq);   // the first message after a SYN of these endpoints
            const auto latest = latest_.find(key);
            if (latest != latest_.end()) {
                id = latest->second.id;
                const TlsSession &s = sessions_[id];
                create = restart || (facts.clientHello && s.hasClientRandom && s.clientRandom != facts.random) ||
                         (facts.serverHello && !facts.helloRetryRequest && s.hasServerRandom && s.serverRandom != facts.random);
            }
            if (create) {
                const size_t cost = sizeof(TlsSession) + key.size() + 64;
                if (memory_ + cost > maxMemory) return false;
                id = static_cast<uint32_t>(sessions_.size());
                sessions_.emplace_back();
                latest_[key].id = id;
                ++latest_[key].count;
                memory_ += cost;
            }

            TlsSession &s = sessions_[id];
            TlsDirection &d = s.directions[direction];
            bool gapBefore = false;
            if (d.haveNext) {
                const int32_t ahead = static_cast<int32_t>(facts.startSeq - d.nextSeq);
                if (ahead < 0) return true;           // bytes of this message were registered already
                if (ahead > 0) d.gap = gapBefore = true;   // a message in between never completed
            }
            const uint32_t first = d.records;
            d.records += facts.records;
            d.haveNext = true;
            d.nextSeq = facts.startSeq + facts.length;
            for (uint32_t at: facts.changeCipherSpecs) {
                if (d.changeCipherSpecs.size() >= TlsDirection::kMaxChangeCipherSpecs) break;
                d.changeCipherSpecs.push_back(first + at);
                memory_ += sizeof(uint32_t);
            }
            if (facts.clientHello) {
                if (!s.hasClientRandom) { s.clientRandom = facts.random; s.hasClientRandom = true; }
                if (facts.earlyData) s.earlyData = true;
                s.clientDirection = static_cast<int8_t>(direction);
                if (d.helloRecord == kTlsNoRecord) d.helloRecord = first + facts.helloRecord;
            } else if (facts.serverHello) {
                if (s.clientDirection < 0) s.clientDirection = static_cast<int8_t>(1 - direction);
                if (facts.helloRetryRequest) {
                    s.helloRetryRequest = true;
                } else if (!s.hasServerRandom) {
                    s.serverRandom = facts.random;
                    s.hasServerRandom = true;
                }
                s.version = facts.version;
                s.cipherSuite = facts.cipherSuite;
                if (!facts.alpn.empty()) s.alpn = facts.alpn.substr(0, 32);
                // the ServerHello proper (not the HelloRetryRequest before it) is where the handshake keys start
                if (d.helloRecord == kTlsNoRecord || !facts.helloRetryRequest) d.helloRecord = first + facts.helloRecord;
            }

            constexpr size_t kMessageCost = sizeof(uint64_t) + sizeof(TlsMessageRef) + 48;   // map node overhead
            if (memory_ + kMessageCost > maxMemory) return false;
            messages_[messageKey] = TlsMessageRef{id, static_cast<uint8_t>(direction), first, facts.records, kTlsNoRecord};
            memory_ += kMessageCost;
            if (result) *result = TlsAddResult{true, id, static_cast<uint8_t>(direction), first, gapBefore};
            return true;
        }

        /// Remembers where the decryption outcomes of a registered message start (see tls_decrypt.h).
        void setFirstOutcome(uint32_t packet, uint32_t startSeq, uint32_t first) {
            const auto it = messages_.find((static_cast<uint64_t>(packet) << 32) | startSeq);
            if (it != messages_.end()) it->second.firstOutcome = first;
        }

        const TlsMessageRef *findMessage(uint32_t packet, uint32_t startSeq) const {
            const auto it = messages_.find((static_cast<uint64_t>(packet) << 32) | startSeq);
            return it == messages_.end() ? nullptr : &it->second;
        }

        const TlsSession *session(uint32_t id) const { return id < sessions_.size() ? &sessions_[id] : nullptr; }
        TlsSession *mutableSession(uint32_t id) { return id < sessions_.size() ? &sessions_[id] : nullptr; }

        /// The most recent session between these endpoints; `direction` receives the index of the traffic that goes
        /// from the first endpoint to the second.
        const TlsSession *find(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort,
                               unsigned *direction = nullptr) const {
            unsigned d = 0;
            const auto it = latest_.find(connectionKey(srcIp, srcPort, dstIp, dstPort, d));
            if (direction) *direction = d;
            if (it == latest_.end()) return nullptr;
            return &sessions_[it->second.id];
        }

        /// How many sessions used these endpoints.
        size_t sessionsBetween(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort) const {
            unsigned d = 0;
            const auto it = latest_.find(connectionKey(srcIp, srcPort, dstIp, dstPort, d));
            return it == latest_.end() ? 0 : it->second.count;
        }

        /// A SYN (without ACK) from src to dst was seen: if these endpoints already have a session, the first message
        /// the SYN's sender sends next, starting at `firstSeq` (the relative sequence number behind the SYN), belongs to
        /// a new connection. Endpoints without a session need no marker, so flows of other protocols cost nothing.
        /// Returns false if the budget `maxMemory` did not allow storing the marker.
        bool markRestart(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort, uint32_t firstSeq,
                         size_t maxMemory) {
            unsigned d = 0;
            const std::string key = connectionKey(srcIp, srcPort, dstIp, dstPort, d);
            if (latest_.find(key) == latest_.end()) return true;
            const auto it = restart_.find(key);
            if (it != restart_.end()) { it->second = {firstSeq, d}; return true; }
            const size_t cost = key.size() + 64;
            if (memory_ + cost > maxMemory) return false;
            restart_.emplace(key, Restart{firstSeq, d});
            memory_ += cost;
            return true;
        }

        /// True if a message of this direction that starts at `startSeq` continues the stream of the latest session and
        /// that direction has changed its keys (a ChangeCipherSpec went by), so a "handshake" record in it is encrypted
        /// data. A restarted sequence space or a SYN means a new connection, whose hello is plain.
        bool continuesEncrypted(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort,
                                uint32_t startSeq) const {
            unsigned d = 0;
            const std::string key = connectionKey(srcIp, srcPort, dstIp, dstPort, d);
            const auto it = latest_.find(key);
            if (it == latest_.end() || restartPending(key, d, startSeq)) return false;
            const TlsDirection &dir = sessions_[it->second.id].directions[d];
            if (dir.changeCipherSpecs.empty()) return false;
            return !dir.haveNext || static_cast<int32_t>(startSeq - dir.nextSeq) >= 0;
        }

        size_t sessionCount() const { return sessions_.size(); }
        size_t messageCount() const { return messages_.size(); }
        size_t memory() const { return memory_; }

        void clear() {
            sessions_.clear();
            latest_.clear();
            restart_.clear();
            messages_.clear();
            memory_ = 0;
        }

    private:
        struct Restart { uint32_t firstSeq = 0; unsigned direction = 0; };

        // A marker applies to the first message of the SYN sender's direction, and only if that message starts right
        // behind the SYN: a retransmitted SYN captured later (the stream is further along) is not a new connection.
        bool restartPending(const std::string &key, unsigned direction, uint32_t startSeq) const {
            const auto it = restart_.find(key);
            return it != restart_.end() && it->second.direction == direction && it->second.firstSeq == startSeq;
        }

        // Like restartPending, and consumes the marker once a message of the SYN sender's direction has passed.
        bool takeRestart(const std::string &key, unsigned direction, uint32_t startSeq) {
            const auto it = restart_.find(key);
            if (it == restart_.end() || it->second.direction != direction) return false;
            const bool applies = it->second.firstSeq == startSeq;
            restart_.erase(it);
            memory_ -= std::min(memory_, key.size() + 64);
            return applies;
        }

        // Both endpoints in a fixed order, so both directions of a connection share one key; `direction` is 0 when
        // the source is the endpoint that sorts first.
        static std::string connectionKey(const std::string &srcIp, uint16_t srcPort, const std::string &dstIp, uint16_t dstPort,
                                         unsigned &direction) {
            const std::string a = srcIp + "/" + std::to_string(srcPort), b = dstIp + "/" + std::to_string(dstPort);
            direction = a <= b ? 0 : 1;
            return direction == 0 ? a + "|" + b : b + "|" + a;
        }

        std::vector<TlsSession> sessions_;
        struct Newest { uint32_t id = 0; uint32_t count = 0; };    // newest session and how many used the endpoints
        std::unordered_map<std::string, Newest> latest_;            // connection key -> its sessions
        std::unordered_map<std::string, Restart> restart_;          // endpoints with a session that saw a new SYN
        std::unordered_map<uint64_t, TlsMessageRef> messages_;      // (packet, start sequence) -> where it sits
        size_t memory_ = 0;
    };
} // namespace dissect
