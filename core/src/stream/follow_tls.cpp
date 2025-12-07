// "Follow TLS stream": decrypts a reassembled TCP conversation record by record (see follow.h). This walks the whole stream
// once with a fresh tls::RecordDecryptor, so it does not depend on the per-record outcomes of the load pass; it uses the same
// rules (which records are protected, what a failure in the TLS 1.3 handshake epoch does to the sequence number).
#include "follow.h"

#include <algorithm>

#include <tls/record_decryptor.h>

namespace stream {
    namespace {
        constexpr uint8_t kChangeCipherSpec = 20, kApplicationData = 23;
        constexpr uint16_t kTls13 = 0x0304;

        uint16_t be16(const char *p) { return static_cast<uint16_t>((static_cast<uint8_t>(p[0]) << 8) | static_cast<uint8_t>(p[1])); }

        // the same plausibility test the TLS dissector applies to a record header
        bool plausible(const char *d) {
            const uint8_t type = static_cast<uint8_t>(d[0]);
            const size_t len = be16(d + 3);
            return type >= 20 && type <= 24 && static_cast<uint8_t>(d[1]) == 3 && static_cast<uint8_t>(d[2]) <= 4 && len > 0 && len <= 16384 + 2048;
        }

        struct Half {
            std::string buffer;          // bytes of a record that has not been completed yet
            bool changedKeys = false;    // TLS 1.2: a ChangeCipherSpec of this direction went by
            bool desync = false;         // data is missing before the next record, or the bytes are not TLS records
        };
    } // namespace

    TlsStreamSetup tlsStreamSetup(const dissect::SessionTables &sessions, const std::string &addressA, uint16_t portA, const std::string &addressB,
                                  uint16_t portB) {
        TlsStreamSetup setup;
        unsigned direction = 0;   // index of the traffic from A to B
        const dissect::TlsSession *s = sessions.findTlsSession(addressA, portA, addressB, portB, &direction);
        if (!s || !s->hasClientRandom || s->clientDirection < 0) return setup;
        setup.available = true;
        setup.version = s->version;
        setup.cipherSuite = s->cipherSuite;
        setup.clientRandom = s->clientRandom;
        setup.serverRandom = s->serverRandom;
        setup.aIsClient = s->roleOf(direction) == dissect::TlsRole::Client;
        tls::KeyEntry entry;
        setup.haveKeys = sessions.findTlsKeys(s->clientRandom, entry);
        if (setup.haveKeys) setup.keys = entry;
        return setup;
    }

    bool decryptTlsStream(const Stream &raw, const TlsStreamSetup &setup, Stream &out, TlsStreamResult &result) {
        result = TlsStreamResult();
        out = Stream();
        out.tcp = raw.tcp;
        out.addressA = raw.addressA;
        out.addressB = raw.addressB;
        out.portA = raw.portA;
        out.portB = raw.portB;
        out.packets = raw.packets;
        if (!raw.tcp) { result.note = "only TCP streams can carry TLS"; return false; }
        if (!setup.available) { result.note = "no TLS handshake (ClientHello) of this conversation was captured"; return false; }
        if (!setup.haveKeys) { result.note = "no key material for this connection (set the TLS key log file, or use a capture with secrets)"; return false; }
        if (setup.version == 0) { result.note = "the ServerHello was not captured: the cipher suite is unknown"; return false; }

        tls::RecordDecryptor dec(setup.version, setup.cipherSuite, setup.clientRandom, setup.serverRandom, &setup.keys);
        if (dec.availability() == tls::DecryptStatus::UnsupportedSuite) { result.note = "unsupported cipher suite or TLS version"; return false; }
        if (dec.availability() == tls::DecryptStatus::NoBackend) { result.note = "TLS decryption is not available in this build (no OpenSSL)"; return false; }

        const bool tls13 = setup.version == kTls13;
        Half half[2];   // 0: A to B, 1: B to A
        auto emit = [&](Direction dir, const std::vector<uint8_t> &plain, int packetNumber, uint64_t missingBefore) {
            (dir == Direction::AtoB ? out.bytesAtoB : out.bytesBtoA) += plain.size();
            out.missingBytes += missingBefore;
            if (!out.chunks.empty() && out.chunks.back().direction == dir && missingBefore == 0 && !plain.empty()) {
                out.chunks.back().data.append(reinterpret_cast<const char *>(plain.data()), plain.size());
                return;
            }
            Chunk c;
            c.direction = dir;
            c.data.assign(reinterpret_cast<const char *>(plain.data()), plain.size());
            c.missingBefore = missingBefore;
            c.firstPacket = packetNumber;
            out.chunks.push_back(std::move(c));
        };

        for (const Chunk &chunk: raw.chunks) {
            const size_t h = chunk.direction == Direction::AtoB ? 0 : 1;
            Half &state = half[h];
            const bool fromClient = (chunk.direction == Direction::AtoB) == setup.aIsClient;
            const tls::Direction tlsDir = fromClient ? tls::Direction::ClientToServer : tls::Direction::ServerToClient;
            if (chunk.missingBefore > 0) {   // a hole: the unfinished record is gone and the numbering after it is unknown
                state.buffer.clear();
                state.desync = true;
            }
            if (state.desync) {
                // what follows cannot be numbered: count the records that start in this chunk instead of trying them
                size_t at = 0;
                while (chunk.data.size() - at >= 5 && plausible(chunk.data.data() + at)) {
                    const size_t len = be16(chunk.data.data() + at + 3);
                    if (len > chunk.data.size() - at - 5) break;
                    const uint8_t type = static_cast<uint8_t>(chunk.data[at]);
                    if (type == kApplicationData || (!tls13 && type != kChangeCipherSpec)) ++result.skipped, ++result.records;
                    at += 5 + len;
                }
                if (chunk.missingBefore > 0) emit(chunk.direction, {}, chunk.firstPacket, chunk.missingBefore);   // keeps the gap marker
                continue;
            }
            state.buffer += chunk.data;
            size_t at = 0;
            while (state.buffer.size() - at >= 5) {
                const char *rec = state.buffer.data() + at;
                if (!plausible(rec)) {   // not TLS records any more: nothing after this can be decrypted
                    state.desync = true;
                    break;
                }
                const size_t len = be16(rec + 3);
                if (len > state.buffer.size() - at - 5) break;   // the rest arrives in a later chunk
                const uint8_t type = static_cast<uint8_t>(rec[0]);
                const uint16_t version = be16(rec + 1);
                const std::span<const uint8_t> fragment(reinterpret_cast<const uint8_t *>(rec) + 5, len);
                at += 5 + len;

                const bool isProtected = tls13 ? type == kApplicationData : (state.changedKeys && type != kChangeCipherSpec);
                if (type == kChangeCipherSpec) state.changedKeys = true;
                if (!isProtected) continue;
                ++result.records;
                const uint64_t before = dec.sequence(tlsDir);
                const tls::KeyEpoch epochBefore = dec.epoch(tlsDir);
                tls::DecryptedRecord r = dec.decrypt(tlsDir, type, version, fragment);
                if (r.status == tls::DecryptStatus::Decrypted) {
                    ++result.decrypted;
                    if (r.contentType == kApplicationData) {
                        emit(chunk.direction, r.plaintext, chunk.firstPacket, 0);
                    }
                } else {
                    ++result.failed;
                    // a record the handshake keys cannot open (0-RTT data) must not move the sequence number
                    if (r.status == tls::DecryptStatus::TagFailure && tls13 && epochBefore == tls::KeyEpoch::Handshake) dec.setSequence(tlsDir, before);
                }
            }
            state.buffer.erase(0, at);
        }

        // empty chunks only exist to carry a gap marker
        result.ok = result.decrypted > 0;
        if (!result.ok) {
            result.note = result.failed > 0 ? "no record could be decrypted: the key does not match this connection (wrong key?)"
                          : result.skipped > 0 ? "no record could be decrypted: TCP data of the connection is missing from the capture"
                                               : "the connection carries no encrypted application data";
        } else if (result.failed > 0 || result.skipped > 0) {
            result.note = std::to_string(result.failed + result.skipped) + " of " + std::to_string(result.records) + " protected records are not shown (" +
                          std::to_string(result.failed) + " could not be decrypted, " + std::to_string(result.skipped) +
                          " follow missing TCP data)";
        }
        return result.ok;
    }
} // namespace stream
