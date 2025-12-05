#include "tls_decrypt.h"

#include <algorithm>
#include <cstring>

namespace dissect {
    namespace {
        constexpr uint16_t kTls13 = 0x0304;
        constexpr uint8_t kChangeCipherSpec = 20;
        constexpr uint8_t kHandshake = 22;
        constexpr uint8_t kApplicationData = 23;
        constexpr uint8_t kEncryptedExtensions = 8;
        constexpr uint16_t kExtAlpn = 16;

        uint16_t be16(const uint8_t *p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

        bool startsWith(std::span<const uint8_t> data, const char *prefix) {
            const size_t n = std::strlen(prefix);
            return data.size() >= n && std::memcmp(data.data(), prefix, n) == 0;
        }

        TlsRecordOutcome outcomeOf(TlsRecordState state, uint8_t contentType) {
            TlsRecordOutcome o;
            o.state = static_cast<uint8_t>(state);
            o.contentType = contentType;
            return o;
        }
    } // namespace

    TlsInner tlsInnerFromAlpn(const std::string &alpn) {
        if (alpn == "h2") return TlsInner::Http2;
        if (alpn == "http/1.1" || alpn == "http/1.0") return TlsInner::Http1;
        return TlsInner::Unknown;
    }

    TlsInner sniffTlsInner(std::span<const uint8_t> data) {
        if (startsWith(data, "PRI * HTTP/2.0")) return TlsInner::Http2;
        for (const char *prefix: {"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "HTTP/1."}) {
            if (startsWith(data, prefix)) return TlsInner::Http1;
        }
        return TlsInner::Unknown;
    }

    std::string alpnFromEncryptedExtensions(std::span<const uint8_t> p) {
        size_t pos = 0;
        while (p.size() - pos >= 4) {   // the handshake messages of the record: type, 24 bit length, body
            const size_t len = (static_cast<size_t>(p[pos + 1]) << 16) | be16(p.data() + pos + 2);
            if (len > p.size() - pos - 4) break;
            if (p[pos] == kEncryptedExtensions && len >= 2) {
                const uint8_t *body = p.data() + pos + 4;
                size_t at = 2;
                const size_t end = std::min<size_t>(len, 2 + be16(body));
                while (end - at >= 4) {
                    const uint16_t type = be16(body + at), extLen = be16(body + at + 2);
                    if (extLen > end - at - 4) break;
                    const uint8_t *d = body + at + 4;
                    if (type == kExtAlpn && extLen >= 3) {   // protocol name list (2), then one length prefixed name
                        const size_t nameLen = d[2];
                        if (3 + nameLen <= extLen) return std::string(reinterpret_cast<const char *>(d + 3), nameLen);
                    }
                    at += 4 + extLen;
                }
                return {};
            }
            pos += 4 + len;
        }
        return {};
    }

    void TlsDecryptTable::clear() {
        outcomes_.clear();
        outcomes_.shrink_to_fit();
        runtimes_.clear();
        memory_ = 0;
        exhausted_ = false;
    }

    tls::Direction TlsDecryptTable::directionOf(const TlsSession &session, unsigned direction) {
        return session.roleOf(direction) == TlsRole::Server ? tls::Direction::ServerToClient : tls::Direction::ClientToServer;
    }

    TlsRecordState TlsDecryptTable::unkeyedState(const TlsSession &session, unsigned direction, uint32_t index, uint8_t type) {
        if (type == kChangeCipherSpec) return TlsRecordState::Clear;   // sent before the keys of its own direction change
        const TlsDirection &d = session.directions[direction & 1];
        const bool afterChangeCipherSpec = !d.changeCipherSpecs.empty() && index > d.changeCipherSpecs.front();
        if (session.version == kTls13) return type == kApplicationData ? TlsRecordState::NoKey : TlsRecordState::Clear;
        if (session.version == 0) return (type == kApplicationData || afterChangeCipherSpec) ? TlsRecordState::NoHandshake : TlsRecordState::Clear;
        return afterChangeCipherSpec ? TlsRecordState::NoKey : TlsRecordState::Clear;   // TLS 1.2 and older: after the ChangeCipherSpec
    }

    bool TlsDecryptTable::process(TlsSession &session, uint32_t sessionId, unsigned direction, uint32_t firstRecord, bool gapBefore,
                                  std::span<const TlsRecordInput> records, const tls::KeyEntry *keys, size_t maxMemory,
                                  uint32_t &firstOutcome, TlsMessageDecryption &out) {
        out.outcomes.clear();
        out.plaintext.assign(records.size(), {});
        firstOutcome = kTlsNoRecord;
        if (exhausted_) return false;
        // a session's decryptor (keys and secrets) is paid for when its entry is made, so building it later cannot overrun the budget
        const bool newRuntime = runtimes_.find(sessionId) == runtimes_.end();
        const size_t need = records.size() * sizeof(TlsRecordOutcome) + (newRuntime ? kRuntimeCost : 0);
        if (memory_ + need > maxMemory) {
            exhausted_ = true;
            return false;
        }
        if (newRuntime) memory_ += kRuntimeCost;
        Runtime &rt = runtimes_[sessionId];
        direction &= 1;
        if (gapBefore) rt.desync[direction] = true;
        const tls::Direction dir = directionOf(session, direction);

        for (size_t i = 0; i < records.size(); ++i) {
            const TlsRecordInput &rec = records[i];
            const uint32_t index = firstRecord + static_cast<uint32_t>(i);
            TlsRecordOutcome o = outcomeOf(unkeyedState(session, direction, index, rec.type), rec.type);

            if (o.recordState() == TlsRecordState::NoKey) {   // a protected record, and there is key material to try
                if (!rt.built) {
                    rt.built = true;
                    if (keys && session.hasClientRandom) {
                        rt.decryptor.emplace(session.version, session.cipherSuite, session.clientRandom, session.serverRandom, keys);
                    }
                }
                if (!rt.decryptor) {
                    // no key entry: the state stays NoKey
                } else if (rt.decryptor->availability() == tls::DecryptStatus::UnsupportedSuite) {
                    o.state = static_cast<uint8_t>(TlsRecordState::UnsupportedSuite);
                } else if (rt.decryptor->availability() == tls::DecryptStatus::NoBackend) {
                    o.state = static_cast<uint8_t>(TlsRecordState::NoBackend);
                } else if (rt.desync[direction]) {
                    o.state = static_cast<uint8_t>(TlsRecordState::CaptureGap);
                } else {
                    tls::RecordDecryptor &dec = *rt.decryptor;
                    const uint64_t before = dec.sequence(dir);
                    const tls::KeyEpoch epochBefore = dec.epoch(dir);
                    tls::DecryptedRecord r = dec.decrypt(dir, rec.type, rec.version, rec.fragment);
                    o.sequence = r.sequence;
                    o.epoch = static_cast<uint8_t>(r.epoch);
                    o.keyUpdates = r.keyUpdates;
                    switch (r.status) {
                        case tls::DecryptStatus::Decrypted: {
                            o.state = static_cast<uint8_t>(TlsRecordState::Decrypted);
                            o.contentType = r.contentType;
                            o.plainLength = static_cast<uint32_t>(r.plaintext.size());
                            if (r.contentType == kHandshake && session.roleOf(direction) == TlsRole::Server && r.epoch == tls::KeyEpoch::Handshake &&
                                session.alpn.empty() && session.version == kTls13) {
                                session.alpn = alpnFromEncryptedExtensions(r.plaintext);
                            }
                            if (r.contentType == kApplicationData) {
                                if (session.inner == TlsInner::Unknown) {
                                    session.inner = tlsInnerFromAlpn(session.alpn);
                                    if (session.inner == TlsInner::Unknown) session.inner = sniffTlsInner(r.plaintext);
                                }
                                o.inner = static_cast<uint8_t>(session.inner);
                            }
                            out.plaintext[i] = std::move(r.plaintext);
                            break;
                        }
                        case tls::DecryptStatus::TagFailure:
                            o.state = static_cast<uint8_t>(TlsRecordState::TagFailure);
                            // a record of the handshake epoch that cannot be opened (0-RTT data of the client, or a wrong key)
                            // must not move the sequence number: the Finished that follows is still the first record of its keys
                            if (epochBefore == tls::KeyEpoch::Handshake && session.version == kTls13) {
                                dec.setSequence(dir, before);
                                if (direction == static_cast<unsigned>(session.clientDirection) && session.earlyData) {
                                    o.state = static_cast<uint8_t>(TlsRecordState::EarlyData);
                                }
                            }
                            break;
                        case tls::DecryptStatus::Malformed: o.state = static_cast<uint8_t>(TlsRecordState::Malformed); break;
                        case tls::DecryptStatus::UnsupportedSuite: o.state = static_cast<uint8_t>(TlsRecordState::UnsupportedSuite); break;
                        case tls::DecryptStatus::NoBackend: o.state = static_cast<uint8_t>(TlsRecordState::NoBackend); break;
                        case tls::DecryptStatus::NoKey: o.state = static_cast<uint8_t>(TlsRecordState::NoKey); break;
                    }
                }
            }
            out.outcomes.push_back(o);
        }

        firstOutcome = static_cast<uint32_t>(outcomes_.size());
        outcomes_.insert(outcomes_.end(), out.outcomes.begin(), out.outcomes.end());
        memory_ += out.outcomes.size() * sizeof(TlsRecordOutcome);
        return true;
    }

    void TlsDecryptTable::read(const TlsSession &session, const TlsMessageRef &ref, std::span<const TlsRecordInput> records,
                               const tls::KeyEntry *keys, TlsMessageDecryption &out) const {
        out.outcomes.clear();
        out.plaintext.assign(records.size(), {});
        const bool recorded = ref.firstOutcome != kTlsNoRecord && ref.records == records.size() &&
                              static_cast<size_t>(ref.firstOutcome) + records.size() <= outcomes_.size();
        for (size_t i = 0; i < records.size(); ++i) {
            out.outcomes.push_back(recorded ? outcomes_[ref.firstOutcome + i]
                                            : outcomeOf(unkeyedState(session, ref.direction, ref.firstRecord + static_cast<uint32_t>(i), records[i].type),
                                                        records[i].type));
        }
        if (!recorded || !keys || !session.hasClientRandom) return;

        std::optional<tls::RecordDecryptor> decryptor;
        for (size_t i = 0; i < records.size(); ++i) {
            TlsRecordOutcome &o = out.outcomes[i];
            if (o.recordState() != TlsRecordState::Decrypted) continue;
            if (!decryptor) decryptor.emplace(session.version, session.cipherSuite, session.clientRandom, session.serverRandom, keys);
            tls::DecryptedRecord r = decryptor->decryptAt(directionOf(session, ref.direction), static_cast<tls::KeyEpoch>(o.epoch), o.keyUpdates,
                                                          o.sequence, records[i].type, records[i].version, records[i].fragment);
            if (r.status == tls::DecryptStatus::Decrypted && r.contentType == o.contentType) {
                out.plaintext[i] = std::move(r.plaintext);
            } else {
                o.state = static_cast<uint8_t>(TlsRecordState::TagFailure);   // the keys are not the ones the load pass used
            }
        }
    }
} // namespace dissect
