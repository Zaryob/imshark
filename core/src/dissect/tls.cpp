// TLS / SSL records, recognised by the record header (any port). Records are framed for TCP reassembly, so a record
// (or a handshake message that spans several records, such as a long Certificate) is decoded as a whole. Handshake
// messages are decoded to the message type, hello fields and extensions, and the certificates of a Certificate message;
// encrypted content is only counted. A message that TCP reassembly cut out of the stream is also registered in the TLS
// session tables (randoms, version, cipher suite, record indices; see tls_session.h) and the detail tree says whether key
// material for the connection is known. When it is, the protected records of that message are decrypted in the load pass
// (tls_decrypt.h): the packet shows what happened to each record (decrypted, wrong key, missing key, ...), a "Decrypted TLS"
// layer with the plaintext, and the application data is dissected as HTTP/1.x or HTTP/2 (ALPN, else sniffed), so the Protocol
// and Info columns of such a packet show the inner protocol.
#include "protocols.h"

#include "tls_decrypt.h"
#include "tls_handshake.h"
#include "util.h"
#include "x509.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <string>
#include <vector>

using packet::Field;

namespace {
    using namespace dissect;
    using namespace dissect::tlsparse;

    // A record header looks plausible: content type 20..24, version 3.0 - 3.4, sane length
    bool plausibleRecord(const char *d, size_t n) {
        if (n < 5) return false;
        const uint8_t type = static_cast<uint8_t>(d[0]);
        const uint8_t major = static_cast<uint8_t>(d[1]), minor = static_cast<uint8_t>(d[2]);
        const size_t len = be16(d + 3);
        return type >= 20 && type <= 24 && major == 3 && minor <= 4 && len > 0 && len <= 16384 + 2048;
    }

    constexpr size_t kMaxHandshake = 1u << 20;   // a handshake message longer than this is not waited for

    // True if the handshake messages in `bytes` end exactly at the end (or one is too large to wait for).
    bool handshakeAligned(const std::string &bytes) {
        size_t q = 0;
        while (q < bytes.size()) {
            if (bytes.size() - q < 4) return false;
            const size_t len = (static_cast<size_t>(static_cast<uint8_t>(bytes[q + 1])) << 16) | be16(bytes.data() + q + 2);
            if (len > kMaxHandshake) return true;
            if (q + 4 + len > bytes.size()) return false;
            q += 4 + len;
        }
        return true;
    }

    // The random a HelloRetryRequest carries in the ServerHello (RFC 8446, 4.1.3): SHA-256 of "HelloRetryRequest"
    constexpr uint8_t kHelloRetryRequestRandom[32] = {0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
                                                      0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

    // One handshake message at bytes[pos, ...) of the joined payload; returns the info word for it
    std::string handshake(const Joined &j, size_t pos, Hello &hello, Field *tree) {
        const size_t n = j.bytes.size() - pos;
        if (n < 4) return "Handshake";
        const char *p = j.bytes.data() + pos;
        const uint8_t type = static_cast<uint8_t>(p[0]);
        const size_t len = (static_cast<size_t>(static_cast<uint8_t>(p[1])) << 16) | be16(p + 2);
        const std::string name = handshakeName(type);

        Field *hs = nullptr;
        if (tree) {
            hs = &tree->add("Handshake Protocol: " + name, j.frame(pos), j.contiguous(pos, std::min(n, len + 4)));
            hs->add("Handshake Type: " + name + " (" + std::to_string(type) + ")", j.frame(pos), 1);
            hs->add("Length: " + std::to_string(len), j.frame(pos + 1), 3);
        }
        const size_t avail = std::min(n - 4, len);
        return decodeHandshakeBody(j, type, pos + 4, avail, len + 4 <= n, hello, hs);
    }

    // The records of one complete TCP message: where each starts, which are ChangeCipherSpec.
    struct RecordScan {
        std::vector<size_t> starts;
        std::vector<uint32_t> changeCipherSpecs;   // record positions
    };

    RecordScan scanRecords(const char *d, size_t n) {
        RecordScan scan;
        size_t pos = 0;
        while (n - pos >= 5 && plausibleRecord(d + pos, n - pos)) {
            if (static_cast<uint8_t>(d[pos]) == 20) scan.changeCipherSpecs.push_back(static_cast<uint32_t>(scan.starts.size()));
            scan.starts.push_back(pos);
            const size_t len = be16(d + pos + 3);
            if (len > n - pos - 5) break;
            pos += 5 + len;
        }
        return scan;
    }

    std::string roleText(const TlsSession &s, unsigned direction) {
        switch (s.roleOf(direction)) {
            case TlsRole::Client: return "client to server";
            case TlsRole::Server: return "server to client";
            default: return "direction not known";
        }
    }

    void zeroRanges(Field &f) {
        f.offset = 0;
        f.length = 0;
        for (auto &c: f.children) zeroRanges(c);
    }

    const char *innerName(TlsInner k) { return k == TlsInner::Http2 ? "HTTP/2" : k == TlsInner::Http1 ? "HTTP/1.x" : "unknown"; }

    // The records of one complete message as the decryptor wants them; false if the last one is cut (then nothing is decrypted).
    bool recordInputs(const char *data, size_t length, const RecordScan &scan, std::vector<TlsRecordInput> &out) {
        out.clear();
        for (size_t start: scan.starts) {
            const size_t len = be16(data + start + 3);
            if (len > length - start - 5) return false;
            out.push_back({static_cast<uint8_t>(data[start]), be16(data + start + 1),
                           std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(data) + start + 5, len)});
        }
        return true;
    }

    // What the application data of a message was dissected as, if it was.
    struct InnerResult {
        bool dissected = false;
        std::string protocol, info, text, text2;
        uint16_t type = 0, flags = 0, code = 0;
        uint32_t stream = 0;
        std::vector<Field> fields;
    };

    // Dissects decrypted application data as the protocol the load pass settled on for it. A chunk that does not start a
    // message (the rest of a body, a frame cut across records) is not a message: `dissected` stays false.
    InnerResult dissectInner(Context &ctx, TlsInner kind, const std::string &plain) {
        InnerResult r;
        if (kind == TlsInner::Unknown || plain.empty()) return r;
        packet::PacketInfo nested(ctx.pack.number);
        nested.link_type = ctx.pack.link_type;
        Context nctx{nested, plain.data(), plain.size(), ctx.tcp, ctx.registry, ctx.mode};
        nctx.sessions = ctx.sessions;
        if (kind == TlsInner::Http2) {
            if (frameHttp2(plain.data(), plain.size()).kind == StreamFrame::Kind::Reject) return r;
            dissectHttp2(nctx, plain.data(), plain.size());
        } else if (!dissectHttp(nctx, plain.data(), plain.size())) {
            return r;
        }
        r.dissected = true;
        r.protocol = nested.protocol;
        r.info = nested.info;
        r.text = nested.app_text;
        r.text2 = nested.app_text2;
        r.type = nested.app_type;
        r.flags = nested.app_flags;
        r.code = nested.app_code;
        r.stream = nested.app_stream;
        r.fields = std::move(nested.fields);
        for (auto &f: r.fields) zeroRanges(f);   // offsets inside the plaintext do not map to bytes of this frame
        return r;
    }

    // Adds the "Decrypted TLS" layer for the decrypted records of a message and takes over what the inner protocol found.
    void showDecryption(Context &ctx, const TlsMessageDecryption &md) {
        auto &pack = ctx.pack;
        size_t total = 0, decrypted = 0;
        std::string appData;                 // the application data of the message, in record order
        TlsInner inner = TlsInner::Unknown;
        for (size_t i = 0; i < md.outcomes.size(); ++i) {
            if (md.outcomes[i].recordState() != TlsRecordState::Decrypted) continue;
            ++decrypted;
            total += md.plaintext[i].size();
            if (md.outcomes[i].contentType == 23) {
                appData.append(reinterpret_cast<const char *>(md.plaintext[i].data()), md.plaintext[i].size());
                if (inner == TlsInner::Unknown) inner = md.outcomes[i].innerProtocol();
            }
        }
        if (decrypted == 0) return;

        Field *layer = ctx.wantFields() ? &ctx.addLayer("Decrypted TLS (" + std::to_string(total) + " bytes)", 0, 0) : nullptr;
        std::string info;                    // what the decrypted records are, for the Info column
        for (size_t i = 0; i < md.outcomes.size(); ++i) {
            const TlsRecordOutcome &o = md.outcomes[i];
            if (o.recordState() != TlsRecordState::Decrypted) continue;
            const std::vector<uint8_t> &pt = md.plaintext[i];
            const std::string sizeText = std::to_string(pt.size()) + " bytes";
            std::string part;
            if (o.contentType == 22) {
                Field *node = layer ? &layer->add("Decrypted Handshake Protocol (" + sizeText + ")") : nullptr;
                Joined joined;
                joined.append(reinterpret_cast<const char *>(pt.data()), pt.size(), 0);
                Hello scratch;
                size_t hp = 0;
                for (int messages = 0; joined.bytes.size() - hp >= 4 && messages < 8; ++messages) {
                    const char *m = joined.bytes.data() + hp;
                    const size_t mlen = (static_cast<size_t>(static_cast<uint8_t>(m[1])) << 16) | be16(m + 2);
                    const std::string w = handshake(joined, hp, scratch, node);
                    part += (part.empty() ? "" : ", ") + w;
                    if (mlen >= joined.bytes.size() - hp - 4) break;
                    hp += 4 + mlen;
                }
                if (part.empty()) part = "Handshake";
            } else if (o.contentType == 21) {
                part = "Alert";
                Field *node = layer ? &layer->add("Decrypted Alert (" + sizeText + ")") : nullptr;
                if (pt.size() >= 2) {
                    const char *name = alertName(pt[1]);
                    part += std::string(" (") + (name ? name : "unknown") + ")";
                    if (node) {
                        node->add(std::string("Level: ") + (pt[0] == 1 ? "Warning" : pt[0] == 2 ? "Fatal" : "Unknown") + " (" + std::to_string(pt[0]) + ")");
                        node->add(std::string("Description: ") + (name ? name : "Unknown") + " (" + std::to_string(pt[1]) + ")");
                    }
                }
            } else if (o.contentType == 23) {
                part = "Application Data (decrypted, " + sizeText + ")";
                if (layer) {
                    Field &node = layer->add("Decrypted Application Data (" + sizeText + ")");
                    node.add("Record sequence number: " + std::to_string(o.sequence) + (o.keyUpdates ? " (after " + std::to_string(o.keyUpdates) + " KeyUpdate(s))" : ""));
                    node.add(std::string("Protocol: ") + innerName(o.innerProtocol()));
                    node.add("Data (" + sizeText + ")");
                }
            } else {
                part = std::string(contentTypeName(o.contentType)) + " (decrypted)";
                if (layer) layer->add(std::string("Decrypted ") + contentTypeName(o.contentType) + " (" + sizeText + ")");
            }
            info += (info.empty() ? "" : ", ") + part;
        }

        const InnerResult r = dissectInner(ctx, inner, appData);
        if (r.dissected) {
            pack.protocol = r.protocol;
            pack.info = r.info;
            pack.app_text = r.text;
            pack.app_text2 = r.text2;
            pack.app_type = r.type;
            pack.app_flags = r.flags;
            pack.app_code = r.code;
            pack.app_stream = r.stream;
            if (ctx.wantFields()) for (const Field &f: r.fields) pack.fields.push_back(f);
        } else if (decrypted == md.outcomes.size() || md.outcomes.size() == 1) {
            // nothing of HTTP in it: the Info column says what the decrypted records are (the TLS records of a message
            // that mixes decrypted and other records keep the text the record loop gave them)
            pack.info = info;
        }
    }

    // Load pass: puts the complete TCP message at `data` into the session tables and decrypts its records. Then (both
    // passes) adds the facts of the session to the TLS layer: the position of the message's records in their direction,
    // the state of the key material and what became of each protected record.
    void sessionInfo(Context &ctx, const char *data, size_t length, const Hello &hello, size_t helloGroupStart, Field *layer) {
        if (!ctx.sessions) return;
        auto &pack = ctx.pack;
        const bool stream = ctx.tcpStreamSeq >= 0 && pack.ip_protocol == 6;
        const uint32_t startSeq = static_cast<uint32_t>(ctx.tcpStreamSeq);
        const size_t recordNodes = layer ? layer->children.size() : 0;   // the record nodes the record loop added, in record order

        RecordScan scan;
        std::vector<TlsRecordInput> inputs;
        bool inputsOk = false;
        TlsMessageDecryption md;
        bool haveDecryption = false;
        if (stream) {
            scan = scanRecords(data, length);
            inputsOk = recordInputs(data, length, scan, inputs);
        }
        if (stream && ctx.mode != ParseMode::Replay) {
            TlsMessageFacts f;
            f.packet = static_cast<uint32_t>(pack.number);
            f.startSeq = startSeq;
            f.length = static_cast<uint32_t>(length);
            f.records = static_cast<uint32_t>(scan.starts.size());
            f.changeCipherSpecs = scan.changeCipherSpecs;
            // keys have changed behind a ChangeCipherSpec: what looks like a hello after it is encrypted data
            // (only for a message that continues the stream: after a SYN or with a restarted sequence space this is a new connection)
            const bool encrypted = ctx.sessions->tlsDirectionEncrypted(pack.source, pack.src_port, pack.destination, pack.dst_port, startSeq);
            if (hello.helloType != 0 && !encrypted) {
                f.clientHello = hello.helloType == 1;
                f.serverHello = hello.helloType == 2;
                f.random = hello.random;
                f.earlyData = f.clientHello && hello.earlyData;
                const auto at = std::find(scan.starts.begin(), scan.starts.end(), helloGroupStart);
                f.helloRecord = at == scan.starts.end() ? 0 : static_cast<uint32_t>(at - scan.starts.begin());
                if (f.serverHello) {
                    f.helloRetryRequest = std::memcmp(hello.random.data(), kHelloRetryRequestRandom, 32) == 0;
                    f.version = hello.supportedVersion != 0 ? hello.supportedVersion : hello.version;
                    f.cipherSuite = hello.cipher;
                    f.alpn = hello.alpn;
                }
            }
            TlsAddResult added;
            const bool registered = ctx.sessions->addTlsMessage(pack.source, pack.src_port, pack.destination, pack.dst_port, f, &added);
            if (registered && added.registered && inputsOk) {
                haveDecryption = ctx.sessions->decryptTlsMessage(added, f.packet, startSeq, inputs, md);
            } else if (!registered && ctx.sessions->isTableStateLost("tls") &&
                       std::any_of(inputs.begin(), inputs.end(), [](const TlsRecordInput &r) { return r.type == 23; })) {
                // no room to keep what decryption needs: say so rather than showing nothing
                pack.reassembled_in = mergeTlsSummary(pack.reassembled_in, tlsSummaryOf(TlsRecordState::StateLost));
            }
        }

        const TlsMessageRef *ref = stream ? ctx.sessions->findTlsMessage(static_cast<uint32_t>(pack.number), startSeq) : nullptr;
        if (ref && inputsOk && !haveDecryption) {   // Replay (or a message that was registered before): the stored outcomes
            ctx.sessions->readTlsMessage(*ref, inputs, md);
            haveDecryption = md.outcomes.size() == inputs.size();
        }
        if (haveDecryption) {
            for (const TlsRecordOutcome &o: md.outcomes) pack.reassembled_in = mergeTlsSummary(pack.reassembled_in, tlsSummaryOf(o.recordState()));
        }
        const TlsSession *session = ref ? ctx.sessions->tlsSession(ref->session) : nullptr;

        if (layer) {
            // a packet that is not a whole message cannot tell which of several connections on the same endpoints it belongs to:
            // then it says nothing about keys rather than showing another connection's state
            if (!ref && ctx.sessions->tlsSessionsBetween(pack.source, pack.src_port, pack.destination, pack.dst_port) > 1) return;
            if (!session) session = ctx.sessions->findTlsSession(pack.source, pack.src_port, pack.destination, pack.dst_port);
            if (ref && session) {
                const std::string first = std::to_string(ref->firstRecord);
                const std::string index = ref->records > 1 ? first + "-" + std::to_string(ref->firstRecord + ref->records - 1) : first;
                layer->add("[TLS record index: " + index + " (" + roleText(*session, ref->direction) + ")]");
            }
            tls::KeyEntry keys;
            const bool found = session && session->hasClientRandom && ctx.sessions->findTlsKeys(session->clientRandom, keys);
            layer->add(std::string("Key material: ") + tls::availabilityText(tls::classify(found ? &keys : nullptr, session ? session->version : uint16_t(0))));
            if (!ref && stream && ctx.sessions->isTableStateLost("tls") && (tlsSummaryState(pack) == TlsRecordState::StateLost)) {
                layer->add(std::string("Decryption status: ") + tlsStateText(TlsRecordState::StateLost));
            }
        }

        if (!haveDecryption) return;
        // what became of each protected record, under its record node; and the packet's overall state
        TlsRecordState overall = TlsRecordState::Clear;
        for (size_t i = 0; i < md.outcomes.size(); ++i) {
            const TlsRecordOutcome &o = md.outcomes[i];
            if (o.recordState() == TlsRecordState::Clear) continue;
            if (overall == TlsRecordState::Clear || o.recordState() == TlsRecordState::Decrypted) overall = o.recordState();
            if (layer && i < recordNodes) {
                Field &rec = layer->children[i];
                rec.add(std::string("[Decryption: ") + tlsStateText(o.recordState()) + "]");
                if (o.recordState() == TlsRecordState::Decrypted) {
                    rec.add(std::string("[Inner content type: ") + contentTypeName(o.contentType) + " (" + std::to_string(o.contentType) + "), " +
                            std::to_string(o.plainLength) + " bytes]");
                }
            }
        }
        if (layer && overall != TlsRecordState::Clear) {
            layer->add(std::string("Decryption status: ") + tlsStateText(overall));
            const bool good = overall == TlsRecordState::Decrypted;
            const bool warn = overall == TlsRecordState::TagFailure || overall == TlsRecordState::Malformed || overall == TlsRecordState::StateLost;
            layer->add(std::string("[Expert Info (") + (good ? "Chat" : warn ? "Warning" : "Note") + "/Decryption): " +
                       (good ? "TLS records decrypted with the key log" : tlsStateText(overall)) + "]");
        }
        showDecryption(ctx, md);
    }
} // namespace

dissect::StreamFrame dissect::frameTls(const char *d, size_t n) {
    // the first bytes decide: type, then major version, then minor version
    if (n >= 1 && (static_cast<uint8_t>(d[0]) < 20 || static_cast<uint8_t>(d[0]) > 24)) return {StreamFrame::Kind::Reject, 0};
    if (n >= 2 && static_cast<uint8_t>(d[1]) != 3) return {StreamFrame::Kind::Reject, 0};
    if (n >= 3 && static_cast<uint8_t>(d[2]) > 4) return {StreamFrame::Kind::Reject, 0};
    if (n < 5) return {StreamFrame::Kind::NeedMore, 0};
    if (!plausibleRecord(d, n)) return {StreamFrame::Kind::Reject, 0};

    // a message made of consecutive handshake records ends at the record where the handshake messages end
    size_t pos = 0;
    std::string handshakeBytes;
    for (int records = 0; records < 64; ++records) {
        if (n - pos < 5) return {StreamFrame::Kind::NeedMore, 0};
        if (!plausibleRecord(d + pos, n - pos)) {
            // after the first record: whatever follows is not another handshake record, so the message ends here
            return pos == 0 ? StreamFrame{StreamFrame::Kind::Reject, 0} : StreamFrame{StreamFrame::Kind::Complete, pos};
        }
        const size_t len = be16(d + pos + 3);
        const uint8_t type = static_cast<uint8_t>(d[pos]);
        if (records > 0 && type != 22) return {StreamFrame::Kind::Complete, pos};
        if (n - pos < 5 + len) return {StreamFrame::Kind::NeedMore, 0};
        if (type != 22) return {StreamFrame::Kind::Complete, pos + 5 + len};
        handshakeBytes.append(d + pos + 5, len);
        pos += 5 + len;
        if (handshakeAligned(handshakeBytes)) return {StreamFrame::Kind::Complete, pos};
    }
    return {StreamFrame::Kind::Complete, pos};
}

bool dissect::dissectTls(Context &ctx, const char *data, size_t length) {
    if (!plausibleRecord(data, length)) return false;

    auto &pack = ctx.pack;
    const size_t o = ctx.offsetOf(data);
    pack.protocol = "TLS";
    pack.app_code = static_cast<uint8_t>(data[0]);
    pack.app_flags = be16(data + 1);

    Field *layer = ctx.wantFields() ? &ctx.addLayer("Transport Layer Security", o, length) : nullptr;
    std::string info;
    Hello hello;
    size_t pos = 0, helloGroupStart = 0;   // helloGroupStart: where the record that holds the hello message starts
    int records = 0;
    while (length - pos >= 5 && records < 16) {
        if (!plausibleRecord(data + pos, length - pos)) break;
        const uint8_t type = static_cast<uint8_t>(data[pos]);
        const uint16_t version = be16(data + pos + 1);
        const size_t recLen = be16(data + pos + 3);
        const size_t avail = std::min(recLen, length - pos - 5);
        bool partial = avail < recLen;

        auto addRecord = [&](size_t at, uint8_t t, uint16_t v, size_t l, size_t a) -> Field * {
            if (!layer) return nullptr;
            Field *r = &layer->add(versionName(v) + " Record Layer: " + contentTypeName(t), o + at, 5 + a);
            r->add(std::string("Content Type: ") + contentTypeName(t) + " (" + std::to_string(t) + ")", o + at, 1);
            r->add("Version: " + versionName(v) + " (" + hexString(v, 4) + ")", o + at + 1, 2);
            r->add("Length: " + std::to_string(l), o + at + 3, 2);
            return r;
        };
        Field *rec = addRecord(pos, type, version, recLen, avail);
        size_t consumed = 5 + recLen;   // bytes of the frame this group of records covers

        std::string part;
        const uint8_t helloBefore = hello.helloType;
        if (type == 22) {
            // the handshake messages of consecutive records are read as one stream: a message may span records
            Joined joined;
            joined.append(data + pos + 5, avail, o + pos + 5);
            struct Follow { size_t at; uint16_t version; size_t length, avail; };
            std::vector<Follow> follow;
            size_t next = pos + consumed;
            while (!partial && !handshakeAligned(joined.bytes) && length - next >= 5 && plausibleRecord(data + next, length - next) &&
                   static_cast<uint8_t>(data[next]) == 22 && follow.size() < 63) {
                const size_t l = be16(data + next + 3), a = std::min(l, length - next - 5);
                joined.append(data + next + 5, a, o + next + 5);
                follow.push_back({next, be16(data + next + 1), l, a});
                if (a < l) partial = true;
                next += 5 + l;
            }
            size_t hp = 0;
            int messages = 0;
            while (joined.bytes.size() - hp >= 4 && messages < 8) {
                const char *m = joined.bytes.data() + hp;
                const size_t mlen = (static_cast<size_t>(static_cast<uint8_t>(m[1])) << 16) | be16(m + 2);
                const std::string w = handshake(joined, hp, hello, rec);
                if (pack.app_type == 0) pack.app_type = static_cast<uint8_t>(m[0]);
                part += (part.empty() ? "" : ", ") + w;
                ++messages;
                if (mlen >= joined.bytes.size() - hp - 4) break; // the message fills (or overruns) the rest of the payload
                hp += 4 + mlen;
            }
            if (part.empty()) part = "Handshake";
            if (hello.cipher != 0) part += " (" + cipherName(hello.cipher) + ")";
            if (!follow.empty()) {
                if (rec) rec->add("[Handshake message spans " + std::to_string(follow.size() + 1) + " records]");
                for (const auto &f: follow) addRecord(f.at, 22, f.version, f.length, f.avail);
                consumed = next - pos;
            }
        } else if (type == 23) {
            part = "Application Data";
            if (rec) rec->add("Encrypted Application Data (" + std::to_string(avail) + " bytes)", o + pos + 5, avail);
        } else if (type == 21 && avail >= 2) {
            part = "Alert";
            const uint8_t level = static_cast<uint8_t>(data[pos + 5]), description = static_cast<uint8_t>(data[pos + 6]);
            if (rec) {
                Field &a = rec->add("Alert Message: level " + std::to_string(level) + ", description " + std::to_string(description), o + pos + 5, 2);
                a.add(std::string("Level: ") + (level == 1 ? "Warning" : level == 2 ? "Fatal" : "Unknown") + " (" + std::to_string(level) + ")", o + pos + 5, 1);
                a.add(std::string("Description: ") + (alertName(description) ? alertName(description) : "Unknown") + " (" + std::to_string(description) + ")", o + pos + 6, 1);
            }
        } else {
            part = contentTypeName(type);
        }
        if (partial) part += " [fragment]";
        if (helloBefore == 0 && hello.helloType != 0) helloGroupStart = pos;
        info += (info.empty() ? "" : ", ") + part;

        if (!hello.serverName.empty()) pack.app_text = hello.serverName;
        if (!hello.subject.empty()) pack.app_text2 = hello.subject;
        pos += consumed;
        ++records;
        if (partial) break;
    }
    pack.info = info.empty() ? "TLS record" : info;
    sessionInfo(ctx, data, length, hello, helloGroupStart, layer);
    if (hello.supportedVersion >= 0x0304 || hello.version == 0x0304) pack.protocol = "TLS";
    return true;
}
