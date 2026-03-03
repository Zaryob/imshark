// DTLS (RFC 6347) over UDP, recognised by the record header: content type 20..25, a DTLS version (0xfeff, 0xfefd, 0xfefc) and
// a length that fits. On any port a datagram counts only when it is nothing but valid records; on the DTLS ports (4433, 5684) and
// for Decode As a valid first header is enough (the capture may have cut the last record) and a DTLS 1.3 record (RFC 9147,
// unified header 001CSLEE) is recognised and flagged, not decoded. A datagram that fails the check is left alone, so it shows as
// the port's usual protocol or as raw UDP.
//
// Handshake messages are split into fragments that travel in different records and datagrams. The load pass puts every fragment
// into the session tables (dtls_session.h), which reassemble the message with network::DatagramReassembler and remember, per
// fragment, where its message was completed. The packet that completes a message decodes it with the TLS parsers (hello with
// cookie, extensions, certificates; tls_handshake.h) and lists the packets it was put together from; the earlier fragments say
// "[Reassembled in #N]". A message that arrives whole is decoded in place and compared with the last message of its key, so a
// retransmitted flight is marked as such. Hellos register DTLS sessions (randoms, version, cipher suite) from which the keys of a
// CLIENT_RANDOM key log entry are derived: records of epoch >= 1 are opened in the load pass (dtls_decrypt.h), the packet shows
// what became of each, a "Decrypted DTLS" layer with the plaintext, and the Info column says "(decrypted)". Detail building
// only reads what the load pass stored.
#include "protocols.h"

#include "dtls_decrypt.h"
#include "tls_handshake.h"
#include "tls_summary.h"
#include "util.h"

#include <algorithm>
#include <string>
#include <vector>

using packet::Field;

namespace {
    using namespace dissect;
    using namespace dissect::tlsparse;

    constexpr size_t kRecordHeader = 13;       // type, version, epoch (2), sequence number (6), length (2)
    constexpr size_t kHandshakeHeader = 12;    // type, length (3), message_seq (2), fragment_offset (3), fragment_length (3)
    constexpr size_t kMaxRecord = 16384 + 2048;
    constexpr uint8_t kChangeCipherSpec = 20, kAlert = 21, kHandshake = 22, kApplicationData = 23, kConnectionId = 25;

    bool dtlsVersion(uint16_t v) { return v == 0xfeff || v == 0xfefd || v == 0xfefc; }

    uint32_t be24(const char *p) {
        return (static_cast<uint32_t>(static_cast<uint8_t>(p[0])) << 16) | (static_cast<uint32_t>(static_cast<uint8_t>(p[1])) << 8) | static_cast<uint8_t>(p[2]);
    }

    struct Header {
        uint8_t type = 0;
        uint16_t version = 0, epoch = 0;
        uint64_t sequence = 0;
        size_t length = 0;
    };

    bool readHeader(const char *d, size_t n, Header &h) {
        if (n < kRecordHeader) return false;
        h.type = static_cast<uint8_t>(d[0]);
        if (h.type < 20 || h.type > 25) return false;
        h.version = be16(d + 1);
        if (!dtlsVersion(h.version)) return false;
        h.epoch = be16(d + 3);
        h.sequence = 0;
        for (size_t i = 0; i < 6; ++i) h.sequence = (h.sequence << 8) | static_cast<uint8_t>(d[5 + i]);
        h.length = be16(d + 11);
        return h.length <= kMaxRecord;
    }

    // Every byte of the datagram belongs to a valid record (what a content heuristic on an arbitrary port insists on).
    bool onlyRecords(const char *d, size_t n) {
        size_t pos = 0;
        int records = 0;
        while (pos < n) {
            Header h;
            if (!readHeader(d + pos, n - pos, h) || h.length > n - pos - kRecordHeader) return false;
            pos += kRecordHeader + h.length;
            ++records;
        }
        return records > 0;
    }

    // DTLS 1.3 unified header (RFC 9147 section 4): 001CSLEE, connection ID if C, sequence number (S: 2 bytes, else 1), length if L.
    struct Unified {
        bool connectionId = false, longSequence = false, hasLength = false;
        uint8_t epochBits = 0;
        size_t headerLength = 0;    // not known with a connection ID
        size_t length = 0;          // the record's length if the header says it
    };

    bool readUnified(const char *d, size_t n, Unified &u) {
        if (n < 2) return false;
        const uint8_t first = static_cast<uint8_t>(d[0]);
        if ((first & 0xe0) != 0x20) return false;
        u.connectionId = first & 0x10;
        u.longSequence = first & 0x08;
        u.hasLength = first & 0x04;
        u.epochBits = first & 0x03;
        if (u.connectionId) return true;   // the length of the ID is negotiated: all that can be said is that it is DTLS 1.3
        u.headerLength = 1 + (u.longSequence ? 2 : 1) + (u.hasLength ? 2 : 0);
        if (n < u.headerLength) return false;
        if (u.hasLength) {
            u.length = be16(d + u.headerLength - 2);
            if (u.length > n - u.headerLength) return false;
        } else {
            u.length = n - u.headerLength;
        }
        return true;
    }

    void zeroRanges(Field &f) {
        f.offset = 0;
        f.length = 0;
        for (auto &c: f.children) zeroRanges(c);
    }

    // Where the handshake fragment at `position` stands, from the tables (both passes read the same entry).
    struct FragmentState {
        const DtlsFragmentRef *ref = nullptr;
        const DtlsMessage *message = nullptr;
    };

    std::string packetList(const std::vector<uint32_t> &packets) {
        std::string out;
        for (uint32_t n: packets) out += (out.empty() ? "#" : ", #") + std::to_string(n);
        return out;
    }

    const char *roleText(const DtlsSession &s, unsigned direction) {
        if (s.clientDirection < 0) return "direction not known";
        return direction == static_cast<unsigned>(s.clientDirection) ? "client to server" : "server to client";
    }

    // The messages in the plaintext of a decrypted handshake record: names for the Info column, nodes for the tree.
    std::string decryptedHandshake(const std::vector<uint8_t> &plain, Field *node) {
        std::string names;
        size_t pos = 0;
        for (int messages = 0; plain.size() - pos >= kHandshakeHeader && messages < 8; ++messages) {
            const char *m = reinterpret_cast<const char *>(plain.data()) + pos;
            const uint8_t type = static_cast<uint8_t>(m[0]);
            const uint32_t length = be24(m + 1), offset = be24(m + 6), fragmentLength = be24(m + 9);
            const size_t have = std::min<size_t>(fragmentLength, plain.size() - pos - kHandshakeHeader);
            const bool whole = offset == 0 && fragmentLength == length && have == fragmentLength;
            std::string name = handshakeName(type, true);
            if (node) {
                Field &hs = node->add("Handshake Protocol: " + name);
                hs.add("Handshake Type: " + name + " (" + std::to_string(type) + ")");
                hs.add("Length: " + std::to_string(length));
                hs.add("Message Sequence: " + std::to_string(be16(m + 4)));
                hs.add("Fragment Offset: " + std::to_string(offset));
                hs.add("Fragment Length: " + std::to_string(fragmentLength));
                if (whole && type != 20) {
                    Joined j;
                    j.append(m + kHandshakeHeader, have, 0);
                    Hello scratch;
                    Field tmp;
                    decodeHandshakeBody(j, type, 0, have, true, scratch, &tmp, true);
                    zeroRanges(tmp);
                    for (auto &c: tmp.children) hs.children.push_back(std::move(c));
                }
            }
            names += (names.empty() ? "" : ", ") + name;
            pos += kHandshakeHeader + have;
            if (have < fragmentLength) break;
        }
        return names.empty() ? "Handshake" : names;
    }

    bool dissectDtlsImpl(Context &ctx, const char *data, size_t length, bool known) {
        Unified unified;
        Header first;
        const bool v13 = known && !readHeader(data, length, first) && readUnified(data, length, unified);
        if (!v13) {
            if (!readHeader(data, length, first)) return false;
            if (!known && !onlyRecords(data, length)) return false;
        }

        auto &pack = ctx.pack;
        const size_t o = ctx.offsetOf(data);
        pack.protocol = "DTLS";
        Field *layer = ctx.wantFields() ? &ctx.addLayer("Datagram Transport Layer Security", o, length) : nullptr;

        if (v13) {
            pack.app_flags = 0xfefc;
            pack.info = "DTLS 1.3 record (unified header, not decoded)";
            if (layer) {
                Field &r = layer->add("DTLS 1.3 Record Layer (unified header, not decoded)", o, length);
                r.add(std::string("Header byte: 001") + (unified.connectionId ? "1" : "0") + (unified.longSequence ? "1" : "0") + (unified.hasLength ? "1" : "0") +
                          std::to_string(unified.epochBits >> 1) + std::to_string(unified.epochBits & 1) + " (epoch bits " + std::to_string(unified.epochBits) + ")",
                      o, 1);
                r.add(std::string("Connection ID: ") + (unified.connectionId ? "present" : "absent"), o, 1);
                r.add(std::string("Sequence number: ") + (unified.longSequence ? "16 bit" : "8 bit"), o, 1);
                if (unified.hasLength && !unified.connectionId) r.add("Length: " + std::to_string(unified.length), o + unified.headerLength - 2, 2);
                r.add("[Expert Info (Note/Protocol): DTLS 1.3 records are recognised but not decoded; the content is encrypted]");
            }
            return true;
        }

        pack.app_code = first.type;
        pack.app_flags = first.version;
        pack.tcp_pdu_start = static_cast<uint32_t>(first.sequence);                                        // dtls.record.sequence_number
        pack.tcp_pdu_len = (static_cast<uint32_t>(first.epoch) << 16) | static_cast<uint32_t>(first.sequence >> 32);   // dtls.record.epoch

        const bool loadPass = ctx.mode != ParseMode::Replay && ctx.sessions && !ctx.sessions->isFrozen();
        std::string info;
        std::string serverName, subject;
        int cookieLength = -1;
        TlsRecordState overall = TlsRecordState::Clear;
        std::vector<uint32_t> otherCompletions;           // packets that completed messages this packet has fragments of
        std::vector<std::pair<uint8_t, std::vector<uint8_t>>> decryptedRecords;   // (content type, plaintext) for the "Decrypted DTLS" layer
        size_t pos = 0;
        int records = 0;

        while (length - pos >= kRecordHeader && records < 16) {
            Header h;
            if (!readHeader(data + pos, length - pos, h)) break;
            const size_t avail = std::min(h.length, length - pos - kRecordHeader);
            const bool partial = avail < h.length;
            const char *body = data + pos + kRecordHeader;
            const size_t bodyOffset = o + pos + kRecordHeader;

            Field *rec = nullptr;
            if (layer) {
                rec = &layer->add(versionName(h.version) + " Record Layer: " + contentTypeName(h.type), o + pos, kRecordHeader + avail);
                rec->add(std::string("Content Type: ") + contentTypeName(h.type) + " (" + std::to_string(h.type) + ")", o + pos, 1);
                rec->add("Version: " + versionName(h.version) + " (" + hexString(h.version, 4) + ")", o + pos + 1, 2);
                rec->add("Epoch: " + std::to_string(h.epoch), o + pos + 3, 2);
                rec->add("Sequence Number: " + std::to_string(h.sequence), o + pos + 5, 6);
                rec->add("Length: " + std::to_string(h.length), o + pos + 11, 2);
            }

            std::string part;
            if (h.type == kConnectionId) {
                part = "Connection ID record (not decoded)";
                if (rec) rec->add("[Connection ID records are not decoded]");
                records = 15;     // the header of such a record is not the 13 byte one: what follows cannot be walked
            } else if (h.epoch == 0 && h.type == kHandshake) {
                // the handshake fragments of the record
                size_t hp = 0;
                for (int messages = 0; avail - hp >= kHandshakeHeader && messages < 8; ++messages) {
                    const char *m = body + hp;
                    const uint8_t type = static_cast<uint8_t>(m[0]);
                    const uint32_t total = be24(m + 1), fragOffset = be24(m + 6), fragLength = be24(m + 9);
                    const uint16_t messageSeq = be16(m + 4);
                    const size_t position = pos + kRecordHeader + hp;
                    if (fragOffset > total || fragLength > total - fragOffset) {
                        part += (part.empty() ? "" : ", ") + std::string("Handshake [malformed fragment]");
                        if (rec) rec->add("[Expert Info (Warning/Malformed): the fragment lies outside its message (offset " + std::to_string(fragOffset) + ", length " +
                                          std::to_string(fragLength) + ", message length " + std::to_string(total) + ")]", bodyOffset + hp, kHandshakeHeader);
                        break;
                    }
                    const size_t have = std::min<size_t>(fragLength, avail - hp - kHandshakeHeader);
                    const bool cut = have < fragLength;
                    const bool whole = fragOffset == 0 && fragLength == total && !cut;
                    const char *fragmentData = m + kHandshakeHeader;

                    // what the tables know about this fragment
                    FragmentState state;
                    if (ctx.sessions && !cut) {
                        if (loadPass) {
                            DtlsFragment f;
                            f.packet = static_cast<uint32_t>(pack.number);
                            f.position = static_cast<uint16_t>(position);
                            f.epoch = h.epoch;
                            f.messageSeq = messageSeq;
                            f.type = type;
                            f.length = total;
                            f.offset = fragOffset;
                            f.data = fragmentData;
                            f.size = have;
                            f.time = pack.time;
                            std::vector<uint32_t> earlier;
                            ctx.sessions->addDtlsFragment(pack.source, pack.src_port, pack.destination, pack.dst_port, f, earlier);
                            if (ctx.completedDatagrams) {
                                // one earlier datagram may hold fragments of several messages this packet completes: tell it once
                                for (uint32_t e: earlier) {
                                    const std::pair<uint32_t, uint32_t> pair{e, static_cast<uint32_t>(pack.number)};
                                    auto &done = *ctx.completedDatagrams;
                                    if (std::find(done.begin(), done.end(), pair) == done.end()) done.push_back(pair);
                                }
                            }
                        }
                        state.ref = ctx.sessions->dtlsFragment(static_cast<uint32_t>(pack.number), static_cast<uint16_t>(position));
                        if (state.ref && (state.ref->flags & DtlsFragmentRef::kCompletesHere) && !(state.ref->flags & DtlsFragmentRef::kWhole))
                            state.message = ctx.sessions->dtlsMessage(state.ref->message);
                    }
                    const bool stateLost = ctx.sessions && !cut && !state.ref && ctx.sessions->isTableStateLost("dtls");
                    const bool reassembled = state.message != nullptr;
                    if (state.ref && state.ref->completedIn && !(state.ref->flags & DtlsFragmentRef::kCompletesHere)) {
                        if (std::find(otherCompletions.begin(), otherCompletions.end(), state.ref->completedIn) == otherCompletions.end())
                            otherCompletions.push_back(state.ref->completedIn);
                    }

                    // the message, when this packet holds all of it (in place) or completes it (reassembled)
                    Joined joined;
                    bool decodable = false;
                    if (whole) {
                        joined.append(fragmentData, have, bodyOffset + hp + kHandshakeHeader);
                        decodable = true;
                    } else if (reassembled) {
                        joined.append(state.message->body.data(), state.message->body.size(), 0);
                        decodable = true;
                    }

                    std::string name = handshakeName(type, true);
                    Hello msg;
                    Field *hs = nullptr;
                    if (rec) {
                        hs = &rec->add("Handshake Protocol: " + name, bodyOffset + hp, kHandshakeHeader + have);
                        hs->add("Handshake Type: " + name + " (" + std::to_string(type) + ")", bodyOffset + hp, 1);
                        hs->add("Length: " + std::to_string(total), bodyOffset + hp + 1, 3);
                        hs->add("Message Sequence: " + std::to_string(messageSeq), bodyOffset + hp + 4, 2);
                        hs->add("Fragment Offset: " + std::to_string(fragOffset), bodyOffset + hp + 6, 3);
                        hs->add("Fragment Length: " + std::to_string(fragLength), bodyOffset + hp + 9, 3);
                    }
                    std::string note;
                    if (decodable) {
                        Field tmp;
                        Field *target = reassembled ? &tmp : hs;
                        name = decodeHandshakeBody(joined, type, 0, joined.bytes.size(), true, msg, target, true);
                        if (msg.cipher != 0) name += " (" + cipherName(msg.cipher) + ")";
                        if (reassembled && hs) {
                            zeroRanges(tmp);
                            hs->add("[Reassembled DTLS handshake message (" + std::to_string(joined.bytes.size()) + " bytes) from frame(s) " +
                                    packetList(state.message->packets) + "]");
                            for (auto &c: tmp.children) hs->children.push_back(std::move(c));
                        }
                        if (reassembled) note = " [Reassembled from " + std::to_string(state.message->packets.size()) + " packet(s)]";
                    } else if (cut) {
                        note = " [fragment cut by the capture]";
                    } else {
                        note = " [fragment " + std::to_string(fragOffset) + "-" + std::to_string(fragOffset + fragLength - (fragLength ? 1 : 0)) + " of " + std::to_string(total) + "]";
                        if (hs) hs->add("[Handshake fragment: bytes " + std::to_string(fragOffset) + "-" + std::to_string(fragOffset + fragLength) + " of " + std::to_string(total) + "]");
                    }
                    if (state.ref) {
                        if (state.ref->completedIn && !(state.ref->flags & DtlsFragmentRef::kCompletesHere)) {
                            if (hs) hs->add("[Reassembled in #" + std::to_string(state.ref->completedIn) + "]");
                        }
                        if (state.ref->flags & DtlsFragmentRef::kRetransmission) {
                            note += " [Retransmission]";
                            if (hs) hs->add("[Retransmission of the message completed in #" + std::to_string(state.ref->retransmissionOf) + "]");
                        }
                        if (state.ref->flags & DtlsFragmentRef::kConflict) {
                            if (hs) hs->add("[Expert Info (Warning/Malformed): an overlapping fragment carried different bytes than an earlier copy; the first copy was kept]");
                        }
                        if (state.ref->flags & DtlsFragmentRef::kTotalConflict) {
                            note += " [message length differs from the first fragment]";
                            if (hs) hs->add("[Expert Info (Warning/Malformed): this fragment announces another message length than the first fragment; the message was discarded]");
                        }
                        if (state.ref->flags & DtlsFragmentRef::kRejected) {
                            if (hs) hs->add("[Expert Info (Warning/Malformed): unusable fragment (outside the message, or the message is too large)]");
                        }
                    } else if (stateLost) {
                        note += " [not reassembled: the DTLS session table lost state]";
                        if (hs) hs->add("[Expert Info (Warning/Decryption): the DTLS session table lost state; this fragment was not reassembled]");
                    }

                    if (msg.helloType != 0 && loadPass) {
                        DtlsHelloFacts facts;
                        facts.client = msg.helloType == 1;
                        facts.random = msg.random;
                        facts.version = msg.version;
                        facts.cipherSuite = msg.cipher;
                        ctx.sessions->addDtlsHello(pack.source, pack.src_port, pack.destination, pack.dst_port, facts);
                    }
                    if (serverName.empty()) serverName = msg.serverName;
                    if (subject.empty()) subject = msg.subject;
                    if (cookieLength < 0) cookieLength = msg.cookieLength;
                    if (pack.app_type == 0) pack.app_type = type;
                    part += (part.empty() ? "" : ", ") + name + note;
                    hp += kHandshakeHeader + have;
                    if (cut) break;
                }
                if (part.empty()) part = "Handshake";
            } else if (h.epoch == 0 && h.type == kChangeCipherSpec) {
                part = "Change Cipher Spec";
            } else if (h.epoch == 0 && h.type == kAlert && avail >= 2) {
                part = "Alert";
                const uint8_t level = static_cast<uint8_t>(body[0]), description = static_cast<uint8_t>(body[1]);
                if (rec) {
                    Field &a = rec->add("Alert Message: level " + std::to_string(level) + ", description " + std::to_string(description), bodyOffset, 2);
                    a.add(std::string("Level: ") + (level == 1 ? "Warning" : level == 2 ? "Fatal" : "Unknown") + " (" + std::to_string(level) + ")", bodyOffset, 1);
                    a.add(std::string("Description: ") + (alertName(description) ? alertName(description) : "Unknown") + " (" + std::to_string(description) + ")", bodyOffset + 1, 1);
                }
            } else if (h.epoch >= 1) {
                // protected: opened with the keys of the session in the load pass, read back from the tables in Replay
                const bool handshakeType = h.type == kHandshake, dataType = h.type == kApplicationData;
                part = handshakeType ? "Encrypted Handshake Message" : dataType ? "Application Data" : h.type == kAlert ? "Encrypted Alert" : contentTypeName(h.type);
                SessionTables::DtlsRecordResult result;
                bool have = false;
                if (!partial) {
                    DtlsRecordInput in;
                    in.type = h.type;
                    in.version = h.version;
                    in.epoch = h.epoch;
                    in.sequence = h.sequence;
                    in.fragment = std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(body), avail);
                    if (!ctx.sessions) {
                        result.state = TlsRecordState::NoKey;
                    } else if (loadPass) {
                        ctx.sessions->decryptDtlsRecord(static_cast<uint32_t>(pack.number), static_cast<uint16_t>(pos), pack.source, pack.src_port, pack.destination,
                                                        pack.dst_port, in, result);
                    } else {
                        ctx.sessions->readDtlsRecord(static_cast<uint32_t>(pack.number), static_cast<uint16_t>(pos), in, result);
                    }
                    have = true;
                }
                if (have) {
                    if (result.state != TlsRecordState::Clear) pack.reassembled_in = mergeTlsSummary(pack.reassembled_in, tlsSummaryOf(result.state));
                    if (overall == TlsRecordState::Clear || result.state == TlsRecordState::Decrypted) overall = result.state;
                    if (rec) {
                        rec->add("Explicit Nonce: 8 bytes", bodyOffset, std::min<size_t>(8, avail));
                        rec->add(std::string("Encrypted ") + contentTypeName(h.type) + " (" + std::to_string(avail) + " bytes)", bodyOffset, avail);
                        rec->add(std::string("[Decryption: ") + tlsStateText(result.state) + "]");
                        if (result.state == TlsRecordState::Decrypted) rec->add("[Plaintext: " + std::to_string(result.plaintext.size()) + " bytes]");
                    }
                    if (result.state == TlsRecordState::Decrypted) {
                        decryptedRecords.push_back({h.type, std::move(result.plaintext)});
                        const std::vector<uint8_t> &plain = decryptedRecords.back().second;
                        if (dataType) {
                            part = "Application Data (decrypted, " + std::to_string(plain.size()) + " bytes)";
                        } else if (handshakeType) {
                            part = decryptedHandshake(plain, nullptr) + " (decrypted)";
                        } else if (h.type == kAlert && plain.size() >= 2) {
                            part = std::string("Alert (") + (alertName(plain[1]) ? alertName(plain[1]) : "unknown") + ")";
                        } else {
                            part = std::string(contentTypeName(h.type)) + " (decrypted)";
                        }
                    }
                } else if (rec) {
                    rec->add(std::string("Encrypted ") + contentTypeName(h.type) + " (" + std::to_string(avail) + " bytes)", bodyOffset, avail);
                }
            } else {
                part = contentTypeName(h.type);
                if (rec && h.type == kApplicationData) rec->add("Application Data (" + std::to_string(avail) + " bytes)", bodyOffset, avail);
            }
            if (partial) part += " [fragment]";
            info += (info.empty() ? "" : ", ") + part;
            pos += kRecordHeader + h.length;
            ++records;
            if (partial) break;
        }

        // the facts of the first record and hello for the summary columns and the display filter
        if (!serverName.empty()) pack.app_text = serverName;
        if (!subject.empty()) pack.app_text2 = subject;
        if (cookieLength >= 0) pack.app_code = static_cast<uint16_t>(first.type | ((cookieLength + 1) << 5));

        // fragments of messages that were completed elsewhere say where
        std::sort(otherCompletions.begin(), otherCompletions.end());
        for (uint32_t n: otherCompletions) info += " [Reassembled in #" + std::to_string(n) + "]";
        pack.info = info.empty() ? "DTLS record" : info;

        // the facts of the connection: who the records belong to and whether key material is known
        if (layer && ctx.sessions) {
            unsigned direction = 0;
            const uint32_t id = ctx.sessions->findDtlsSession(pack.source, pack.src_port, pack.destination, pack.dst_port, &direction);
            if (const DtlsSession *s = ctx.sessions->dtlsSession(id)) {
                layer->add(std::string("[DTLS session: ") + roleText(*s, direction) + ", " + (s->version ? versionName(s->version) : "ServerHello not seen") + "]");
                tls::KeyEntry keys;
                const bool found = s->hasClientRandom && ctx.sessions->findTlsKeys(s->clientRandom, keys);
                layer->add(std::string("Key material: ") + tls::availabilityText(tls::classify(found ? &keys : nullptr, 0x0303)));
            }
        }
        if (layer && overall != TlsRecordState::Clear) {
            layer->add(std::string("Decryption status: ") + tlsStateText(overall));
            const bool good = overall == TlsRecordState::Decrypted;
            const bool warn = overall == TlsRecordState::TagFailure || overall == TlsRecordState::Malformed || overall == TlsRecordState::StateLost;
            layer->add(std::string("[Expert Info (") + (good ? "Chat" : warn ? "Warning" : "Note") + "/Decryption): " +
                       (good ? "DTLS records decrypted with the key log" : tlsStateText(overall)) + "]");
        }
        if (layer && !decryptedRecords.empty()) {
            size_t total = 0;
            for (const auto &r: decryptedRecords) total += r.second.size();
            Field &plain = ctx.addLayer("Decrypted DTLS (" + std::to_string(total) + " bytes)", 0, 0);
            for (const auto &r: decryptedRecords) {
                const std::string sizeText = std::to_string(r.second.size()) + " bytes";
                if (r.first == kHandshake) {
                    Field &n = plain.add("Decrypted Handshake Protocol (" + sizeText + ")");
                    decryptedHandshake(r.second, &n);
                } else if (r.first == kAlert) {
                    Field &n = plain.add("Decrypted Alert (" + sizeText + ")");
                    if (r.second.size() >= 2) {
                        const char *name = alertName(r.second[1]);
                        n.add(std::string("Level: ") + (r.second[0] == 1 ? "Warning" : r.second[0] == 2 ? "Fatal" : "Unknown") + " (" + std::to_string(r.second[0]) + ")");
                        n.add(std::string("Description: ") + (name ? name : "Unknown") + " (" + std::to_string(r.second[1]) + ")");
                    }
                } else {
                    plain.add(std::string("Decrypted ") + contentTypeName(r.first) + " (" + sizeText + ")");
                }
            }
        }
        return true;
    }
} // namespace

bool dissect::dissectDtlsHeuristic(Context &ctx, const char *data, size_t length) {
    return dissectDtlsImpl(ctx, data, length, false);
}

void dissect::dissectDtlsPort(Context &ctx, const char *data, size_t length) {
    dissectDtlsImpl(ctx, data, length, true);   // false leaves pack.protocol empty: udp.cpp then shows the datagram as raw UDP
}
