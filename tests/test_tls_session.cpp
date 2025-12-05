// TLS session mapping of the load pass: client / server random, negotiated version, cipher suite and the per-direction record
// indices that the decryptor needs, plus the "Key material" line of the detail tree.
//
// Oracles: the fixtures in tests/data/tls come from REAL handshakes (Python ssl, OpenSSL 3), and expected.json was derived
// by tools/make_tls_fixtures.py with a separate record parser and cross-checked against the key log OpenSSL wrote.
#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <random>
#include <regex>

#include <core.h>
#include <tls/keylog.h>

#include "tls_support.h"

using namespace tlstest;

namespace {
    const dissect::TlsSession *sessionOf(const Loaded &cap, unsigned *direction = nullptr) {
        return cap.fp.sessions().findTlsSession("10.0.0.1", 50000, "10.0.0.2", 443, direction);
    }

    std::string u8(unsigned v) { char b[8]; std::snprintf(b, sizeof b, "%02x", v); return b; }
    std::string u16(unsigned v) { char b[8]; std::snprintf(b, sizeof b, "%04x", v); return b; }
    std::string u24(unsigned v) { char b[8]; std::snprintf(b, sizeof b, "%06x", v); return b; }
    std::string record(unsigned type, const std::string &body, unsigned version = 0x0303) {
        return u8(type) + u16(version) + u16(static_cast<unsigned>(body.size() / 2)) + body;
    }
    std::string handshake(unsigned type, const std::string &body) { return u8(type) + u24(static_cast<unsigned>(body.size() / 2)) + body; }

    std::string clientHelloRecord(const std::string &random) {
        const std::string ext = u16(43) + u16(5) + "04" + "0304" + "0303";
        const std::string body = "0303" + random + "00" + u16(4) + "1301c02f" + "0100" + u16(static_cast<unsigned>(ext.size() / 2)) + ext;
        return record(22, handshake(1, body), 0x0301);
    }

    // `version13`: carries supported_versions = TLS 1.3 like a real TLS 1.3 ServerHello
    std::string serverHelloRecord(const std::string &random, unsigned cipher, bool version13) {
        const std::string ext = version13 ? u16(43) + u16(2) + "0304" : "";
        const std::string body = "0303" + random + "00" + u16(cipher) + "00" + u16(static_cast<unsigned>(ext.size() / 2)) + ext;
        return record(22, handshake(2, body));
    }

    const std::string kHrrRandom = "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c";
    std::string rnd(char c) { return std::string(64, c); }

    std::string seqHex(uint32_t v) { char b[16]; std::snprintf(b, sizeof b, "%08x", v); return b; }

    // A TCP conversation client 10.0.0.1:50000 <-> server 10.0.0.2:443; frames are collected in order.
    struct Flow {
        std::vector<std::vector<char>> frames;
        uint32_t c = 1000, s = 5000;   // next sequence numbers

        Flow &syn() {
            frames.push_back(support::tcpPacket("0a000001", "0a000002", "c350", "01bb", seqHex(c - 1), "00000000", "02"));
            return *this;
        }
        Flow &synAck() {
            frames.push_back(support::tcpPacket("0a000002", "0a000001", "01bb", "c350", seqHex(s - 1), seqHex(c), "12"));
            return *this;
        }
        // returns the relative sequence number of the first byte
        uint32_t toServer(const std::string &bytes, bool advance = true) {
            frames.push_back(support::tcpPacket("0a000001", "0a000002", "c350", "01bb", seqHex(c), seqHex(s), "18", bytes));
            const uint32_t at = c - 999;
            if (advance) c += static_cast<uint32_t>(bytes.size());
            return at;
        }
        uint32_t toClient(const std::string &bytes) {
            frames.push_back(support::tcpPacket("0a000002", "0a000001", "01bb", "c350", seqHex(s), seqHex(c), "18", bytes));
            const uint32_t at = s - 4999;
            s += static_cast<uint32_t>(bytes.size());
            return at;
        }
        // at an explicit raw sequence number (does not move the counters)
        void toServerAt(uint32_t seq, const std::string &bytes) {
            frames.push_back(support::tcpPacket("0a000001", "0a000002", "c350", "01bb", seqHex(seq), seqHex(s), "18", bytes));
        }
    };

    struct FlowCapture : Loaded {
        explicit FlowCapture(const Flow &flow) : Loaded(support::pcapBytes(flow.frames), "tlsflow.pcap", false) {}
    };

    std::string textOfRecordIndex(const packet::PacketInfo &d) {
        const auto *n = find(d.fields, "[TLS record index:");
        return n ? n->text : "";
    }
} // namespace

// ---- session mapping on real handshakes -------------------------------------------------------------------

namespace {
    void checkRealHandshake(const char *name) {
        SCOPED_TRACE(name);
        const auto want = expected(name);
        Loaded cap(kDir + name + ".pcapng");
        ASSERT_TRUE(cap.ok) << cap.message;
        ASSERT_EQ(cap.packets.size(), static_cast<size_t>(want.num("packets")));
        EXPECT_FALSE(cap.fp.sessions().hasStateLost());
        EXPECT_TRUE(cap.fp.sessions().isFrozen());

        unsigned direction = 9;
        const dissect::TlsSession *s = sessionOf(cap, &direction);
        ASSERT_NE(s, nullptr);
        EXPECT_EQ(direction, 0u) << "10.0.0.1/50000 sorts before 10.0.0.2/443";
        EXPECT_EQ(cap.fp.sessions().tlsTable().sessionCount(), 1u);
        ASSERT_TRUE(s->hasClientRandom);
        ASSERT_TRUE(s->hasServerRandom);
        EXPECT_EQ(hexOfRandom(s->clientRandom), want.str("client_random"));
        EXPECT_EQ(hexOfRandom(s->serverRandom), want.str("server_random"));
        EXPECT_EQ(s->version, static_cast<uint16_t>(want.num("negotiated_version")));
        EXPECT_EQ(s->cipherSuite, static_cast<uint16_t>(want.num("cipher_suite")));
        EXPECT_FALSE(s->helloRetryRequest);
        ASSERT_NE(s->client(), nullptr);
        ASSERT_NE(s->server(), nullptr);
        EXPECT_EQ(s->roleOf(0), dissect::TlsRole::Client);
        EXPECT_EQ(s->roleOf(1), dissect::TlsRole::Server);

        EXPECT_EQ(s->client()->records, static_cast<uint32_t>(want.at("records").num("c2s")));
        EXPECT_EQ(s->server()->records, static_cast<uint32_t>(want.at("records").num("s2c")));
        EXPECT_FALSE(s->client()->gap);
        EXPECT_FALSE(s->server()->gap);
        EXPECT_EQ(s->client()->helloRecord, static_cast<uint32_t>(want.at("hello_record").num("c2s")));
        EXPECT_EQ(s->server()->helloRecord, static_cast<uint32_t>(want.at("hello_record").num("s2c")));
        for (const char *dir: {"c2s", "s2c"}) {
            const auto &d = *(std::string(dir) == "c2s" ? s->client() : s->server());
            std::vector<uint32_t> ccs;
            for (const auto &n: want.at("change_cipher_spec").at(dir).items) ccs.push_back(static_cast<uint32_t>(n.number));
            EXPECT_EQ(d.changeCipherSpecs, ccs) << dir;
        }

        // keys: from the Decryption Secrets Block of the file
        tls::KeyEntry keys;
        ASSERT_TRUE(cap.fp.sessions().findTlsKeys(s->clientRandom, keys));
        EXPECT_EQ(tls::classify(&keys, s->version), want.num("negotiated_version") == 0x0304 ? tls::KeyAvailability::Tls13TrafficSecrets
                                                                                             : tls::KeyAvailability::Tls12MasterSecret);
        EXPECT_EQ(cap.fp.captureInfo().tlsKeyLogSecrets, want.at("key_labels").items.size());
    }
}

TEST(TlsSession, RealTls12HandshakeMatchesTheIndependentParse) { checkRealHandshake("tls12"); }
TEST(TlsSession, RealTls13HandshakeMatchesTheIndependentParse) { checkRealHandshake("tls13"); }

namespace {
    // Every TLS layer of every packet: record index lines (replay) and key material lines
    struct ReplayView {
        std::vector<std::string> keyMaterial;
        std::vector<std::vector<std::string>> indexLines;     // per packet
        size_t tlsPackets = 0;
    };

    ReplayView replayAll(Loaded &cap) {
        ReplayView v;
        for (size_t i = 0; i < cap.packets.size(); ++i) {
            const auto d = cap.details(i);
            expectInside(d.fields, d.raw_data.size());
            std::vector<std::string> idx, keys;
            collect(d.fields, "[TLS record index:", idx);
            collect(d.fields, "Key material:", keys);
            if (!keys.empty()) ++v.tlsPackets;
            for (auto &k: keys) v.keyMaterial.push_back(k);
            v.indexLines.push_back(idx);
        }
        return v;
    }

    // "[TLS record index: 3-5 (server to client)]" -> {first, last, direction text}
    struct IndexLine { uint32_t first, last; std::string role; };
    IndexLine parseIndex(const std::string &line) {
        static const std::regex re(R"(\[TLS record index: (\d+)(?:-(\d+))? \(([a-z ]+)\)\])");
        std::smatch m;
        EXPECT_TRUE(std::regex_match(line, m, re)) << line;
        IndexLine out{};
        if (m.size() == 4) {
            out.first = static_cast<uint32_t>(std::stoul(m[1]));
            out.last = m[2].matched ? static_cast<uint32_t>(std::stoul(m[2])) : out.first;
            out.role = m[3];
        }
        return out;
    }

    void checkReplay(const char *name) {
        SCOPED_TRACE(name);
        const auto want = expected(name);
        Loaded cap(kDir + name + ".pcapng");
        ASSERT_TRUE(cap.ok) << cap.message;
        const auto &sessions = cap.fp.sessions();
        const size_t memory = sessions.totalMemoryUsage(), messages = sessions.tlsTable().messageCount();
        const dissect::TlsSession *s = sessionOf(cap);
        ASSERT_NE(s, nullptr);
        const dissect::TlsDirection before0 = s->directions[0], before1 = s->directions[1];

        // the detail of a packet equals what the load pass stored for the message it completes
        size_t reassembled = 0, whole = 0;
        for (size_t i = 0; i < cap.packets.size(); ++i) {
            const auto &p = cap.packets[i];
            if (p.tcp_pdu_state != 2 && p.tcp_pdu_state != 3) continue;
            (p.tcp_pdu_state == 2 ? reassembled : whole)++;
            const dissect::TlsMessageRef *ref = sessions.findTlsMessage(static_cast<uint32_t>(p.number), p.tcp_pdu_start);
            ASSERT_NE(ref, nullptr) << "packet " << p.number;
            const auto d = cap.details(i);
            const auto lines = std::vector<std::string>{textOfRecordIndex(d)};
            const auto got = parseIndex(lines[0]);
            EXPECT_EQ(got.first, ref->firstRecord) << p.number;
            EXPECT_EQ(got.last, ref->firstRecord + ref->records - 1) << p.number;
            EXPECT_EQ(got.role, sessions.tlsSession(ref->session)->roleOf(ref->direction) == dissect::TlsRole::Client ? "client to server" : "server to client");
        }

        EXPECT_GT(reassembled, 0u) << "the fixture is cut into small segments, so messages are reassembled";
        EXPECT_GT(whole, 0u);
        const ReplayView view = replayAll(cap);
        // all indices of a direction, in packet order, are consecutive and cover every record exactly once
        uint32_t next[2] = {0, 0};
        for (const auto &lines: view.indexLines) {
            for (const auto &line: lines) {
                const IndexLine ix = parseIndex(line);
                const int dir = ix.role == "client to server" ? 0 : 1;
                EXPECT_EQ(ix.first, next[dir]) << line;
                next[dir] = ix.last + 1;
            }
        }
        EXPECT_EQ(next[0], static_cast<uint32_t>(want.at("records").num("c2s")));
        EXPECT_EQ(next[1], static_cast<uint32_t>(want.at("records").num("s2c")));

        // the key material state shown for every TLS layer comes from the Decryption Secrets Block
        ASSERT_FALSE(view.keyMaterial.empty());
        const std::string text = want.num("negotiated_version") == 0x0304 ? "available (TLS 1.3 traffic secrets)" : "available (TLS 1.2 master secret)";
        for (const auto &k: view.keyMaterial) EXPECT_EQ(k, "Key material: " + text);

        // Replay only reads
        EXPECT_EQ(sessions.totalMemoryUsage(), memory);
        EXPECT_EQ(sessions.tlsTable().messageCount(), messages);
        EXPECT_EQ(s->directions[0].records, before0.records);
        EXPECT_EQ(s->directions[1].records, before1.records);
        EXPECT_EQ(s->directions[0].changeCipherSpecs, before0.changeCipherSpecs);
        EXPECT_FALSE(sessions.hasStateLost());
    }
}

TEST(TlsSession, ReplayOfEveryPacketMatchesTheLoadPassTls12) { checkReplay("tls12"); }
TEST(TlsSession, ReplayOfEveryPacketMatchesTheLoadPassTls13) { checkReplay("tls13"); }

TEST(TlsSession, KeyMaterialFollowsTheKeyStore) {
    Loaded cap(kDir + "tls13.pcapng");
    ASSERT_TRUE(cap.ok);
    auto line = [&](size_t i) { const auto d = cap.details(i); const auto *n = find(d.fields, "Key material:"); return n ? n->text : std::string(); };
    size_t tlsPacket = 0;
    for (size_t i = 0; i < cap.packets.size(); ++i) if (cap.packets[i].protocol == "TLS") { tlsPacket = i; break; }
    ASSERT_NE(line(tlsPacket), "");
    EXPECT_EQ(line(tlsPacket), "Key material: available (TLS 1.3 traffic secrets)");

    cap.fp.sessions().tlsCaptureKeys().clear();   // keys removed again: nothing known
    EXPECT_EQ(line(tlsPacket), "Key material: not found");

    // a key log the user supplies afterwards is picked up by the next detail build
    tls::KeyLogStats stats;
    std::string error;
    ASSERT_TRUE(cap.fp.sessions().tlsExternalKeys().loadFile(kDir + "tls13.keys", stats, error)) << error;
    EXPECT_EQ(line(tlsPacket), "Key material: available (TLS 1.3 traffic secrets)");

    // only an exporter secret is no help
    cap.fp.sessions().tlsExternalKeys().clear();
    const auto want = expected("tls13");
    cap.fp.sessions().tlsExternalKeys().parseText("EXPORTER_SECRET " + want.str("client_random") + " " + std::string(64, 'e') + "\n");
    EXPECT_EQ(line(tlsPacket), "Key material: not found");
}

// ---- session mapping on synthetic handshakes -------------------------------------------------------------

TEST(TlsSession, HelloRetryRequestKeepsTheRealServerRandomAndTheClientRandom) {
    Flow f;
    f.syn();
    f.toServer(raw(clientHelloRecord(rnd('a'))));
    f.toClient(raw(serverHelloRecord(kHrrRandom, 0x1301, true)));
    f.toServer(raw(record(20, "01")));
    f.toServer(raw(clientHelloRecord(rnd('a'))));          // the second ClientHello keeps its random
    f.toClient(raw(serverHelloRecord(rnd('b'), 0x1302, true)));
    f.toClient(raw(record(20, "01")));
    f.toClient(raw(record(23, std::string(80, 'c'))));
    FlowCapture cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    const auto *s = sessionOf(cap);
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(cap.fp.sessions().tlsTable().sessionCount(), 1u);
    EXPECT_TRUE(s->helloRetryRequest);
    EXPECT_EQ(hexOfRandom(s->clientRandom), rnd('a'));
    EXPECT_EQ(hexOfRandom(s->serverRandom), rnd('b')) << "the HelloRetryRequest's fixed random is not the server random";
    EXPECT_EQ(s->version, 0x0304);
    EXPECT_EQ(s->cipherSuite, 0x1302) << "the suite of the ServerHello proper";
    EXPECT_EQ(s->client()->records, 3u);
    EXPECT_EQ(s->server()->records, 4u);
    EXPECT_EQ(s->server()->helloRecord, 1u) << "the handshake keys start after the real ServerHello, not the HelloRetryRequest";
    EXPECT_EQ(s->client()->helloRecord, 0u);
    EXPECT_EQ(s->client()->changeCipherSpecs, std::vector<uint32_t>{1});
    EXPECT_EQ(s->server()->changeCipherSpecs, std::vector<uint32_t>{2});
}

TEST(TlsSession, Tls12UsesTheLegacyVersionAndIgnoresEncryptedLookalikes) {
    Flow f;
    f.syn();
    f.toServer(raw(clientHelloRecord(rnd('1'))));
    f.toClient(raw(serverHelloRecord(rnd('2'), 0xc02f, false) + record(22, handshake(14, ""))));   // ServerHello + ServerHelloDone, one segment
    f.toServer(raw(record(22, handshake(16, "00")) + record(20, "01")));                           // ClientKeyExchange + CCS
    // a TLS 1.2 Finished is encrypted but its record type is 22: these bytes happen to form a hello
    f.toServer(raw(record(22, handshake(1, "0303" + rnd('f') + "00" + u16(2) + "c02f" + "0100"))));
    f.toClient(raw(record(20, "01")));
    FlowCapture cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    const auto *s = sessionOf(cap);
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(s->version, 0x0303);
    EXPECT_EQ(s->cipherSuite, 0xc02f);
    EXPECT_FALSE(s->helloRetryRequest);
    EXPECT_EQ(hexOfRandom(s->clientRandom), rnd('1')) << "a handshake record behind the ChangeCipherSpec is encrypted data";
    EXPECT_EQ(hexOfRandom(s->serverRandom), rnd('2'));
    EXPECT_EQ(s->client()->records, 4u);
    EXPECT_EQ(s->server()->records, 3u);
    EXPECT_EQ(s->client()->changeCipherSpecs, std::vector<uint32_t>{2});
    EXPECT_EQ(cap.packets[1].protocol, "TLS");
}

TEST(TlsSession, EncryptedLookalikeBeforeAnyChangeCipherSpecNeedsAPlausibleHello) {
    Flow f;
    f.syn();
    // handshake record whose body starts with 0x01 and a length that does not fit: not a hello
    f.toServer(raw(record(22, "01ffffff" + std::string(140, '0'))));
    FlowCapture cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    const auto *s = sessionOf(cap);
    ASSERT_NE(s, nullptr);
    EXPECT_FALSE(s->hasClientRandom);
    EXPECT_EQ(s->clientDirection, -1);
}

TEST(TlsSession, MessageSplitOverSegmentsAndRecordsFollowingInTheSameSegment) {
    const std::string hello = clientHelloRecord(rnd('3'));
    const std::string rec1 = record(23, std::string(60, 'a')), rec2 = record(23, std::string(40, 'b'));
    Flow f;
    f.syn();
    const std::string bytes = raw(hello + rec1 + rec2);   // the hello is 63 bytes
    f.toServer(bytes.substr(0, 20));                       // the hello starts ...
    f.toServer(bytes.substr(20, 25));                      // ... continues ...
    f.toServer(bytes.substr(45));                          // ... ends, and rec1 and rec2 follow in the same segment
    FlowCapture cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    EXPECT_EQ(cap.packets[3].tcp_pdu_state, 2) << cap.packets[3].info;
    const auto *s = sessionOf(cap);
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(hexOfRandom(s->clientRandom), rnd('3'));
    EXPECT_EQ(s->client()->records, 3u) << "the hello and both records that follow it in the completing segment";
    const auto d = cap.details(3);
    std::vector<std::string> lines;
    collect(d.fields, "[TLS record index:", lines);
    ASSERT_EQ(lines.size(), 3u) << "one layer per message: the reassembled hello and the two that follow";
    EXPECT_EQ(lines[0], "[TLS record index: 0 (client to server)]");
    EXPECT_EQ(lines[1], "[TLS record index: 1 (client to server)]");
    EXPECT_EQ(lines[2], "[TLS record index: 2 (client to server)]");
    // the first segment of the message shows no index (it is only a part), but still says whether keys exist
    const auto first = cap.details(1);
    EXPECT_EQ(find(first.fields, "[TLS record index:"), nullptr);
    EXPECT_NE(find(first.fields, "Key material: not found"), nullptr);
}

TEST(TlsSession, MessagesCompletedOutOfOrderAreCountedInStreamOrder) {
    const std::string hello = raw(clientHelloRecord(rnd('9')));    // record 0 (63 bytes)
    const std::string a = raw(record(23, std::string(60, 'a')));   // record 1: 5 + 30 bytes
    const std::string b = raw(record(23, std::string(40, 'b')));   // record 2
    const std::string c = raw(record(23, std::string(20, 'c')));   // record 3
    Flow f;
    f.syn();
    f.toServer(hello);
    const uint32_t rawA = f.c;                                  // raw sequence number where A starts
    f.toServer(a.substr(0, 12));                                // first part of A
    const uint32_t rawB = rawA + static_cast<uint32_t>(a.size());
    f.toServerAt(rawB, b);                                      // B arrives before the rest of A: waits for the hole
    f.toServerAt(rawA + 12, a.substr(12));                      // the rest of A: completes A, then B behind it
    f.c = rawB + static_cast<uint32_t>(b.size());
    f.toServer(c);                                              // C afterwards
    FlowCapture cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    const auto *s = sessionOf(cap);
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(s->client()->records, 4u);
    EXPECT_FALSE(s->client()->gap);
    // C is record 3 in the direction, although B was never shown by any packet's details
    const auto &pc = cap.packets.back();
    const auto *ref = cap.fp.sessions().findTlsMessage(static_cast<uint32_t>(pc.number), pc.tcp_pdu_start);
    ASSERT_NE(ref, nullptr);
    EXPECT_EQ(ref->firstRecord, 3u);
    EXPECT_EQ(textOfRecordIndex(cap.details(cap.packets.size() - 1)), "[TLS record index: 3 (client to server)]");
    // the completing packet is where A and B were registered: A as its own message, B as an extra
    const auto &completing = cap.packets[cap.packets.size() - 2];
    EXPECT_EQ(completing.tcp_pdu_state, 2);
    const auto *refA = cap.fp.sessions().findTlsMessage(static_cast<uint32_t>(completing.number), completing.tcp_pdu_start);
    ASSERT_NE(refA, nullptr);
    EXPECT_EQ(refA->firstRecord, 1u);
    const auto *refB = cap.fp.sessions().findTlsMessage(static_cast<uint32_t>(completing.number), completing.tcp_pdu_start + static_cast<uint32_t>(a.size()));
    ASSERT_NE(refB, nullptr) << "a message that only this segment completed is registered although no detail shows it";
    EXPECT_EQ(refB->firstRecord, 2u);
}

TEST(TlsSession, ASecondConnectionOnTheSameEndpointsGetsItsOwnSession) {
    Flow f;
    f.syn();
    f.toServer(raw(clientHelloRecord(rnd('4'))));
    f.toClient(raw(serverHelloRecord(rnd('5'), 0xc02f, false)));
    f.toServer(raw(record(23, std::string(20, 'a'))));
    f.c = 1000; f.s = 5000;                                      // same ports again: a new connection with a new hello
    f.syn().synAck();
    f.toServer(raw(clientHelloRecord(rnd('6'))));
    f.toClient(raw(serverHelloRecord(rnd('7'), 0xc030, false)));
    FlowCapture cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    const auto &tables = cap.fp.sessions();
    EXPECT_EQ(tables.tlsTable().sessionCount(), 2u);
    const auto *latest = sessionOf(cap);
    ASSERT_NE(latest, nullptr);
    EXPECT_EQ(hexOfRandom(latest->clientRandom), rnd('6'));
    EXPECT_EQ(latest->cipherSuite, 0xc030);
    const auto *older = tables.tlsSession(0);
    ASSERT_NE(older, nullptr);
    EXPECT_EQ(hexOfRandom(older->clientRandom), rnd('4'));
    EXPECT_EQ(older->client()->records, 2u);
    EXPECT_EQ(latest->client()->records, 1u);
    // the packets of the first connection still map to the first session
    const auto &p = cap.packets[1];
    const auto *ref = tables.findTlsMessage(static_cast<uint32_t>(p.number), p.tcp_pdu_start);
    ASSERT_NE(ref, nullptr);
    EXPECT_EQ(ref->session, 0u);
    EXPECT_EQ(textOfRecordIndex(cap.details(1)), "[TLS record index: 0 (client to server)]");
    const auto &q = cap.packets[cap.packets.size() - 2];
    EXPECT_EQ(tables.findTlsMessage(static_cast<uint32_t>(q.number), q.tcp_pdu_start)->session, 1u);
}

TEST(TlsSession, ASecondConnectionAfterOneThatChangedKeysIsStillRecognised) {
    Flow f;
    f.syn().synAck();
    f.toServer(raw(clientHelloRecord(rnd('1'))));
    f.toClient(raw(serverHelloRecord(rnd('2'), 0xc02f, false)));
    f.toServer(raw(record(22, handshake(16, "00")) + record(20, "01")));       // ClientKeyExchange + ChangeCipherSpec
    f.toClient(raw(record(20, "01")));
    f.toServer(raw(record(23, std::string(20, 'a'))));
    f.c = 1000; f.s = 5000;                                                  // the same ports again
    f.syn().synAck();
    const std::string hello = raw(clientHelloRecord(rnd('3')));
    f.toServer(hello.substr(0, 20));                                         // a hello split over segments
    f.toServer(hello.substr(20, 20));
    f.toServer(hello.substr(40));
    f.toClient(raw(serverHelloRecord(rnd('4'), 0xc030, false)));
    FlowCapture cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    const auto &tables = cap.fp.sessions();
    ASSERT_EQ(tables.tlsTable().sessionCount(), 2u) << "the second hello must not be taken for encrypted data of the first connection";
    EXPECT_FALSE(tables.hasStateLost());
    const auto *first = tables.tlsSession(0), *second = tables.tlsSession(1);
    ASSERT_NE(first, nullptr);
    ASSERT_NE(second, nullptr);
    EXPECT_EQ(hexOfRandom(first->clientRandom), rnd('1'));
    EXPECT_EQ(first->client()->records, 4u);
    EXPECT_EQ(first->client()->changeCipherSpecs, std::vector<uint32_t>{2});
    EXPECT_EQ(hexOfRandom(second->clientRandom), rnd('3'));
    EXPECT_EQ(hexOfRandom(second->serverRandom), rnd('4'));
    EXPECT_EQ(second->cipherSuite, 0xc030);
    EXPECT_EQ(second->client()->records, 1u) << "the records of the new connection are not appended to the old one";
    EXPECT_TRUE(second->client()->changeCipherSpecs.empty());

    // replay: the completed hello knows its session; a lone segment of it cannot tell the connections apart
    size_t completing = 0;
    for (size_t i = 0; i < cap.packets.size(); ++i) if (cap.packets[i].tcp_pdu_state == 2 && cap.packets[i].info.find("Client Hello") != std::string::npos) completing = i;
    ASSERT_NE(completing, 0u);
    EXPECT_EQ(textOfRecordIndex(cap.details(completing)), "[TLS record index: 0 (client to server)]");
    EXPECT_NE(find(cap.details(completing).fields, "Key material: not found"), nullptr);
    const auto part = cap.details(completing - 2);                            // the first segment of the split hello
    EXPECT_EQ(find(part.fields, "Key material:"), nullptr) << "two connections used these endpoints: nothing is claimed for a lone segment";
    EXPECT_EQ(find(part.fields, "[TLS record index:"), nullptr);
}

TEST(TlsSession, ARetransmittedSynAckAfterTheHelloDoesNotSplitTheConnection) {
    Flow f;
    f.syn().synAck();
    f.toServer(raw(clientHelloRecord(rnd('1'))));
    f.synAck();                                                              // the SYN-ACK is retransmitted late
    f.toClient(raw(serverHelloRecord(rnd('2'), 0xc02f, false)));
    f.toServer(raw(record(23, std::string(20, 'a'))));
    f.toClient(raw(record(23, std::string(20, 'b'))));
    f.toClient(raw(record(23, std::string(20, 'c'))));
    FlowCapture cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    const auto &tables = cap.fp.sessions();
    ASSERT_EQ(tables.tlsTable().sessionCount(), 1u) << "one connection, however many SYN-ACKs were captured";
    const auto *s = sessionOf(cap);
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(hexOfRandom(s->clientRandom), rnd('1'));
    EXPECT_EQ(hexOfRandom(s->serverRandom), rnd('2'));
    EXPECT_EQ(s->client()->records, 2u);
    EXPECT_EQ(s->server()->records, 3u);
}

TEST(TlsSession, ManyNonTlsConnectionsLeaveTheTlsTableAlone) {
    Flow f;
    f.syn().synAck();
    f.toServer(raw(clientHelloRecord(rnd('1'))));
    for (int i = 0; i < 300; ++i) {                                          // web traffic on other ports
        char port[8];
        std::snprintf(port, sizeof port, "%04x", 2000 + i);
        f.frames.push_back(support::tcpPacket("0a000001", "0a000003", port, "0050", seqHex(77), "00000000", "02"));
    }
    FlowCapture cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    Flow g;
    g.syn().synAck();
    g.toServer(raw(clientHelloRecord(rnd('1'))));
    FlowCapture plain(g);
    EXPECT_EQ(cap.fp.sessions().tlsTable().memory(), plain.fp.sessions().tlsTable().memory()) << "SYNs of other flows are not remembered";
    EXPECT_EQ(cap.fp.sessions().tlsTable().sessionCount(), 1u);
    EXPECT_FALSE(cap.fp.sessions().hasStateLost());
}

TEST(TlsSession, ServerSideOnlyCaptureStillNamesTheClientDirection) {
    Flow f;
    f.syn();
    f.toClient(raw(serverHelloRecord(rnd('8'), 0x1301, true) + record(20, "01") + record(23, std::string(30, 'e'))));
    FlowCapture cap(f);
    ASSERT_TRUE(cap.ok) << cap.message;
    const auto *s = sessionOf(cap);
    ASSERT_NE(s, nullptr);
    EXPECT_FALSE(s->hasClientRandom);
    EXPECT_EQ(s->roleOf(1), dissect::TlsRole::Server);
    EXPECT_EQ(s->roleOf(0), dissect::TlsRole::Client);
    EXPECT_EQ(s->server()->records, 3u);
    EXPECT_EQ(s->server()->helloRecord, 0u);
    EXPECT_EQ(s->version, 0x0304);
    EXPECT_NE(find(cap.details(1).fields, "Key material: not found"), nullptr) << "without a ClientHello there is no random to look up";
}

// ---- the table itself --------------------------------------------------------------------------------------

namespace {
    dissect::TlsMessageFacts facts(uint32_t packet, uint32_t seq, uint32_t length, uint32_t records) {
        dissect::TlsMessageFacts f;
        f.packet = packet;
        f.startSeq = seq;
        f.length = length;
        f.records = records;
        return f;
    }
}

TEST(TlsSessionTable, GapDuplicatesAndFreeze) {
    core::SessionTables t;
    EXPECT_TRUE(t.addTlsMessage("1.1.1.1", 1, "2.2.2.2", 2, facts(5, 1, 100, 2)));
    EXPECT_TRUE(t.addTlsMessage("1.1.1.1", 1, "2.2.2.2", 2, facts(5, 1, 100, 2))) << "the same message twice";
    EXPECT_TRUE(t.addTlsMessage("1.1.1.1", 1, "2.2.2.2", 2, facts(9, 50, 20, 1))) << "bytes already registered under another packet";
    unsigned dir = 7;
    const auto *s = t.findTlsSession("2.2.2.2", 2, "1.1.1.1", 1, &dir);
    ASSERT_NE(s, nullptr);
    EXPECT_EQ(dir, 1u) << "the reverse direction of the same connection";
    EXPECT_EQ(s->directions[0].records, 2u);
    EXPECT_FALSE(s->directions[0].gap);

    EXPECT_TRUE(t.addTlsMessage("1.1.1.1", 1, "2.2.2.2", 2, facts(12, 400, 30, 1)));   // 101..399 never completed
    s = t.findTlsSession("1.1.1.1", 1, "2.2.2.2", 2, &dir);
    EXPECT_EQ(dir, 0u);
    EXPECT_TRUE(s->directions[0].gap);
    EXPECT_EQ(s->directions[0].records, 3u);
    EXPECT_FALSE(s->directions[1].gap) << "the other direction is unaffected";
    EXPECT_EQ(t.findTlsMessage(12, 400)->firstRecord, 2u);
    EXPECT_EQ(t.findTlsMessage(99, 1), nullptr);

    t.freeze();
    EXPECT_FALSE(t.addTlsMessage("1.1.1.1", 1, "2.2.2.2", 2, facts(13, 430, 30, 1)));
    EXPECT_EQ(t.findTlsSession("1.1.1.1", 1, "2.2.2.2", 2)->directions[0].records, 3u);
    EXPECT_FALSE(t.hasStateLost()) << "frozen is not a memory problem";
    t.clear();
    EXPECT_EQ(t.tlsTable().sessionCount(), 0u);
    EXPECT_EQ(t.findTlsSession("1.1.1.1", 1, "2.2.2.2", 2), nullptr);
    EXPECT_EQ(t.totalMemoryUsage(), 0u);
}

TEST(TlsSessionTable, EncryptedRuleOnlyAppliesToTheSameStream) {
    core::SessionTables t;
    auto ccs = facts(5, 1, 100, 2);
    ccs.changeCipherSpecs = {1};
    ASSERT_TRUE(t.addTlsMessage("1.1.1.1", 1, "2.2.2.2", 2, ccs));       // direction 0 sent a ChangeCipherSpec, next byte is 101
    EXPECT_FALSE(t.tlsDirectionEncrypted("2.2.2.2", 2, "1.1.1.1", 1, 101)) << "the other direction has not changed keys";
    EXPECT_TRUE(t.tlsDirectionEncrypted("1.1.1.1", 1, "2.2.2.2", 2, 101)) << "the stream goes on: records are encrypted";
    EXPECT_TRUE(t.tlsDirectionEncrypted("1.1.1.1", 1, "2.2.2.2", 2, 900));
    EXPECT_FALSE(t.tlsDirectionEncrypted("1.1.1.1", 1, "2.2.2.2", 2, 1)) << "a restarted sequence space is a new connection";
    EXPECT_FALSE(t.tlsDirectionEncrypted("3.3.3.3", 1, "2.2.2.2", 2, 101)) << "unknown endpoints";

    const size_t memoryBefore = t.totalMemoryUsage();
    EXPECT_TRUE(t.markTlsRestart("5.5.5.5", 7, "6.6.6.6", 8, 1)) << "a SYN of endpoints without a session needs no marker";
    EXPECT_EQ(t.totalMemoryUsage(), memoryBefore);

    EXPECT_TRUE(t.markTlsRestart("1.1.1.1", 1, "2.2.2.2", 2, 1));          // a SYN from the client side; its data would start at 1
    EXPECT_GT(t.totalMemoryUsage(), memoryBefore);
    EXPECT_FALSE(t.tlsDirectionEncrypted("1.1.1.1", 1, "2.2.2.2", 2, 1)) << "after a SYN the next hello is plain";
    EXPECT_TRUE(t.addTlsMessage("1.1.1.1", 1, "2.2.2.2", 2, facts(8, 1, 50, 1)));
    EXPECT_EQ(t.totalMemoryUsage(), memoryBefore + sizeof(dissect::TlsSession) + 19 + 64 + sizeof(uint64_t) + sizeof(dissect::TlsMessageRef) + 48) << "the marker is gone, a session and a message were added";
    EXPECT_EQ(t.tlsSessionsBetween("1.1.1.1", 1, "2.2.2.2", 2), 2u) << "the SYN started a second session";
    EXPECT_EQ(t.findTlsSession("1.1.1.1", 1, "2.2.2.2", 2)->directions[0].records, 1u);

    // a SYN that is retransmitted after the hello: the next message is further along in the stream, so it does not restart
    EXPECT_TRUE(t.markTlsRestart("1.1.1.1", 1, "2.2.2.2", 2, 1));
    EXPECT_TRUE(t.addTlsMessage("1.1.1.1", 1, "2.2.2.2", 2, facts(9, 51, 40, 1)));
    EXPECT_EQ(t.tlsSessionsBetween("1.1.1.1", 1, "2.2.2.2"  , 2), 2u);
    EXPECT_EQ(t.findTlsSession("1.1.1.1", 1, "2.2.2.2", 2)->directions[0].records, 2u);
    // ... and a marker is not used up by traffic of the other direction
    EXPECT_TRUE(t.markTlsRestart("1.1.1.1", 1, "2.2.2.2", 2, 91));
    EXPECT_TRUE(t.addTlsMessage("2.2.2.2", 2, "1.1.1.1", 1, facts(10, 1, 30, 1)));
    EXPECT_TRUE(t.addTlsMessage("1.1.1.1", 1, "2.2.2.2", 2, facts(11, 91, 20, 1)));
    EXPECT_EQ(t.tlsSessionsBetween("1.1.1.1", 1, "2.2.2.2", 2), 3u);
    t.freeze();
    EXPECT_FALSE(t.markTlsRestart("1.1.1.1", 1, "2.2.2.2", 2, 1));
}

TEST(TlsSessionTable, SynsOfOtherProtocolsDoNotUseTheTlsBudget) {
    // thousands of connections that never carry TLS (the SYN of each is seen by the TCP dissector)
    core::SessionTables t(2000);
    for (uint32_t i = 0; i < 5000; ++i) {
        EXPECT_TRUE(t.markTlsRestart("10.0.0." + std::to_string(i % 250), static_cast<uint16_t>(1024 + i), "10.9.9.9", 80, 1));
    }
    EXPECT_EQ(t.totalMemoryUsage(), 0u);
    EXPECT_FALSE(t.hasStateLost());
    EXPECT_TRUE(t.addTlsMessage("10.1.1.1", 1, "10.2.2.2", 443, facts(1, 1, 50, 1))) << "a TLS session still fits";
    EXPECT_FALSE(t.isTableStateLost("tls"));
}

TEST(TlsSessionTable, MemoryBoundMarksTheTableStateLost) {
    core::SessionTables t(1500);   // room for a session or two and a handful of messages
    bool refused = false;
    for (uint32_t i = 0; i < 50 && !refused; ++i) {
        const std::string ip = "10.0.0." + std::to_string(i);
        refused = !t.addTlsMessage(ip, 1000, "10.1.1.1", 443, facts(i + 1, 1, 50, 1));
    }
    EXPECT_TRUE(refused);
    EXPECT_TRUE(t.hasStateLost());
    EXPECT_TRUE(t.isTableStateLost("tls"));
    EXPECT_FALSE(t.isTableStateLost("ftp"));
    EXPECT_LE(t.totalMemoryUsage(), 1500u);

    // messages of one connection: the counters keep advancing when only the message reference no longer fits
    core::SessionTables u(sizeof(dissect::TlsSession) + 200);
    bool lost = false;
    for (uint32_t i = 0; i < 20; ++i) lost |= !u.addTlsMessage("1.1.1.1", 1, "2.2.2.2", 2, facts(i + 1, 1 + i * 10, 10, 1));
    EXPECT_TRUE(lost);
    EXPECT_TRUE(u.isTableStateLost("tls"));
    EXPECT_EQ(u.findTlsSession("1.1.1.1", 1, "2.2.2.2", 2)->directions[0].records, 20u);
    EXPECT_LT(u.tlsTable().messageCount(), 20u);

    // the loaded capture reports it as well
    Loaded cap(kDir + "tls13.pcapng");
    EXPECT_FALSE(cap.fp.sessions().isTableStateLost("tls"));
}

TEST(TlsSessionTable, TlsMemoryIsReleasedWithTheCapture) {
    Loaded cap(kDir + "tls12.pcapng");
    ASSERT_TRUE(cap.ok);
    EXPECT_GT(cap.fp.sessions().tlsTable().memory(), 0u);
    EXPECT_EQ(cap.fp.sessions().totalMemoryUsage() >= cap.fp.sessions().tlsTable().memory(), true);
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(cap.fp.processPcapFile(IMSHARK_TEST_DATA_DIR "/sample.pcap", packets, message));
    EXPECT_EQ(cap.fp.sessions().tlsTable().sessionCount(), 0u);
}

// ---- robustness --------------------------------------------------------------------------------------------

TEST(TlsSession, TruncatedCapturesAtEveryLengthNeverCrash) {
    const std::vector<char> whole = slurpBytes(kDir + "tls13.pcapng");
    ASSERT_GT(whole.size(), 1000u);
    const std::string path = (std::filesystem::temp_directory_path() / "imshark_test_tls_trunc.pcapng").string();
    size_t withSession = 0;
    for (size_t n = 0; n <= whole.size(); ++n) {
        {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            out.write(whole.data(), static_cast<std::streamsize>(n));
        }
        Loaded cap(path);
        if (const auto *s = sessionOf(cap)) {
            ++withSession;
            EXPECT_LE(s->directions[0].records + s->directions[1].records, 14u);
        }
        if (n % 97 == 0 && !cap.packets.empty()) {
            for (size_t i = 0; i < cap.packets.size(); ++i) {
                const auto d = cap.details(i);
                expectInside(d.fields, d.raw_data.size());
            }
        }
    }
    std::remove(path.c_str());
    EXPECT_GT(withSession, 100u);
}

TEST(TlsSession, CutAndCorruptedTlsSegmentsNeverCrash) {
    const std::vector<char> whole = slurpBytes(kDir + "tls13.pcapng");
    std::mt19937 rng(0x7155);
    const std::string path = (std::filesystem::temp_directory_path() / "imshark_test_tls_mut.pcapng").string();
    for (int round = 0; round < 400; ++round) {
        std::vector<char> bytes = whole;
        const int flips = 1 + static_cast<int>(rng() % 6);
        for (int k = 0; k < flips; ++k) bytes[200 + rng() % (bytes.size() - 200)] = static_cast<char>(rng());   // after the headers and the key block
        {
            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        }
        Loaded cap(path);
        for (size_t i = 0; i < cap.packets.size(); ++i) {
            const auto d = cap.details(i);
            expectInside(d.fields, d.raw_data.size());
        }
    }
    std::remove(path.c_str());
}

TEST(TlsSession, ShortAndCutRecordsInSyntheticFlows) {
    // every prefix of a hello + records flight as TCP payload
    const std::string bytes = raw(clientHelloRecord(rnd('9')) + serverHelloRecord(rnd('a'), 0x1301, true) + record(20, "01") + record(23, std::string(50, 'd')));
    for (size_t n = 0; n <= bytes.size(); ++n) {
        Flow f;
        f.syn();
        f.toServer(bytes.substr(0, n));
        if (n < bytes.size()) f.toServer(bytes.substr(n));
        FlowCapture cap(f);
        ASSERT_TRUE(cap.ok) << cap.message;
        for (size_t i = 0; i < cap.packets.size(); ++i) {
            const auto d = cap.details(i);
            expectInside(d.fields, d.raw_data.size());
        }
        if (n == 0 || n == bytes.size()) continue;
        const auto *s = sessionOf(cap);
        ASSERT_NE(s, nullptr) << n;
        EXPECT_EQ(s->directions[0].records, 4u) << "the stream is the same however it is cut: " << n;
    }
}
