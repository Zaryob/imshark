// The decryption bookkeeping of the load pass (dissect/tls_decrypt.h) driven through SessionTables, without any TCP or
// dissector in between: messages are registered the way the TLS dissector registers them, their records go to
// decryptTlsMessage() in stream order and are read back with readTlsMessage() the way detail building does.
//
// Oracles: the records and key logs of tests/data/tls/decrypt_tls13.json / decrypt_tls12.json are real connections of
// `openssl s_client` / `openssl s_server`; the plaintext they must give is what the client sent and what s_client printed.
#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include <core.h>
#include <dissect/tls_decrypt.h>
#include <tls/crypto.h>

#include "tls_support.h"

namespace {
    using dissect::TlsRecordState;
    using tlstest::kDir;

    struct Rec {
        uint8_t type;
        uint16_t version;
        std::vector<uint8_t> fragment;
    };

    std::vector<uint8_t> bytesOf(const std::string &hexText) {
        std::vector<uint8_t> out;
        for (char c: support::hex(hexText)) out.push_back(static_cast<uint8_t>(c));
        return out;
    }

    struct Case {
        std::string name, keylog, clientRandomHex, serverRandomHex;
        uint16_t version = 0, cipher = 0;
        std::vector<Rec> records[2];            // [0] client to server, [1] server to client (protected records only)
        std::vector<uint8_t> application[2];    // expected application data
    };

    std::vector<Case> loadCases(const std::string &file) {
        std::vector<Case> out;
        const auto doc = testutil::JsonParser(tlstest::slurp(kDir + file)).parse();
        for (const auto &j: doc.at("cases").items) {
            Case c;
            c.name = j.str("name");
            c.keylog = j.str("keylog");
            c.clientRandomHex = j.str("client_random");
            c.serverRandomHex = j.str("server_random");
            c.version = static_cast<uint16_t>(j.num("version"));
            c.cipher = static_cast<uint16_t>(j.num("cipher"));
            const char *names[2] = {"c2s", "s2c"};
            for (int d = 0; d < 2; ++d) {
                for (const auto &r: j.at(names[d]).items) {
                    c.records[d].push_back({static_cast<uint8_t>(r.num("type")), static_cast<uint16_t>(r.num("version")), bytesOf(r.str("fragment"))});
                }
            }
            c.application[0] = bytesOf(j.str("c2s_application_data"));
            c.application[1] = bytesOf(j.str("s2c_application_data"));
            out.push_back(std::move(c));
        }
        return out;
    }

    // One TLS connection 10.0.0.1:50000 -> 10.0.0.2:443 fed to the session tables a record per message.
    struct Conn {
        core::SessionTables t;
        uint32_t packet = 1;
        uint32_t seq[2] = {1, 1};
        uint32_t index[2] = {0, 0};   // record index in each direction
        struct Sent {
            uint32_t packet, startSeq;
            int dir;
            Rec rec;
            dissect::TlsMessageDecryption md;
        };
        std::vector<Sent> sent;

        explicit Conn(size_t budget = core::SessionTables::kDefaultMaxMemoryPerTable) : t(budget) {}

        const dissect::TlsSession *session() const { return t.findTlsSession("10.0.0.1", 50000, "10.0.0.2", 443); }

        // `facts` fills what the dissector found in the message; the record is its only record
        dissect::TlsMessageDecryption send(int dir, const Rec &rec, dissect::TlsMessageFacts facts = {}, bool skipBytes = false, bool *registered = nullptr) {
            facts.packet = packet++;
            facts.startSeq = seq[dir];
            facts.length = static_cast<uint32_t>(5 + rec.fragment.size());
            facts.records = 1;
            if (skipBytes) seq[dir] += 1000;   // a message that never completed lies in between: the stream has a hole
            facts.startSeq = seq[dir];
            seq[dir] += facts.length;
            ++index[dir];
            const std::string src = dir == 0 ? "10.0.0.1" : "10.0.0.2", dst = dir == 0 ? "10.0.0.2" : "10.0.0.1";
            const uint16_t sport = dir == 0 ? 50000 : 443, dport = dir == 0 ? 443 : 50000;
            dissect::TlsAddResult added;
            const bool ok = t.addTlsMessage(src, sport, dst, dport, facts, &added);
            if (registered) *registered = ok;
            Sent s{facts.packet, facts.startSeq, dir, rec, {}};
            if (ok) {
                const dissect::TlsRecordInput in{rec.type, rec.version, rec.fragment};
                t.decryptTlsMessage(added, facts.packet, facts.startSeq, std::span<const dissect::TlsRecordInput>(&in, 1), s.md);
            }
            sent.push_back(s);
            return sent.back().md;
        }

        // the same message read back the way detail building does
        dissect::TlsMessageDecryption read(size_t i) const {
            dissect::TlsMessageDecryption md;
            const auto &s = sent[i];
            const auto *ref = t.findTlsMessage(s.packet, s.startSeq);
            EXPECT_NE(ref, nullptr);
            if (!ref) return md;
            const dissect::TlsRecordInput in{s.rec.type, s.rec.version, s.rec.fragment};
            t.readTlsMessage(*ref, std::span<const dissect::TlsRecordInput>(&in, 1), md);
            return md;
        }

        // hellos (and, for TLS 1.2, the ChangeCipherSpec of each direction) as the dissector registers them
        void handshake(const Case &c, bool earlyData = false, const std::string &alpn = "") {
            dissect::TlsMessageFacts ch;
            ch.clientHello = true;
            ch.random = tlstest::randomOf(c.clientRandomHex);
            ch.earlyData = earlyData;
            send(0, {22, 0x0301, std::vector<uint8_t>(40, 1)}, ch);
            dissect::TlsMessageFacts sh;
            sh.serverHello = true;
            sh.random = tlstest::randomOf(c.serverRandomHex);
            sh.version = c.version;
            sh.cipherSuite = c.cipher;
            sh.alpn = alpn;
            send(1, {22, 0x0303, std::vector<uint8_t>(40, 2)}, sh);
            if (c.version != 0x0304) {   // TLS 1.2: the records that follow the ChangeCipherSpec are protected
                dissect::TlsMessageFacts ccs;
                ccs.changeCipherSpecs = {0};
                for (int d = 0; d < 2; ++d) send(d, {20, 0x0303, {1}}, ccs);
            }
        }
    };

    std::vector<uint8_t> concat(const std::vector<const dissect::TlsMessageDecryption *> &parts, uint8_t contentType) {
        std::vector<uint8_t> out;
        for (const auto *md: parts) {
            for (size_t i = 0; i < md->outcomes.size(); ++i) {
                if (md->outcomes[i].recordState() == TlsRecordState::Decrypted && md->outcomes[i].contentType == contentType) {
                    out.insert(out.end(), md->plaintext[i].begin(), md->plaintext[i].end());
                }
            }
        }
        return out;
    }

    class TlsDecryptTable : public ::testing::Test {
    protected:
        void SetUp() override {
            if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
        }
    };

    // all protected records of the case, interleaved client first then server, as the connection ran per direction
    void feedAll(Conn &c, const Case &cs, std::vector<size_t> *order = nullptr) {
        for (int d = 0; d < 2; ++d) {
            for (const Rec &r: cs.records[d]) {
                c.send(d, r);
                if (order) order->push_back(c.sent.size() - 1);
            }
        }
    }
} // namespace

TEST_F(TlsDecryptTable, EveryOpenSslSuiteDecryptsToTheKnownPlaintext) {
    for (const char *file: {"decrypt_tls13.json", "decrypt_tls12.json"}) {
        for (const Case &cs: loadCases(file)) {
            SCOPED_TRACE(cs.name);
            Conn c;
            c.t.tlsExternalKeys().parseText(cs.keylog);
            c.handshake(cs);
            const size_t first = c.sent.size();
            feedAll(c, cs);
            std::vector<const dissect::TlsMessageDecryption *> client, server;
            for (size_t i = first; i < c.sent.size(); ++i) {
                for (const auto &o: c.sent[i].md.outcomes) EXPECT_EQ(o.recordState(), TlsRecordState::Decrypted) << i;
                (c.sent[i].dir == 0 ? client : server).push_back(&c.sent[i].md);
            }
            EXPECT_EQ(concat(client, 23), cs.application[0]);
            EXPECT_EQ(concat(server, 23), cs.application[1]);
            EXPECT_FALSE(c.t.hasStateLost());
            EXPECT_GT(c.t.tlsDecryptTable().outcomeCount(), 0u);
        }
    }
}

TEST_F(TlsDecryptTable, ReadingBackGivesWhatTheLoadPassDecided) {
    // replay equality at the table level: states, positions, inner content types and plaintext
    size_t keyUpdates = 0;
    for (const char *file: {"decrypt_tls13.json", "decrypt_tls12.json"}) {
        for (const Case &cs: loadCases(file)) {
            SCOPED_TRACE(cs.name);
            Conn c;
            c.t.tlsExternalKeys().parseText(cs.keylog);
            c.handshake(cs);
            feedAll(c, cs);
            for (size_t i = 0; i < c.sent.size(); ++i) {
                const auto again = c.read(i);
                const auto &was = c.sent[i].md;
                ASSERT_EQ(again.outcomes.size(), was.outcomes.size());
                for (size_t k = 0; k < was.outcomes.size(); ++k) {
                    EXPECT_EQ(again.outcomes[k].state, was.outcomes[k].state) << i;
                    EXPECT_EQ(again.outcomes[k].contentType, was.outcomes[k].contentType) << i;
                    EXPECT_EQ(again.outcomes[k].sequence, was.outcomes[k].sequence) << i;
                    EXPECT_EQ(again.outcomes[k].keyUpdates, was.outcomes[k].keyUpdates) << i;
                    EXPECT_EQ(again.outcomes[k].plainLength, was.outcomes[k].plainLength) << i;
                    EXPECT_EQ(again.plaintext[k], was.plaintext[k]) << i;
                    keyUpdates += was.outcomes[k].keyUpdates;
                }
            }
        }
    }
    EXPECT_GT(keyUpdates, 0u) << "the TLS 1.3 fixtures contain a KeyUpdate: later records are opened from the stored generation";
}

TEST_F(TlsDecryptTable, OnlyTheRecordsOfOneMessageAreNeededToReadItBack) {
    // a late application record is re-opened from its stored position alone: nothing before it is replayed
    const auto cases = loadCases("decrypt_tls13.json");
    const Case &cs = cases[0];
    Conn c;
    c.t.tlsExternalKeys().parseText(cs.keylog);
    c.handshake(cs);
    feedAll(c, cs);
    const auto last = c.sent.size() - 1;
    const auto md = c.read(last);
    ASSERT_EQ(md.outcomes.size(), 1u);
    EXPECT_EQ(md.outcomes[0].recordState(), TlsRecordState::Decrypted);
    EXPECT_EQ(md.plaintext[0], c.sent[last].md.plaintext[0]);
    EXPECT_GT(md.outcomes[0].sequence + md.outcomes[0].keyUpdates, 0u) << "not the first record of its keys";
}

TEST_F(TlsDecryptTable, RecordsOfAnotherConnectionsKeysAreATagFailureWithoutPlaintext) {
    const auto cases = loadCases("decrypt_tls13.json");
    const Case *a = nullptr, *b = nullptr;   // two SHA-256 suites: the secrets have the right length but are not this connection's
    for (const auto &cs: cases) {
        if (cs.cipher == 0x1301) a = &cs;
        if (cs.cipher == 0x1303) b = &cs;
    }
    ASSERT_TRUE(a && b);
    std::string log = a->keylog;   // a's secrets under b's client random
    for (size_t at; (at = log.find(a->clientRandomHex)) != std::string::npos;) log.replace(at, a->clientRandomHex.size(), b->clientRandomHex);
    Conn c;
    c.t.tlsExternalKeys().parseText(log);
    c.handshake(*b);
    feedAll(c, *b);
    size_t failed = 0;
    for (size_t i = 2; i < c.sent.size(); ++i) {
        ASSERT_EQ(c.sent[i].md.outcomes.size(), 1u);
        EXPECT_EQ(c.sent[i].md.outcomes[0].recordState(), TlsRecordState::TagFailure) << i;
        EXPECT_TRUE(c.sent[i].md.plaintext[0].empty());
        EXPECT_EQ(c.read(i).outcomes[0].recordState(), TlsRecordState::TagFailure);
        EXPECT_TRUE(c.read(i).plaintext[0].empty());
        ++failed;
    }
    EXPECT_GT(failed, 4u);
}

TEST_F(TlsDecryptTable, NoKeyMaterialKeepsNoOutcomesAndSaysSo) {
    for (const char *file: {"decrypt_tls13.json", "decrypt_tls12.json"}) {
        const auto cases = loadCases(file);
        const Case &cs = cases[0];
        SCOPED_TRACE(cs.name);
        Conn c;   // no key store at all
        c.handshake(cs);
        feedAll(c, cs);
        for (size_t i = cs.version == 0x0304 ? 2 : 4; i < c.sent.size(); ++i) {   // after the hellos (and the ChangeCipherSpec records)
            ASSERT_EQ(c.sent[i].md.outcomes.size(), 1u);
            EXPECT_EQ(c.sent[i].md.outcomes[0].recordState(), TlsRecordState::NoKey) << i;
            EXPECT_EQ(c.read(i).outcomes[0].recordState(), TlsRecordState::NoKey);
        }
        // hellos and (TLS 1.2) the ChangeCipherSpec records are not protected
        EXPECT_EQ(c.sent[0].md.outcomes[0].recordState(), TlsRecordState::Clear);
        EXPECT_EQ(c.sent[1].md.outcomes[0].recordState(), TlsRecordState::Clear);
        EXPECT_EQ(c.t.tlsDecryptTable().outcomeCount(), 0u) << "nothing is stored for a connection without keys";
    }
}

TEST_F(TlsDecryptTable, ASecretLessConnectionAmongKeyedOnesIsNoKeyToo) {
    const auto cases = loadCases("decrypt_tls13.json");
    Conn c;
    c.t.tlsExternalKeys().parseText(cases[1].keylog);   // keys of another connection only
    c.handshake(cases[0]);
    feedAll(c, cases[0]);
    EXPECT_EQ(c.sent.back().md.outcomes[0].recordState(), TlsRecordState::NoKey);
}

TEST_F(TlsDecryptTable, UnsupportedSuiteBeatsTheKeys) {
    auto cases = loadCases("decrypt_tls12.json");
    Case cs = cases[0];
    cs.cipher = 0x002f;   // TLS_RSA_WITH_AES_128_CBC_SHA: a CBC suite
    Conn c;
    c.t.tlsExternalKeys().parseText(cs.keylog);
    c.handshake(cs);
    feedAll(c, cs);
    for (size_t i = 4; i < c.sent.size(); ++i) {
        EXPECT_EQ(c.sent[i].md.outcomes[0].recordState(), TlsRecordState::UnsupportedSuite) << i;
        EXPECT_TRUE(c.sent[i].md.plaintext[0].empty());
        EXPECT_EQ(c.read(i).outcomes[0].recordState(), TlsRecordState::UnsupportedSuite);
    }
}

TEST_F(TlsDecryptTable, WithoutAServerHelloTheSuiteIsUnknown) {
    const auto cases = loadCases("decrypt_tls13.json");
    const Case &cs = cases[0];
    Conn c;
    c.t.tlsExternalKeys().parseText(cs.keylog);
    dissect::TlsMessageFacts ch;
    ch.clientHello = true;
    ch.random = tlstest::randomOf(cs.clientRandomHex);
    c.send(0, {22, 0x0301, std::vector<uint8_t>(40, 1)}, ch);
    const auto md = c.send(0, cs.records[0][0]);   // the ServerHello never arrived: version and suite are unknown
    EXPECT_EQ(md.outcomes[0].recordState(), TlsRecordState::NoHandshake);
    EXPECT_EQ(c.read(1).outcomes[0].recordState(), TlsRecordState::NoHandshake);
}

TEST_F(TlsDecryptTable, RecordsAfterAGapAreNotReportedAsAWrongKey) {
    const auto cases = loadCases("decrypt_tls13.json");
    const Case &cs = cases[0];
    ASSERT_GE(cs.records[1].size(), 6u);
    Conn c;
    c.t.tlsExternalKeys().parseText(cs.keylog);
    c.handshake(cs);
    // the server's first two records arrive, then a message of that direction is missing (a hole in the TCP stream)
    EXPECT_EQ(c.send(1, cs.records[1][0]).outcomes[0].recordState(), TlsRecordState::Decrypted);
    EXPECT_EQ(c.send(1, cs.records[1][1]).outcomes[0].recordState(), TlsRecordState::Decrypted);
    const auto after = c.send(1, cs.records[1][3], {}, /*skipBytes=*/true);
    EXPECT_EQ(after.outcomes[0].recordState(), TlsRecordState::CaptureGap);
    EXPECT_TRUE(after.plaintext[0].empty());
    EXPECT_TRUE(c.session()->directions[1].gap || c.session()->directions[0].gap);
    EXPECT_EQ(c.send(1, cs.records[1][4]).outcomes[0].recordState(), TlsRecordState::CaptureGap) << "the direction stays unnumbered";
    EXPECT_EQ(c.read(c.sent.size() - 1).outcomes[0].recordState(), TlsRecordState::CaptureGap);
    // the other direction is intact
    EXPECT_EQ(c.send(0, cs.records[0][0]).outcomes[0].recordState(), TlsRecordState::Decrypted);
}

TEST_F(TlsDecryptTable, ARecordThatFailsInTheHandshakeEpochDoesNotMoveTheSequenceNumber) {
    const auto cases = loadCases("decrypt_tls13.json");
    const Case &cs = cases[0];
    for (bool offered: {true, false}) {
        SCOPED_TRACE(offered ? "ClientHello offered early data" : "no early data offered");
        Conn c;
        c.t.tlsExternalKeys().parseText(cs.keylog);
        c.handshake(cs, offered);
        // 0-RTT data of the client: a protected record that the handshake keys cannot open, in front of the client Finished
        Rec early{23, 0x0303, std::vector<uint8_t>(60, 0x5a)};
        const auto e = c.send(0, early);
        EXPECT_EQ(e.outcomes[0].recordState(), offered ? TlsRecordState::EarlyData : TlsRecordState::TagFailure);
        EXPECT_TRUE(e.plaintext[0].empty());
        const auto finished = c.send(0, cs.records[0][0]);
        EXPECT_EQ(finished.outcomes[0].recordState(), TlsRecordState::Decrypted) << "still the first record under the handshake keys";
        EXPECT_EQ(finished.outcomes[0].sequence, 0u);
        EXPECT_EQ(c.read(c.sent.size() - 1).outcomes[0].recordState(), TlsRecordState::Decrypted);
        // the application records that follow keep working
        for (size_t i = 1; i < cs.records[0].size(); ++i) {
            EXPECT_EQ(c.send(0, cs.records[0][i]).outcomes[0].recordState(), TlsRecordState::Decrypted) << i;
        }
    }
}

TEST_F(TlsDecryptTable, MalformedProtectedRecords) {
    const auto cases = loadCases("decrypt_tls13.json");
    Conn c;
    c.t.tlsExternalKeys().parseText(cases[0].keylog);
    c.handshake(cases[0]);
    EXPECT_EQ(c.send(1, {23, 0x0303, {1, 2, 3}}).outcomes[0].recordState(), TlsRecordState::Malformed) << "shorter than an authentication tag";
    EXPECT_EQ(c.send(1, cases[0].records[1][0]).outcomes[0].recordState(), TlsRecordState::Decrypted) << "and it did not consume a sequence number";
}

TEST_F(TlsDecryptTable, TheTableBudgetBoundsWhatIsKept) {
    const auto cases = loadCases("decrypt_tls13.json");
    const Case &cs = cases[0];
    Conn big;
    big.t.tlsExternalKeys().parseText(cs.keylog);
    big.handshake(cs);
    feedAll(big, cs);
    const size_t needed = big.t.totalMemoryUsage();

    // not enough room for everything: the rest is lost, never answered wrongly, and the budget holds
    Conn c(needed / 2);
    c.t.tlsExternalKeys().parseText(cs.keylog);
    c.handshake(cs);
    size_t decrypted = 0, lost = 0;
    for (int d = 0; d < 2; ++d) {
        for (const Rec &r: cs.records[d]) {
            c.send(d, r);
            const auto &md = c.sent.back().md;
            if (md.outcomes.empty()) ++lost;
            else if (md.outcomes[0].recordState() == TlsRecordState::Decrypted) ++decrypted;
        }
    }
    EXPECT_GT(lost, 0u);
    EXPECT_TRUE(c.t.isTableStateLost("tls"));
    EXPECT_LE(c.t.totalMemoryUsage(), c.t.maxMemoryPerTable());
    EXPECT_TRUE(c.sent.back().md.outcomes.empty()) << "the last message did not fit";
    (void) decrypted;
}

TEST_F(TlsDecryptTable, ADecryptTableThatRanOutOfRoomStaysExhausted) {
    const auto cases = loadCases("decrypt_tls13.json");
    const Case &cs = cases[0];
    dissect::TlsSession session;
    session.version = cs.version;
    session.cipherSuite = cs.cipher;
    session.hasClientRandom = session.hasServerRandom = true;
    session.clientRandom = tlstest::randomOf(cs.clientRandomHex);
    session.serverRandom = tlstest::randomOf(cs.serverRandomHex);
    session.clientDirection = 0;
    tls::KeyStore store;
    store.parseText(cs.keylog);
    const dissect::TlsRecordInput in{23, 0x0303, cs.records[1][0].fragment};
    dissect::TlsDecryptTable table;
    dissect::TlsMessageDecryption out;
    uint32_t first = 0;
    EXPECT_FALSE(table.process(session, 0, 1, 0, false, std::span<const dissect::TlsRecordInput>(&in, 1), store.find(session.clientRandom), 100, first, out));
    EXPECT_TRUE(table.exhausted());
    EXPECT_TRUE(out.outcomes.empty());
    EXPECT_EQ(table.memory(), 0u);
    EXPECT_FALSE(table.process(session, 0, 1, 0, false, std::span<const dissect::TlsRecordInput>(&in, 1), store.find(session.clientRandom), 1 << 20, first, out))
        << "later records cannot be numbered once one was dropped";
}

TEST_F(TlsDecryptTable, ASessionTableClearForgetsTheOutcomes) {
    const auto cases = loadCases("decrypt_tls12.json");
    Conn c;
    c.t.tlsExternalKeys().parseText(cases[0].keylog);
    c.handshake(cases[0]);
    feedAll(c, cases[0]);
    EXPECT_GT(c.t.tlsDecryptTable().outcomeCount(), 0u);
    c.t.clear();
    EXPECT_EQ(c.t.tlsDecryptTable().outcomeCount(), 0u);
    EXPECT_EQ(c.t.tlsDecryptTable().memory(), 0u);
    EXPECT_EQ(c.t.totalMemoryUsage(), 0u);
    EXPECT_FALSE(c.t.tlsExternalKeys().empty()) << "the keys the user supplied outlive a new capture";
}

// ---- ALPN and the inner protocol ----------------------------------------------------------------------------------

TEST(TlsInnerProtocol, AlpnAndSniffing) {
    EXPECT_EQ(dissect::tlsInnerFromAlpn("h2"), dissect::TlsInner::Http2);
    EXPECT_EQ(dissect::tlsInnerFromAlpn("http/1.1"), dissect::TlsInner::Http1);
    EXPECT_EQ(dissect::tlsInnerFromAlpn("http/1.0"), dissect::TlsInner::Http1);
    EXPECT_EQ(dissect::tlsInnerFromAlpn(""), dissect::TlsInner::Unknown);
    EXPECT_EQ(dissect::tlsInnerFromAlpn("h3"), dissect::TlsInner::Unknown);
    auto sniff = [](const std::string &s) { return dissect::sniffTlsInner(std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(s.data()), s.size())); };
    EXPECT_EQ(sniff("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), dissect::TlsInner::Http2);
    EXPECT_EQ(sniff("GET / HTTP/1.1\r\n"), dissect::TlsInner::Http1);
    EXPECT_EQ(sniff("POST /x HTTP/1.1\r\n"), dissect::TlsInner::Http1);
    EXPECT_EQ(sniff("HTTP/1.1 200 OK\r\n"), dissect::TlsInner::Http1);
    EXPECT_EQ(sniff("SSH-2.0-OpenSSH\r\n"), dissect::TlsInner::Unknown);
    EXPECT_EQ(sniff(""), dissect::TlsInner::Unknown);
    EXPECT_EQ(sniff("GET"), dissect::TlsInner::Unknown) << "a method needs its space";
}

TEST(TlsInnerProtocol, AlpnFromEncryptedExtensions) {
    // EncryptedExtensions (type 8): extensions length, then supported_groups (10) and ALPN (16) naming "h2"
    // ALPN body: protocol_name_list length (2) = 3, name length (1) = 2, "h2"; the extension is type 0010, length 0005
    const std::string alpn = "0010" "0005" "0003" "02" "6832";
    const std::string groups = "000a" "0004" "0002" "001d";
    const std::string body = "0016" + groups + alpn;   // 0x16 = 22 bytes of extensions
    auto message = [](const std::string &b) { return "08" "0000" + std::string(1, "0123456789abcdef"[(b.size() / 2) >> 4]) + std::string(1, "0123456789abcdef"[(b.size() / 2) & 15]) + b; };
    auto toBytes = [](const std::string &h) { std::vector<uint8_t> v; for (char c: support::hex(h)) v.push_back(static_cast<uint8_t>(c)); return v; };
    const auto bytes = toBytes(message(body));
    EXPECT_EQ(dissect::alpnFromEncryptedExtensions(bytes), "h2");
    // other messages before it in the same record do not hide it; one that is not EncryptedExtensions gives nothing
    auto withTicket = toBytes("04000004" "00000000" + message(body));
    EXPECT_EQ(dissect::alpnFromEncryptedExtensions(withTicket), "h2");
    EXPECT_EQ(dissect::alpnFromEncryptedExtensions(toBytes("0b000004" "00000000")), "");
    // every cut of it is safe and never invents a protocol
    for (size_t n = 0; n <= bytes.size(); ++n) {
        const std::string got = dissect::alpnFromEncryptedExtensions(std::span<const uint8_t>(bytes.data(), n));
        EXPECT_TRUE(got.empty() || (n == bytes.size() && got == "h2")) << n;
    }
    for (size_t i = 0; i < bytes.size(); ++i) {   // and every damaged byte
        auto damaged = bytes;
        damaged[i] ^= 0xff;
        (void) dissect::alpnFromEncryptedExtensions(damaged);
    }
}

TEST_F(TlsDecryptTable, TheSelectedAlpnOfTlsTwelveComesFromTheServerHelloFacts) {
    const auto cases = loadCases("decrypt_tls12.json");
    Conn c;
    c.t.tlsExternalKeys().parseText(cases[0].keylog);
    c.handshake(cases[0], false, "h2");
    EXPECT_EQ(c.session()->alpn, "h2");
}
