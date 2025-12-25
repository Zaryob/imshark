// The DTLS session tables (dissect/dtls_session.h, dtls_decrypt.h) driven through SessionTables, without any UDP or dissector
// in between: hellos, handshake fragments and protected records are registered the way the DTLS dissector registers them.
//
// Oracles: the sealed records come from tools/make_dtls_vectors.py (AES and GCM implemented from FIPS 197 / SP 800-38D and
// checked against NIST GCM test cases 4 and 16; TLS 1.2 PRF from hmac/hashlib and compared with `openssl kdf ... TLS1-PRF`),
// master secret 30..5f, client random 00..1f, server random 80..9f. The expected plaintext is what that script sealed.
#include <gtest/gtest.h>

#include <algorithm>
#include <string>
#include <vector>

#include <core.h>
#include <tls/crypto.h>

#include "support.h"

namespace {
    using dissect::DtlsFragment;
    using dissect::DtlsFragmentRef;
    using dissect::DtlsHelloFacts;
    using dissect::TlsRecordState;

    const std::string kClient = "10.0.0.1", kServer = "10.0.0.2";
    constexpr uint16_t kClientPort = 50000, kServerPort = 4433;

    DtlsHelloFacts hello(bool client, uint8_t fill, uint16_t version = 0xfefd, uint16_t cipher = 0xc02f) {
        DtlsHelloFacts f;
        f.client = client;
        f.random.fill(fill);
        f.version = version;
        f.cipherSuite = cipher;
        return f;
    }

    // `data` outlives the call: the table copies what it keeps
    DtlsFragment fragment(uint32_t packet, uint16_t epoch, uint16_t seq, uint32_t length, uint32_t offset, const std::string &data, uint16_t position = 13 + 12) {
        DtlsFragment f;
        f.packet = packet;
        f.position = position;
        f.epoch = epoch;
        f.messageSeq = seq;
        f.type = 1;
        f.length = length;
        f.offset = offset;
        f.data = data.data();
        f.size = data.size();
        f.time = packet * 0.001;
        return f;
    }

    bool add(core::SessionTables &t, const DtlsFragment &f, std::vector<uint32_t> *earlier = nullptr, bool fromClient = true) {
        std::vector<uint32_t> e;
        const bool ok = fromClient ? t.addDtlsFragment(kClient, kClientPort, kServer, kServerPort, f, e)
                                   : t.addDtlsFragment(kServer, kServerPort, kClient, kClientPort, f, e);
        if (earlier) *earlier = e;
        return ok;
    }

    std::vector<uint8_t> bytesOf(const std::string &hexText) {
        std::vector<uint8_t> out;
        for (char c: support::hex(hexText)) out.push_back(static_cast<uint8_t>(c));
        return out;
    }

    // a sealed record as printed by the script: 13 byte header and the fragment
    struct Sealed {
        std::vector<uint8_t> bytes;
        dissect::DtlsRecordInput input() const {
            dissect::DtlsRecordInput in;
            in.type = bytes[0];
            in.version = static_cast<uint16_t>(bytes[1] << 8 | bytes[2]);
            in.epoch = static_cast<uint16_t>(bytes[3] << 8 | bytes[4]);
            for (size_t i = 0; i < 6; ++i) in.sequence = in.sequence << 8 | bytes[5 + i];
            in.fragment = std::span<const uint8_t>(bytes.data() + 13, bytes.size() - 13);
            return in;
        }
    };
    Sealed sealed(const std::string &hexText) { return Sealed{bytesOf(hexText)}; }

    const std::string kMaster = "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f";

    // AES-128-GCM (0xc02f): the vectors of tools/make_dtls_vectors.py
    const char *kClientFinished128 = "16fefd000100000000000000300001000000000000c6a8ad73ecd5afdde9d4a2edc0ae40825b142c04b23792f28b20e02494684548e4609f4301f9bbd5";
    const char *kServerFinished128 = "16fefd0001000000000000003000010000000000003643077842771539658f10892b81d95ff8bdc6dbd31a90767980029fbb0066371406f4eea4d8136a";
    const char *kClientData128 = "17fefd00010000000000010022000100000000000182b4a773227fb79930def22b0edf1304ef570a5cdb8a7a3f8c03";
    const char *kServerData128 = "17fefd0001000000000005001c010203040506070855316e6b2387c5e39ded9f0bf09055ae3537557b";
    // AES-256-GCM (0xc030)
    const char *kClientData256 = "17fefd0001000000000001002200010000000000015d17152edb2d41b227b48295d924a33b4714d563ed331b339a5f";

    // a session whose hellos were seen (client random 00..1f, server random 80..9f) and whose key log has the master secret
    void prepare(core::SessionTables &t, uint16_t cipher = 0xc02f, uint16_t version = 0xfefd, bool withServerHello = true, const std::string &master = kMaster) {
        DtlsHelloFacts c, s;
        c.client = true;
        s.client = false;
        for (size_t i = 0; i < 32; ++i) { c.random[i] = static_cast<uint8_t>(i); s.random[i] = static_cast<uint8_t>(0x80 + i); }
        s.version = version;
        s.cipherSuite = cipher;
        ASSERT_TRUE(t.addDtlsHello(kClient, kClientPort, kServer, kServerPort, c));
        if (withServerHello) ASSERT_TRUE(t.addDtlsHello(kServer, kServerPort, kClient, kClientPort, s));
        if (!master.empty()) t.tlsExternalKeys().parseText("CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f " + master + "\n");
    }

    std::string text(const std::vector<uint8_t> &v) { return std::string(v.begin(), v.end()); }
} // namespace

TEST(DtlsSessions, HelloRandomsMakeSessionsAndRetransmissionsKeepThem) {
    core::SessionTables t;
    EXPECT_EQ(t.findDtlsSession(kClient, kClientPort, kServer, kServerPort), dissect::kDtlsNone);
    ASSERT_TRUE(t.addDtlsHello(kClient, kClientPort, kServer, kServerPort, hello(true, 0x11)));
    const uint32_t first = t.findDtlsSession(kClient, kClientPort, kServer, kServerPort);
    ASSERT_NE(first, dissect::kDtlsNone);
    // the second ClientHello after a HelloVerifyRequest carries the same random: same session
    ASSERT_TRUE(t.addDtlsHello(kClient, kClientPort, kServer, kServerPort, hello(true, 0x11)));
    EXPECT_EQ(t.findDtlsSession(kClient, kClientPort, kServer, kServerPort), first);
    ASSERT_TRUE(t.addDtlsHello(kServer, kServerPort, kClient, kClientPort, hello(false, 0x22)));
    EXPECT_EQ(t.findDtlsSession(kServer, kServerPort, kClient, kClientPort), first) << "both directions share the session";
    const dissect::DtlsSession *s = t.dtlsSession(first);
    ASSERT_NE(s, nullptr);
    EXPECT_TRUE(s->hasClientRandom && s->hasServerRandom);
    EXPECT_EQ(s->version, 0xfefd);
    EXPECT_EQ(s->cipherSuite, 0xc02f);
    unsigned toServer = 9, toClient = 9;
    t.findDtlsSession(kClient, kClientPort, kServer, kServerPort, &toServer);
    t.findDtlsSession(kServer, kServerPort, kClient, kClientPort, &toClient);
    EXPECT_NE(toServer, toClient);
    EXPECT_EQ(static_cast<unsigned>(s->clientDirection), toServer) << "the client sends the ClientHello";

    // a ClientHello with another random is a new connection between the same endpoints
    ASSERT_TRUE(t.addDtlsHello(kClient, kClientPort, kServer, kServerPort, hello(true, 0x33)));
    const uint32_t second = t.findDtlsSession(kClient, kClientPort, kServer, kServerPort);
    EXPECT_NE(second, first);
    EXPECT_EQ(t.dtlsTable().sessionCount(), 2u);
    EXPECT_FALSE(t.dtlsSession(second)->hasServerRandom);
    // a ServerHello alone (the ClientHello was not captured) still makes a session and knows who the client is
    ASSERT_TRUE(t.addDtlsHello("10.9.9.9", 1, "10.9.9.8", 2, hello(false, 0x44)));
    const uint32_t lone = t.findDtlsSession("10.9.9.9", 1, "10.9.9.8", 2);
    ASSERT_NE(lone, dissect::kDtlsNone);
    EXPECT_FALSE(t.dtlsSession(lone)->hasClientRandom);
    EXPECT_GE(t.dtlsSession(lone)->clientDirection, 0);
}

TEST(DtlsFragments, AMessageCompletesInAnyArrivalOrderAndEveryFragmentKnowsWhere) {
    const std::string whole = "AAAAAAAABBBBBBBBCCCCCCCC";
    const std::vector<std::pair<uint32_t, uint32_t>> parts = {{0, 8}, {8, 8}, {16, 8}};
    std::vector<int> order = {0, 1, 2};
    do {
        core::SessionTables t;
        std::vector<uint32_t> earlier;
        for (size_t i = 0; i < order.size(); ++i) {
            const auto &p = parts[order[i]];
            const uint32_t packet = 10 + static_cast<uint32_t>(order[i]);
            ASSERT_TRUE(add(t, fragment(packet, 0, 3, 24, p.first, whole.substr(p.first, p.second)), &earlier));
            EXPECT_EQ(earlier.empty(), i + 1 < order.size()) << "only the completing fragment reports earlier packets";
        }
        const uint32_t last = 10 + static_cast<uint32_t>(order.back());
        EXPECT_EQ(earlier.size(), 2u);
        for (int n: order) {
            const DtlsFragmentRef *ref = t.dtlsFragment(10 + static_cast<uint32_t>(n), 25);
            ASSERT_NE(ref, nullptr);
            EXPECT_EQ(ref->completedIn, last);
            const bool completes = 10 + static_cast<uint32_t>(n) == last;
            EXPECT_EQ((ref->flags & DtlsFragmentRef::kCompletesHere) != 0, completes);
            EXPECT_EQ(ref->flags & DtlsFragmentRef::kWhole, 0);
            if (completes) {
                const dissect::DtlsMessage *m = t.dtlsMessage(ref->message);
                ASSERT_NE(m, nullptr);
                EXPECT_EQ(m->body, whole);
                EXPECT_EQ(m->packets.size(), 3u);
                EXPECT_EQ(m->packets.back(), last);
            } else {
                EXPECT_EQ(ref->message, dissect::kDtlsNone);
            }
        }
        EXPECT_EQ(t.dtlsTable().pendingMessages(), 0u);
    } while (std::next_permutation(order.begin(), order.end()));
}

TEST(DtlsFragments, WholeMessagesAreNotReassembledAndEqualOnesAreRetransmissions) {
    core::SessionTables t;
    ASSERT_TRUE(add(t, fragment(1, 0, 0, 5, 0, "hello")));
    const DtlsFragmentRef *first = t.dtlsFragment(1, 25);
    ASSERT_NE(first, nullptr);
    EXPECT_EQ(first->flags, DtlsFragmentRef::kCompletesHere | DtlsFragmentRef::kWhole);
    EXPECT_EQ(first->completedIn, 1u);
    EXPECT_EQ(t.dtlsTable().messageCount(), 0u) << "the bytes stay in the packet";
    ASSERT_TRUE(add(t, fragment(4, 0, 0, 5, 0, "hello")));   // the sender retransmits the flight
    const DtlsFragmentRef *again = t.dtlsFragment(4, 25);
    ASSERT_NE(again, nullptr);
    EXPECT_TRUE(again->flags & DtlsFragmentRef::kRetransmission);
    EXPECT_EQ(again->retransmissionOf, 1u);
    ASSERT_TRUE(add(t, fragment(7, 0, 0, 5, 0, "other")));   // a different message under the same key is not a retransmission
    EXPECT_FALSE(t.dtlsFragment(7, 25)->flags & DtlsFragmentRef::kRetransmission);
    ASSERT_TRUE(add(t, fragment(8, 0, 0, 5, 0, "other")));
    EXPECT_EQ(t.dtlsFragment(8, 25)->retransmissionOf, 7u) << "the latest message of the key is what a retransmission repeats";
    // another direction and another epoch are other messages
    ASSERT_TRUE(add(t, fragment(9, 0, 0, 5, 0, "hello"), nullptr, false));
    EXPECT_FALSE(t.dtlsFragment(9, 25)->flags & DtlsFragmentRef::kRetransmission);
    ASSERT_TRUE(add(t, fragment(10, 1, 0, 5, 0, "hello")));
    EXPECT_FALSE(t.dtlsFragment(10, 25)->flags & DtlsFragmentRef::kRetransmission);
    // an empty message (HelloRequest, ServerHelloDone) is whole
    ASSERT_TRUE(add(t, fragment(11, 0, 9, 0, 0, "")));
    EXPECT_TRUE(t.dtlsFragment(11, 25)->flags & DtlsFragmentRef::kWhole);
}

TEST(DtlsFragments, ReassembledRetransmissionIsRecognisedByItsBytes) {
    core::SessionTables t;
    ASSERT_TRUE(add(t, fragment(1, 0, 2, 8, 0, "AAAA")));
    ASSERT_TRUE(add(t, fragment(2, 0, 2, 8, 4, "BBBB")));
    EXPECT_FALSE(t.dtlsFragment(2, 25)->flags & DtlsFragmentRef::kRetransmission);
    ASSERT_TRUE(add(t, fragment(5, 0, 2, 8, 0, "AAAA")));    // the flight again
    ASSERT_TRUE(add(t, fragment(6, 0, 2, 8, 4, "BBBB")));
    const DtlsFragmentRef *ref = t.dtlsFragment(6, 25);
    ASSERT_NE(ref, nullptr);
    EXPECT_TRUE(ref->flags & DtlsFragmentRef::kCompletesHere);
    EXPECT_TRUE(ref->flags & DtlsFragmentRef::kRetransmission);
    EXPECT_EQ(ref->retransmissionOf, 2u);
    EXPECT_EQ(t.dtlsFragment(5, 25)->completedIn, 6u);
}

TEST(DtlsFragments, ConflictsMismatchesAndUnusableFragmentsAreFlagged) {
    core::SessionTables t;
    ASSERT_TRUE(add(t, fragment(1, 0, 1, 8, 0, "AAAAAA")));
    ASSERT_TRUE(add(t, fragment(2, 0, 1, 8, 2, "XXXXXX")));   // overlaps with other bytes: first copy wins, flagged
    EXPECT_TRUE(t.dtlsFragment(2, 25)->flags & DtlsFragmentRef::kConflict);
    EXPECT_EQ(t.dtlsFragment(2, 25)->completedIn, 2u) << "the pieces cover the message";
    const dissect::DtlsMessage *m = t.dtlsMessage(t.dtlsFragment(2, 25)->message);
    ASSERT_NE(m, nullptr);
    EXPECT_EQ(m->body, "AAAAAAXX");

    ASSERT_TRUE(add(t, fragment(3, 0, 2, 20, 0, "AAAA")));
    ASSERT_TRUE(add(t, fragment(4, 0, 2, 30, 4, "BBBB")));    // announces another total length
    EXPECT_TRUE(t.dtlsFragment(4, 25)->flags & DtlsFragmentRef::kTotalConflict);
    EXPECT_EQ(t.dtlsFragment(3, 25)->completedIn, 0u);
    EXPECT_EQ(t.dtlsTable().pendingMessages(), 0u) << "the message was dropped";

    ASSERT_TRUE(add(t, fragment(5, 0, 3, 4, 2, "ZZZZ")));     // runs past the end of the message
    EXPECT_TRUE(t.dtlsFragment(5, 25)->flags & DtlsFragmentRef::kRejected);
}

TEST(DtlsFragments, AFragmentOfAKnownPacketAndPositionIsIgnored) {
    core::SessionTables t;
    ASSERT_TRUE(add(t, fragment(1, 0, 1, 8, 0, "AAAA")));
    const size_t refs = t.dtlsTable().fragmentCount();
    ASSERT_TRUE(add(t, fragment(1, 0, 1, 8, 0, "AAAA")));
    EXPECT_EQ(t.dtlsTable().fragmentCount(), refs);
    ASSERT_TRUE(add(t, fragment(1, 0, 1, 8, 4, "BBBB"), nullptr, true));   // same packet, same position: still ignored
    EXPECT_EQ(t.dtlsFragment(1, 25)->completedIn, 0u);
    ASSERT_TRUE(add(t, fragment(1, 0, 1, 8, 4, "BBBB", 100)));              // the same packet, another record: counts
    EXPECT_EQ(t.dtlsFragment(1, 100)->completedIn, 1u);
    EXPECT_EQ(t.dtlsFragment(1, 25)->completedIn, 1u);
}

TEST(DtlsFragments, ForgottenMessagesDoNotKeepTheirRefsForever) {
    core::SessionTables t;
    auto f = fragment(1, 0, 1, 8, 0, "AAAA");
    ASSERT_TRUE(add(t, f));
    auto late = fragment(2, 0, 1, 8, 4, "BBBB");
    late.time = 1000;                         // far beyond the 60 s reassembly timeout: the first fragment is forgotten
    ASSERT_TRUE(add(t, late));
    EXPECT_EQ(t.dtlsFragment(1, 25)->completedIn, 0u);
    EXPECT_EQ(t.dtlsFragment(2, 25)->completedIn, 0u) << "half of a message is still half";
}

TEST(DtlsTableBudget, RunningOutOfRoomMarksTheTableStateLost) {
    core::SessionTables t(4096);
    std::string big(3000, 'x');
    ASSERT_TRUE(add(t, fragment(1, 0, 1, 6000, 0, big)));
    EXPECT_FALSE(t.isTableStateLost("dtls"));
    EXPECT_FALSE(add(t, fragment(2, 0, 1, 6000, 3000, big)));
    EXPECT_TRUE(t.isTableStateLost("dtls"));
    EXPECT_EQ(t.dtlsFragment(2, 25), nullptr);
    EXPECT_LE(t.dtlsTable().memory(), 4096u);

    core::SessionTables small(300);
    EXPECT_FALSE(small.addDtlsHello(kClient, kClientPort, kServer, kServerPort, hello(true, 1)));
    EXPECT_TRUE(small.isTableStateLost("dtls"));
}

TEST(DtlsTableBudget, FrozenTablesTakeNothingAndClearStartsOver) {
    core::SessionTables t;
    ASSERT_TRUE(add(t, fragment(1, 0, 1, 4, 0, "AAAA")));
    ASSERT_TRUE(t.addDtlsHello(kClient, kClientPort, kServer, kServerPort, hello(true, 1)));
    t.freeze();
    EXPECT_FALSE(add(t, fragment(2, 0, 1, 4, 0, "AAAA")));
    EXPECT_FALSE(t.addDtlsHello(kClient, kClientPort, kServer, kServerPort, hello(true, 2)));
    EXPECT_EQ(t.dtlsFragment(2, 25), nullptr);
    EXPECT_FALSE(t.isTableStateLost("dtls")) << "a frozen table is not a full one";
    EXPECT_NE(t.dtlsFragment(1, 25), nullptr);
    t.clear();
    EXPECT_EQ(t.dtlsFragment(1, 25), nullptr);
    EXPECT_EQ(t.findDtlsSession(kClient, kClientPort, kServer, kServerPort), dissect::kDtlsNone);
    EXPECT_EQ(t.dtlsTable().memory(), 0u);
}

class DtlsRecords : public ::testing::Test {
protected:
    void SetUp() override {
        if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
    }
    // load pass for `record` (client -> server or back), then the Replay read; both must agree
    dissect::SessionTables::DtlsRecordResult open(core::SessionTables &t, const Sealed &record, uint32_t packet, bool fromClient, bool *ok = nullptr) {
        dissect::SessionTables::DtlsRecordResult loaded, replayed;
        const std::string &src = fromClient ? kClient : kServer, &dst = fromClient ? kServer : kClient;
        const uint16_t sport = fromClient ? kClientPort : kServerPort, dport = fromClient ? kServerPort : kClientPort;
        const bool recorded = t.decryptDtlsRecord(packet, 13, src, sport, dst, dport, record.input(), loaded);
        if (ok) *ok = recorded;
        t.freeze();
        t.readDtlsRecord(packet, 13, record.input(), replayed);
        t.unfreeze();
        EXPECT_EQ(replayed.state, loaded.state);
        EXPECT_EQ(replayed.plaintext, loaded.plaintext) << "Replay opens the record again with the stored keys";
        return loaded;
    }
};

TEST_F(DtlsRecords, TheRecordsOfTheScriptDecryptToWhatItSealed) {
    core::SessionTables t;
    prepare(t);
    auto r = open(t, sealed(kClientFinished128), 1, true);
    EXPECT_EQ(r.state, TlsRecordState::Decrypted);
    EXPECT_EQ(support::hexOf(text(r.plaintext)), "1400000c000500000000000ca0a1a2a3a4a5a6a7a8a9aaab");
    r = open(t, sealed(kServerFinished128), 2, false);
    EXPECT_EQ(r.state, TlsRecordState::Decrypted);
    EXPECT_EQ(support::hexOf(text(r.plaintext)).substr(0, 24), "1400000c000600000000000c");
    r = open(t, sealed(kClientData128), 3, true);
    EXPECT_EQ(r.state, TlsRecordState::Decrypted);
    EXPECT_EQ(text(r.plaintext), "hello dtls");
    r = open(t, sealed(kServerData128), 4, false);   // the explicit nonce is the record's own (0102030405060708), not epoch || sequence
    EXPECT_EQ(r.state, TlsRecordState::Decrypted);
    EXPECT_EQ(text(r.plaintext), "pong");
}

TEST_F(DtlsRecords, Aes256GcmUsesTheSha384KeyBlock) {
    core::SessionTables t;
    prepare(t, 0xc030);
    const auto r = open(t, sealed(kClientData256), 1, true);
    EXPECT_EQ(r.state, TlsRecordState::Decrypted);
    EXPECT_EQ(text(r.plaintext), "hello dtls");
    // the 128-bit record under the 256-bit suite is somebody else's key
    EXPECT_EQ(open(t, sealed(kClientData128), 2, true).state, TlsRecordState::TagFailure);
}

TEST_F(DtlsRecords, WrongDirectionWrongMasterAndDamagedRecordsFailTheTagAndShowNoPlaintext) {
    {   // client record opened with the server's keys
        core::SessionTables t;
        prepare(t);
        const auto r = open(t, sealed(kClientData128), 1, false);
        EXPECT_EQ(r.state, TlsRecordState::TagFailure);
        EXPECT_TRUE(r.plaintext.empty());
    }
    {   // another master secret
        core::SessionTables t;
        prepare(t, 0xc02f, 0xfefd, true, std::string(96, 'a'));
        const auto r = open(t, sealed(kClientData128), 1, true);
        EXPECT_EQ(r.state, TlsRecordState::TagFailure);
        EXPECT_TRUE(r.plaintext.empty());
    }
    {   // every bit of the header fields that go into the AAD, the nonce, the ciphertext and the tag matters
        core::SessionTables t;
        prepare(t);
        const Sealed good = sealed(kClientData128);
        for (size_t i = 0; i < good.bytes.size(); ++i) {
            if (i >= 11 && i < 13) continue;   // the record length is not authenticated (the AAD has the plaintext length)
            Sealed bad = good;
            bad.bytes[i] ^= 0x01;
            const auto r = open(t, bad, static_cast<uint32_t>(10 + i), true);
            EXPECT_NE(r.state, TlsRecordState::Decrypted) << "byte " << i;
            EXPECT_TRUE(r.plaintext.empty());
        }
    }
}

TEST_F(DtlsRecords, MissingKeysMissingServerHelloAndUnsupportedSuitesAreToldApart) {
    {   // no key log at all
        core::SessionTables t;
        prepare(t, 0xc02f, 0xfefd, true, "");
        EXPECT_EQ(open(t, sealed(kClientData128), 1, true).state, TlsRecordState::NoKey);
    }
    {   // no session at all
        core::SessionTables t;
        EXPECT_EQ(open(t, sealed(kClientData128), 1, true).state, TlsRecordState::NoKey);
    }
    {   // keys known but the ServerHello was not captured
        core::SessionTables t;
        prepare(t, 0xc02f, 0xfefd, false);
        EXPECT_EQ(open(t, sealed(kClientData128), 1, true).state, TlsRecordState::NoHandshake);
    }
    {   // ChaCha20-Poly1305, CBC, DTLS 1.0 and DTLS 1.3
        for (const std::pair<uint16_t, uint16_t> &c: std::vector<std::pair<uint16_t, uint16_t>>{{0xcca8, 0xfefd}, {0xc027, 0xfefd}, {0xc02f, 0xfeff}, {0xc02f, 0xfefc}}) {
            core::SessionTables t;
            prepare(t, c.first, c.second);
            EXPECT_EQ(open(t, sealed(kClientData128), 1, true).state, TlsRecordState::UnsupportedSuite) << std::hex << c.first << " " << c.second;
        }
    }
    {   // too short to hold an explicit nonce and a tag
        core::SessionTables t;
        prepare(t);
        Sealed tiny = sealed(kClientData128);
        tiny.bytes.resize(13 + 23);
        EXPECT_EQ(open(t, tiny, 1, true).state, TlsRecordState::Malformed);
        tiny.bytes.resize(13);
        EXPECT_EQ(open(t, tiny, 2, true).state, TlsRecordState::Malformed);
    }
}

TEST_F(DtlsRecords, EveryCutRecordIsRejectedWithoutPlaintext) {
    core::SessionTables t;
    prepare(t);
    const Sealed good = sealed(kClientFinished128);
    for (size_t n = 13; n < good.bytes.size(); ++n) {
        Sealed cut = good;
        cut.bytes.resize(n);
        const auto r = open(t, cut, static_cast<uint32_t>(n), true);
        EXPECT_NE(r.state, TlsRecordState::Decrypted) << n;
        EXPECT_TRUE(r.plaintext.empty());
    }
}

TEST_F(DtlsRecords, TheOutcomeBudgetIsEnforcedAndRepliedAsStateLost) {
    core::SessionTables t(600);
    prepare(t);
    bool ok = true;
    int kept = 0;
    for (uint32_t packet = 1; packet < 40 && ok; ++packet) {
        open(t, sealed(kClientData128), packet, true, &ok);
        if (ok) ++kept;
    }
    EXPECT_FALSE(ok);
    EXPECT_TRUE(t.isTableStateLost("dtls"));
    EXPECT_GT(kept, 0);
    dissect::SessionTables::DtlsRecordResult r;
    t.readDtlsRecord(1000, 13, sealed(kClientData128).input(), r);
    EXPECT_EQ(r.state, TlsRecordState::StateLost) << "no outcome and the table lost state: not shown as a missing key";
    core::SessionTables fresh;
    fresh.readDtlsRecord(1000, 13, sealed(kClientData128).input(), r);
    EXPECT_EQ(r.state, TlsRecordState::NoKey);
}

TEST(DtlsRecordsBackend, WithoutOpenSslTheStateSaysSo) {
    if (tls::crypto::available()) GTEST_SKIP() << "this build has OpenSSL";
    core::SessionTables t;
    prepare(t);
    dissect::SessionTables::DtlsRecordResult r;
    const Sealed record = sealed(kClientData128);
    t.decryptDtlsRecord(1, 13, kClient, kClientPort, kServer, kServerPort, record.input(), r);
    EXPECT_EQ(r.state, TlsRecordState::NoBackend);
    EXPECT_TRUE(r.plaintext.empty());
}
