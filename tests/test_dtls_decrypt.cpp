// DTLS 1.2 AES-GCM decryption through the whole pipeline: a capture of hand-built datagrams (ClientHello, ServerHello, sealed
// Finished and application data records) is loaded with a key log, and the packets are checked for what the load pass decided
// and what detail building (Replay) shows.
//
// Oracle for the sealed records: tools/make_dtls_vectors.py. It implements AES and GCM from FIPS 197 / NIST SP 800-38D (checked
// against NIST GCM test cases 4 and 16 before it prints anything), computes the TLS 1.2 PRF with hmac/hashlib (compared with
// `openssl kdf ... TLS1-PRF`) and seals the records the way RFC 6347 section 4.1.2.1 and RFC 5288 section 3 describe. Master
// secret 30..5f, client random 00..1f, server random 80..9f, so the key log line below is the only secret in play. The code
// under test derives its keys and opens the records on its own; the expected plaintext is what the script sealed.
#include <gtest/gtest.h>

#include <memory>
#include <span>
#include <string>
#include <vector>

#include <core.h>
#include <filter/filter.h>
#include <stats/statistics.h>
#include <dissect/dtls_decrypt.h>
#include <dissect/tls_summary.h>
#include <tls/crypto.h>

#include "dtls_support.h"
#include "tls_support.h"

namespace {
    using namespace dtlstest;
    using dissect::TlsRecordState;

    const std::string kKeyLog = "CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f "
                                "303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f\n";
    const std::string kWrongKeyLog = "CLIENT_RANDOM 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f " + std::string(96, 'a') + "\n";

    // AES-128-GCM (0xc02f), from the script
    const char *kClientFinished = "16fefd000100000000000000300001000000000000c6a8ad73ecd5afdde9d4a2edc0ae40825b142c04b23792f28b20e02494684548e4609f4301f9bbd5";
    const char *kServerFinished = "16fefd0001000000000000003000010000000000003643077842771539658f10892b81d95ff8bdc6dbd31a90767980029fbb0066371406f4eea4d8136a";
    const char *kClientData = "17fefd00010000000000010022000100000000000182b4a773227fb79930def22b0edf1304ef570a5cdb8a7a3f8c03";
    const char *kServerData = "17fefd0001000000000005001c010203040506070855316e6b2387c5e39ded9f0bf09055ae3537557b";
    // AES-256-GCM (0xc030)
    const char *kClientData256 = "17fefd0001000000000001002200010000000000015d17152edb2d41b227b48295d924a33b4714d563ed331b339a5f";

    std::string bytes(const char *hexText) {
        const auto v = support::hex(hexText);
        return std::string(v.begin(), v.end());
    }

    // 1 ClientHello, 2 ServerHello, 3 client Finished, 4 server Finished, 5 client data, 6 server data
    std::vector<std::vector<char>> flow(uint16_t cipher = 0xc02f, bool serverHello = true) {
        std::vector<std::vector<char>> f;
        f.push_back(toServer(hsRecord(0, handshake(1, 0, clientHelloBody("", "example.test")))));
        if (serverHello) f.push_back(toClient(hsRecord(0, handshake(2, 1, serverHelloBody(cipher)))));
        else f.push_back(toClient(hsRecord(0, handshake(14, 1, ""))));
        f.push_back(toServer(bytes(kClientFinished)));
        f.push_back(toClient(bytes(kServerFinished)));
        f.push_back(toServer(bytes(kClientData)));
        f.push_back(toClient(bytes(kServerData)));
        return f;
    }

    struct Cap {
        std::string path, message;
        std::vector<packet::PacketInfo> packets;
        core::FileProcessor fp;
        bool ok = false;
        Cap(const std::vector<std::vector<char>> &frames, const std::string &name, const std::string &keys = kKeyLog, size_t budget = 0) {
            path = support::writeTemp("dtlsdec_" + name + ".pcap", support::pcapBytes(frames));
            if (!keys.empty()) fp.sessions().tlsExternalKeys().parseText(keys);
            if (budget) fp.sessions().setMaxMemoryPerTable(budget);
            ok = fp.processPcapFile(path, packets, message);
        }
        ~Cap() { std::remove(path.c_str()); }
        Cap(const Cap &) = delete;
        packet::PacketInfo details(size_t i) {
            packet::PacketInfo d;
            EXPECT_TRUE(core::buildPacketDetails(path, packets[i], d, &packets, &fp.captureInfo(), nullptr, &fp.sessions()));
            return d;
        }
    };

    std::string textOf(const std::vector<packet::Field> &fields) {
        std::string out;
        for (const auto &f: fields) out += f.text + "\n" + textOf(f.children);
        return out;
    }

    // the plaintext the script sealed (tools/make_dtls_vectors.py): finished(msg_seq) and the two application data strings
    std::string finishedPlain(uint8_t messageSeq) {
        std::string p = std::string("\x14\x00\x00\x0c\x00", 5) + static_cast<char>(messageSeq) + std::string("\x00\x00\x00\x00\x00\x0c", 6);
        for (int i = 0; i < 12; ++i) p += static_cast<char>(0xa0 + i);
        return p;
    }
    const std::string kHelloPlain = "hello dtls", kPongPlain = "pong";

    // what Replay reads back for the record `sealed` (a whole record at `position` of packet i's UDP payload): its state and plaintext
    struct Opened {
        TlsRecordState state;
        std::string plain;
    };
    Opened openedRecord(Cap &cap, size_t i, const std::string &sealed, uint16_t position = 0) {
        Opened o{TlsRecordState::NoKey, {}};
        if (sealed.size() < 13) return o;
        const auto u = [&](size_t at, size_t n) { uint64_t v = 0; for (size_t k = 0; k < n; ++k) v = v << 8 | static_cast<uint8_t>(sealed[at + k]); return v; };
        const std::string body = sealed.substr(13);
        dissect::DtlsRecordInput in;
        in.type = static_cast<uint8_t>(sealed[0]);
        in.version = static_cast<uint16_t>(u(1, 2));
        in.epoch = static_cast<uint16_t>(u(3, 2));
        in.sequence = u(5, 6);
        in.fragment = std::span<const uint8_t>(reinterpret_cast<const uint8_t *>(body.data()), body.size());
        dissect::SessionTables::DtlsRecordResult r;
        cap.fp.sessions().readDtlsRecord(static_cast<uint32_t>(i + 1), position, in, r);
        o.state = r.state;
        o.plain.assign(r.plaintext.begin(), r.plaintext.end());
        return o;
    }

    // nothing of the sealed plaintext may reach the packet: neither the bytes Replay reads back nor any text the plaintext would
    // produce (the string "hello dtls", "pong", the decoded Finished handshake or the decrypted layers) in the Info or the tree
    void expectNoPlaintext(Cap &cap, size_t i, const std::string &treeText) {
        static const char *sealed[] = {kClientFinished, kServerFinished, kClientData, kServerData};
        const Opened o = openedRecord(cap, i, bytes(sealed[i - 2]));
        EXPECT_NE(o.state, TlsRecordState::Decrypted) << i;
        EXPECT_TRUE(o.plain.empty()) << i;
        for (const std::string &text: {treeText, cap.packets[i].info})
            for (const char *known: {"hello dtls", "pong", "Decrypted DTLS", "Decrypted Handshake", "Decrypted Application Data", "Handshake Type: Finished (20)", "Finished (decrypted)"})
                EXPECT_EQ(text.find(known), std::string::npos) << i << ": " << known;
    }

    // what the load pass concluded and what Replay shows must be the same
    void expectReplayEqualsLoad(Cap &cap) {
        for (size_t i = 0; i < cap.packets.size(); ++i) {
            const auto d = cap.details(i);
            EXPECT_EQ(d.info, cap.packets[i].info) << i;
            EXPECT_EQ(d.protocol, cap.packets[i].protocol) << i;
            EXPECT_EQ(d.reassembled_in, cap.packets[i].reassembled_in) << i;
            EXPECT_EQ(d.app_code, cap.packets[i].app_code) << i;
            EXPECT_EQ(d.app_text, cap.packets[i].app_text) << i;
            tlstest::expectInside(d.fields, d.raw_data.size());
        }
    }
} // namespace

class DtlsFlow : public ::testing::Test {
protected:
    void SetUp() override {
        if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
    }
};

TEST_F(DtlsFlow, TheRecordsDecryptAndThePacketsSayWhatTheyHold) {
    Cap cap(flow(), "ok");
    ASSERT_TRUE(cap.ok) << cap.message;
    ASSERT_EQ(cap.packets.size(), 6u);
    EXPECT_EQ(cap.packets[0].info, "Client Hello (SNI=example.test)");
    EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[0]), TlsRecordState::Clear);
    EXPECT_EQ(cap.packets[1].info, "Server Hello (TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256)");
    EXPECT_EQ(cap.packets[2].info, "Finished (decrypted)");
    EXPECT_EQ(cap.packets[3].info, "Finished (decrypted)");
    EXPECT_EQ(cap.packets[4].info, "Application Data (decrypted, 10 bytes)");
    EXPECT_EQ(cap.packets[5].info, "Application Data (decrypted, 4 bytes)");
    for (size_t i = 2; i < 6; ++i) {
        EXPECT_EQ(cap.packets[i].protocol, "DTLS");
        EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[i]), TlsRecordState::Decrypted) << i;
    }

    auto d = cap.details(4);
    const std::string t = textOf(d.fields);
    EXPECT_NE(t.find("Decrypted DTLS (10 bytes)"), std::string::npos) << t;
    EXPECT_NE(t.find("Decrypted Application Data (10 bytes)"), std::string::npos);
    EXPECT_NE(t.find("Decryption status: decrypted"), std::string::npos);
    EXPECT_NE(t.find("[Expert Info (Chat/Decryption): DTLS records decrypted with the key log]"), std::string::npos);
    EXPECT_NE(t.find("Key material: available (TLS 1.2 master secret)"), std::string::npos);
    EXPECT_NE(t.find("[DTLS session: client to server, DTLS 1.2]"), std::string::npos);
    EXPECT_NE(t.find("Explicit Nonce: 8 bytes"), std::string::npos);
    auto fin = cap.details(2);
    const std::string ft = textOf(fin.fields);
    EXPECT_NE(ft.find("Decrypted Handshake Protocol (24 bytes)"), std::string::npos) << ft;
    EXPECT_NE(ft.find("Handshake Type: Finished (20)"), std::string::npos);
    EXPECT_NE(ft.find("Message Sequence: 5"), std::string::npos);
    EXPECT_NE(textOf(cap.details(3).fields).find("[DTLS session: server to client, DTLS 1.2]"), std::string::npos);
    // the bytes the records open to are the ones the script sealed
    const std::string sealed[4] = {bytes(kClientFinished), bytes(kServerFinished), bytes(kClientData), bytes(kServerData)};
    const std::string expected[4] = {finishedPlain(5), finishedPlain(6), kHelloPlain, kPongPlain};
    for (size_t k = 0; k < 4; ++k) {
        const Opened o = openedRecord(cap, k + 2, sealed[k]);
        EXPECT_EQ(o.state, TlsRecordState::Decrypted) << k;
        EXPECT_EQ(o.plain, expected[k]) << k;
    }
    expectReplayEqualsLoad(cap);
}

TEST_F(DtlsFlow, WithoutAKeyTheRecordsStayEncryptedAndNoPlaintextAppears) {
    Cap cap(flow(), "nokey", "");
    ASSERT_TRUE(cap.ok) << cap.message;
    for (size_t i = 2; i < 6; ++i) {
        EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[i]), TlsRecordState::NoKey) << i;
        const auto d = cap.details(i);
        const std::string t = textOf(d.fields);
        expectNoPlaintext(cap, i, t);
        EXPECT_NE(t.find("Decryption status: missing key"), std::string::npos) << t;
        EXPECT_NE(t.find("Key material: not found"), std::string::npos);
    }
    EXPECT_EQ(cap.packets[2].info, "Encrypted Handshake Message");
    EXPECT_EQ(cap.packets[4].info, "Application Data");
    expectReplayEqualsLoad(cap);
}

TEST_F(DtlsFlow, AWrongKeyIsATagFailureAndShowsNothing) {
    Cap cap(flow(), "wrongkey", kWrongKeyLog);
    ASSERT_TRUE(cap.ok) << cap.message;
    for (size_t i = 2; i < 6; ++i) {
        EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[i]), TlsRecordState::TagFailure) << i;
        const auto d = cap.details(i);
        const std::string t = textOf(d.fields);
        EXPECT_NE(t.find("Decryption status: wrong key"), std::string::npos) << t;
        EXPECT_NE(t.find("[Expert Info (Warning/Decryption): "), std::string::npos);
        expectNoPlaintext(cap, i, t);
    }
    EXPECT_EQ(cap.packets[4].info, "Application Data");
    expectReplayEqualsLoad(cap);
}

TEST_F(DtlsFlow, AMissingServerHelloAndAnUnsupportedSuiteAreToldApart) {
    {
        Cap cap(flow(0xc02f, false), "nohello");
        ASSERT_TRUE(cap.ok);
        EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[4]), TlsRecordState::NoHandshake);
        EXPECT_NE(textOf(cap.details(4).fields).find("the ServerHello was not captured"), std::string::npos);
        expectReplayEqualsLoad(cap);
    }
    {   // ChaCha20-Poly1305
        Cap cap(flow(0xcca8), "chacha");
        ASSERT_TRUE(cap.ok);
        EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[4]), TlsRecordState::UnsupportedSuite);
        EXPECT_NE(textOf(cap.details(4).fields).find("unsupported cipher suite"), std::string::npos);
        expectReplayEqualsLoad(cap);
    }
}

TEST_F(DtlsFlow, Aes256GcmWithTheSha384Prf) {
    auto frames = flow(0xc030);
    frames[4] = toServer(bytes(kClientData256));
    Cap cap(frames, "aes256");
    ASSERT_TRUE(cap.ok);
    EXPECT_EQ(cap.packets[4].info, "Application Data (decrypted, 10 bytes)");
    EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[4]), TlsRecordState::Decrypted);
    EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[2]), TlsRecordState::TagFailure) << "the 128-bit Finished under the 256-bit suite";
    const Opened o = openedRecord(cap, 4, bytes(kClientData256));
    EXPECT_EQ(o.state, TlsRecordState::Decrypted);
    EXPECT_EQ(o.plain, kHelloPlain);
    EXPECT_TRUE(openedRecord(cap, 2, bytes(kClientFinished)).plain.empty());
    expectReplayEqualsLoad(cap);
}

TEST_F(DtlsFlow, ADatagramCarryingASealedRecordAfterClearOnesKeepsBothStates) {
    // ChangeCipherSpec (epoch 0) and the sealed Finished (epoch 1) in one datagram, the way a client sends them
    auto frames = flow();
    frames[2] = toServer(record(20, 0xfefd, 0, 2, "\x01") + bytes(kClientFinished));
    Cap cap(frames, "mixed");
    ASSERT_TRUE(cap.ok);
    EXPECT_EQ(cap.packets[2].info, "Change Cipher Spec, Finished (decrypted)");
    EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[2]), TlsRecordState::Decrypted);
    const Opened o = openedRecord(cap, 2, bytes(kClientFinished), 14);       // after the 13 byte header and 1 byte of the ChangeCipherSpec
    EXPECT_EQ(o.state, TlsRecordState::Decrypted);
    EXPECT_EQ(o.plain, finishedPlain(5));
    expectReplayEqualsLoad(cap);
}

TEST_F(DtlsFlow, ADecryptedMessageOfTheOtherDirectionIsNotMixedUp) {
    // the server's Finished sent in the client's direction fails: the write keys are per direction
    auto frames = flow();
    frames[3] = toServer(bytes(kServerFinished));
    Cap cap(frames, "direction");
    ASSERT_TRUE(cap.ok);
    EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[3]), TlsRecordState::TagFailure);
    EXPECT_EQ(cap.packets[3].info, "Encrypted Handshake Message");
    const Opened o = openedRecord(cap, 3, bytes(kServerFinished));
    EXPECT_NE(o.state, TlsRecordState::Decrypted);
    EXPECT_TRUE(o.plain.empty());
}

TEST_F(DtlsFlow, ATableThatRanOutOfRoomReportsStateLostNotAMissingKey) {
    Cap cap(flow(), "lost", kKeyLog, 700);
    ASSERT_TRUE(cap.ok);
    EXPECT_TRUE(cap.fp.sessions().isTableStateLost("dtls"));
    bool sawLost = false;
    for (const auto &p: cap.packets) sawLost = sawLost || dissect::dtlsSummaryState(p) == TlsRecordState::StateLost;
    EXPECT_TRUE(sawLost);
    for (size_t i = 0; i < cap.packets.size(); ++i) {
        const auto d = cap.details(i);
        EXPECT_EQ(d.reassembled_in, cap.packets[i].reassembled_in) << i;
        EXPECT_EQ(d.info, cap.packets[i].info) << i;
    }
}

TEST_F(DtlsFlow, EveryCutAndEveryDamagedByteOfASealedRecordNeverShowsWrongPlaintext) {
    for (const char *sealed: {kClientFinished, kClientData}) {
        const std::string good = bytes(sealed);
        std::vector<std::vector<char>> frames = flow();
        frames.resize(2);                     // the hellos, then every variant of the record
        for (size_t n = 0; n <= good.size(); ++n) frames.push_back(toServer(good.substr(0, n)));
        for (size_t i = 0; i < good.size(); ++i) {
            std::string bad = good;
            bad[i] = static_cast<char>(bad[i] ^ 0x5a);
            frames.push_back(toServer(bad));
        }
        Cap cap(frames, "sweep");
        ASSERT_TRUE(cap.ok);
        const bool isData = sealed == kClientData;
        const std::string expected = isData ? kHelloPlain : finishedPlain(5);
        const std::string known = isData ? "hello dtls" : "Handshake Type: Finished (20)";
        for (size_t i = 2; i < cap.packets.size(); ++i) {
            const auto d = cap.details(i);
            tlstest::expectInside(d.fields, d.raw_data.size());
            EXPECT_EQ(d.info, cap.packets[i].info) << i;
            EXPECT_EQ(d.reassembled_in, cap.packets[i].reassembled_in) << i;
            const size_t firstCut = 2, firstFlip = 3 + good.size();
            const bool decrypted = dissect::dtlsSummaryState(cap.packets[i]) == TlsRecordState::Decrypted;
            if (i < firstCut + good.size()) {                               // cut: the tag cannot be checked, nothing is shown
                EXPECT_FALSE(decrypted) << "cut to " << i - firstCut << " bytes";
            } else if (i >= firstFlip) {
                // the tag authenticates every byte but the record length (11, 12); a flip there leaves a record that is cut or has
                // trailing bytes
                const size_t flipped = i - firstFlip;
                if (flipped != 11 && flipped != 12) EXPECT_FALSE(decrypted) << "byte " << flipped << " changed but the record decrypted";
            } else {
                EXPECT_TRUE(decrypted) << "the unchanged record";
            }
            // the variant of this packet, as sent
            const size_t variant = i - firstCut;
            std::string sent = good;
            if (variant < good.size() + 1) sent = good.substr(0, variant);
            else if (i >= firstFlip) sent[i - firstFlip] = static_cast<char>(sent[i - firstFlip] ^ 0x5a);
            const Opened o = openedRecord(cap, i, sent);
            if (decrypted) {
                if (i == firstCut + good.size()) EXPECT_EQ(o.plain, expected) << "the unchanged record";
            } else {
                EXPECT_TRUE(o.plain.empty()) << i;
                EXPECT_EQ(textOf(d.fields).find(known), std::string::npos) << i;
                EXPECT_EQ(cap.packets[i].info.find("decrypted"), std::string::npos) << i;
            }
        }
    }
}

namespace {
    size_t countMatching(const std::vector<packet::PacketInfo> &packets, const std::string &expression) {
        auto compiled = filter::Filter::compile(expression);
        EXPECT_TRUE(compiled.ok) << expression << ": " << compiled.error.message;
        size_t n = 0;
        if (compiled.ok) for (const auto &p: packets) if (compiled.filter.matches(p)) ++n;
        return n;
    }

    uint64_t expertCount(const std::vector<packet::PacketInfo> &packets, const std::string &summary) {
        for (const auto &item: stats::expertInfo(packets, nullptr)) if (item.summary == summary) return item.count;
        return 0;
    }
} // namespace

TEST_F(DtlsFlow, TheDecryptionFieldsAndTheExpertInformationFollowTheStates) {
    {
        Cap cap(flow(), "fields");
        ASSERT_TRUE(cap.ok);
        EXPECT_EQ(countMatching(cap.packets, "dtls.decrypted"), 4u) << "dtls.decrypted is false for the hellos and true for the four sealed records";
        EXPECT_EQ(countMatching(cap.packets, "dtls.decrypted == 1"), 4u);
        EXPECT_EQ(countMatching(cap.packets, "dtls.decryption_status == \"decrypted\""), 4u);
        EXPECT_EQ(countMatching(cap.packets, "dtls.decryption_status"), 4u) << "only packets with protected records have a status";
        EXPECT_EQ(countMatching(cap.packets, "dtls.record.epoch == 1"), 4u);
        EXPECT_EQ(countMatching(cap.packets, "dtls.record.sequence_number == 5"), 1u);
        EXPECT_EQ(expertCount(cap.packets, "DTLS: records decrypted with the key log"), 4u);
        // the hierarchy is UDP -> DTLS for these packets (no inner protocol is dissected)
        const stats::HierarchyNode root = stats::protocolHierarchy(cap.packets, nullptr);
        bool found = false;
        std::vector<const stats::HierarchyNode *> stack = {&root};
        while (!stack.empty()) {
            const auto *n = stack.back();
            stack.pop_back();
            if (n->name == "Datagram Transport Layer Security") { found = true; EXPECT_EQ(n->packets, 6u); }
            for (const auto &c: n->children) stack.push_back(&c);
        }
        EXPECT_TRUE(found);
    }
    {
        Cap cap(flow(), "fieldswrong", kWrongKeyLog);
        ASSERT_TRUE(cap.ok);
        EXPECT_EQ(countMatching(cap.packets, "dtls.decryption_status == \"tag_failure\""), 4u);
        EXPECT_EQ(countMatching(cap.packets, "dtls.decrypted == 1"), 0u);
        EXPECT_EQ(expertCount(cap.packets, "DTLS: wrong key (the authentication tag of a record does not match)"), 4u);
    }
    {
        Cap cap(flow(), "fieldsnokey", "");
        ASSERT_TRUE(cap.ok);
        EXPECT_EQ(countMatching(cap.packets, "dtls.decryption_status == \"no_key\""), 4u);
        EXPECT_EQ(expertCount(cap.packets, "DTLS: no key material for the connection"), 4u);
    }
}

namespace {
    // Ethernet + IPv4 fragment of payload[offset, offset + len) (the offset field counts 8 byte units)
    std::vector<char> ipFragment(const std::string &payload, size_t offset, size_t len, uint16_t id, bool more) {
        char head[160];
        const uint16_t field = static_cast<uint16_t>((more ? 0x2000 : 0) | (offset / 8));
        std::snprintf(head, sizeof head, "001122334455 aabbccddeeff 0800 4500%04zx %04x %04x 40110000 0a000001 0a000002", 20 + len, id, field);
        auto frame = support::hex(head);
        frame.insert(frame.end(), payload.begin() + static_cast<long>(offset), payload.begin() + static_cast<long>(offset + len));
        return frame;
    }
} // namespace

TEST_F(DtlsFlow, ASealedRecordInAnIpFragmentedDatagramIsDecryptedAtTheLastFragment) {
    auto frames = flow();
    const std::string record = bytes(kClientData);                     // 13 + 34 bytes
    const std::string datagram = be(kClientPort, 2) + be(kServerPort, 2) + be(8 + record.size(), 2) + be(0, 2) + record;   // UDP header + DTLS
    ASSERT_GT(datagram.size(), 40u);
    frames[4] = ipFragment(datagram, 0, 24, 0x4242, true);
    frames.insert(frames.begin() + 5, ipFragment(datagram, 24, datagram.size() - 24, 0x4242, false));
    Cap cap(frames, "ipfrag");
    ASSERT_TRUE(cap.ok) << cap.message;
    ASSERT_EQ(cap.packets.size(), 7u);
    EXPECT_EQ(cap.packets[4].ip_frag, 1u);
    EXPECT_EQ(cap.packets[5].ip_frag, 2u);
    EXPECT_EQ(cap.packets[5].protocol, "DTLS");
    EXPECT_EQ(cap.packets[5].info, "Application Data (decrypted, 10 bytes)");
    EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[5]), TlsRecordState::Decrypted);
    const auto d = cap.details(5);
    EXPECT_EQ(d.info, cap.packets[5].info);
    EXPECT_EQ(d.reassembled_in, cap.packets[5].reassembled_in);
    EXPECT_NE(textOf(d.fields).find("Decrypted Application Data (10 bytes)"), std::string::npos);
    const Opened o = openedRecord(cap, 5, bytes(kClientData));
    EXPECT_EQ(o.state, TlsRecordState::Decrypted);
    EXPECT_EQ(o.plain, kHelloPlain);
}

TEST(DtlsFlowNoBackend, WithoutOpenSslTheStateSaysDecryptionIsNotAvailable) {
    if (tls::crypto::available()) GTEST_SKIP() << "this build has OpenSSL";
    Cap cap(flow(), "nobackend");
    ASSERT_TRUE(cap.ok);
    EXPECT_EQ(dissect::dtlsSummaryState(cap.packets[4]), TlsRecordState::NoBackend);
    EXPECT_NE(textOf(cap.details(4).fields).find("no OpenSSL"), std::string::npos);
}
