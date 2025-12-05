// TLS decryption end to end: real connections (tests/data/tls, tools/make_tls_fixtures.py) as pcap/pcapng TCP streams go
// through the load pass (reassembly, session tables, decryption) and detail building; the packet summaries and the field
// trees are checked.
//
// Oracles: the plaintext of every connection is known by construction (the generator wrote it and prints it into the .json
// files next to the captures), the key logs are what OpenSSL wrote, and the key log of the wrong-key case is another real
// connection's. Nothing is compared with output of the code under test.
#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

#include <core.h>
#include <dissect/tls_decrypt.h>
#include <tls/crypto.h>

#include "tls_support.h"

using namespace tlstest;
using dissect::TlsRecordState;

namespace {
    const std::string kRequest = "GET /index.html HTTP/1.1\r\nHost: imshark.test\r\n\r\n";      // what tls12.pcapng / tls13.pcapng carry
    const std::string kResponse = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";

    class TlsFlow : public ::testing::Test {
    protected:
        void SetUp() override {
            if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
        }
    };

    std::vector<std::vector<char>> framesOf(const Loaded &cap) {
        std::vector<std::vector<char>> frames;
        for (const auto &p: cap.packets) {
            std::vector<char> bytes;
            EXPECT_TRUE(core::readPacketBytes(cap.path, p, bytes));
            frames.push_back(std::move(bytes));
        }
        return frames;
    }

    // A capture with its own FileProcessor: keys of the user and the table budget can be set before the load.
    struct Cap {
        std::string path, message;
        std::vector<packet::PacketInfo> packets;
        core::FileProcessor fp;
        bool ok = false;

        Cap(const std::vector<char> &bytes, const std::string &name, bool pcapng, const std::string &userKeys = "", size_t budget = 0) {
            path = support::writeTemp(name, bytes);
            if (!userKeys.empty()) fp.sessions().tlsExternalKeys().parseText(userKeys);
            if (budget) fp.sessions().setMaxMemoryPerTable(budget);
            ok = pcapng ? fp.processPcapngFile(path, packets, message) : fp.processPcapFile(path, packets, message);
        }
        ~Cap() { std::remove(path.c_str()); }
        Cap(const Cap &) = delete;

        packet::PacketInfo details(size_t i) {
            packet::PacketInfo d;
            EXPECT_TRUE(core::buildPacketDetails(path, packets[i], d, &packets, &fp.captureInfo(), nullptr, &fp.sessions()));
            return d;
        }
    };

    // the same packets without the Decryption Secrets Block (a classic pcap holds none)
    std::vector<char> pcapOf(const Loaded &cap) { return support::pcapBytes(framesOf(cap)); }

    std::string allText(const std::vector<packet::Field> &fields) {
        std::string out;
        for (const auto &f: fields) out += f.text + "\n" + allText(f.children);
        return out;
    }

    TlsRecordState stateOf(const packet::PacketInfo &p) { return dissect::tlsSummaryState(p); }

    std::vector<size_t> indicesWhere(const std::vector<packet::PacketInfo> &packets, const std::function<bool(const packet::PacketInfo &)> &f) {
        std::vector<size_t> out;
        for (size_t i = 0; i < packets.size(); ++i) if (f(packets[i])) out.push_back(i);
        return out;
    }

    // replay equality: the details of every packet say what the load pass concluded, and every node is inside the frame
    template<typename C>
    void expectReplayEqualsLoad(C &cap) {
        for (size_t i = 0; i < cap.packets.size(); ++i) {
            SCOPED_TRACE("packet " + std::to_string(i + 1));
            const auto d = cap.details(i);
            const auto &s = cap.packets[i];
            EXPECT_EQ(d.protocol, s.protocol);
            EXPECT_EQ(d.info, s.info);
            EXPECT_EQ(d.app_text, s.app_text);
            EXPECT_EQ(d.app_text2, s.app_text2);
            EXPECT_EQ(d.app_type, s.app_type);
            EXPECT_EQ(d.app_flags, s.app_flags);
            EXPECT_EQ(d.app_code, s.app_code);
            EXPECT_EQ(d.app_stream, s.app_stream);
            EXPECT_EQ(d.reassembled_in, s.reassembled_in) << "the TLS decryption summary";
            expectInside(d.fields, d.raw_data.size());
        }
    }

    std::string userKeysFrom(const std::string &keylogOfAnotherConnection, const std::string &anotherRandom, const std::string &thisRandom) {
        std::string text = keylogOfAnotherConnection;
        for (size_t at; (at = text.find(anotherRandom)) != std::string::npos;) text.replace(at, anotherRandom.size(), thisRandom);
        return text;
    }
} // namespace

// ---- HTTP/1.1 over TLS 1.2 and TLS 1.3 -------------------------------------------------------------------------

namespace {
    void checkHttp1OverTls(const char *name) {
        SCOPED_TRACE(name);
        Loaded cap(kDir + name + ".pcapng");
        ASSERT_TRUE(cap.ok) << cap.message;

        const auto requests = indicesWhere(cap.packets, [](const packet::PacketInfo &p) { return p.protocol == "HTTP" && p.app_flags == 0; });
        const auto responses = indicesWhere(cap.packets, [](const packet::PacketInfo &p) { return p.protocol == "HTTP" && p.app_flags == 1; });
        ASSERT_EQ(requests.size(), 1u);
        ASSERT_EQ(responses.size(), 1u);

        // the summary (what the packet list shows) is the inner protocol's
        const auto &req = cap.packets[requests[0]];
        EXPECT_EQ(req.info, "GET /index.html HTTP/1.1");
        EXPECT_EQ(req.app_text, "imshark.test");
        EXPECT_EQ(req.app_text2, "/index.html");
        EXPECT_EQ(req.app_type, 1) << "GET";
        EXPECT_EQ(stateOf(req), TlsRecordState::Decrypted);
        const auto &resp = cap.packets[responses[0]];
        EXPECT_EQ(resp.info, "HTTP/1.1 200 OK");
        EXPECT_EQ(resp.app_code, 200);
        EXPECT_EQ(stateOf(resp), TlsRecordState::Decrypted);

        // the tree: the TLS layer says what happened, the decrypted layer holds the plaintext's size, HTTP follows
        const auto d = cap.details(requests[0]);
        const auto *tls = find(d.fields, "Transport Layer Security");
        ASSERT_NE(tls, nullptr);
        EXPECT_NE(find(tls->children, "Key material: available"), nullptr);
        EXPECT_NE(find(tls->children, "Decryption status: decrypted"), nullptr);
        EXPECT_NE(find(tls->children, "[Expert Info (Chat/Decryption)"), nullptr);
        EXPECT_NE(find(d.fields, "Decrypted TLS (" + std::to_string(kRequest.size()) + " bytes)"), nullptr);
        EXPECT_NE(find(d.fields, "Hypertext Transfer Protocol"), nullptr);
        EXPECT_NE(find(d.fields, "Request Method: GET"), nullptr);
        EXPECT_NE(find(d.fields, "Host: imshark.test"), nullptr);
        expectInside(d.fields, d.raw_data.size());
        // the encrypted bytes stay what they are in the TLS layer, the decrypted nodes have no position in the frame
        const auto *dec = find(d.fields, "Decrypted TLS (");
        ASSERT_NE(dec, nullptr);
        EXPECT_EQ(dec->offset, 0u);
        EXPECT_EQ(dec->length, 0u);

        const auto dr = cap.details(responses[0]);
        EXPECT_NE(find(dr.fields, "Decrypted TLS (" + std::to_string(kResponse.size()) + " bytes)"), nullptr);
        EXPECT_NE(find(dr.fields, "Status Code: 200"), nullptr);
        EXPECT_NE(find(dr.fields, "File Data: 5 bytes"), nullptr);

        // the other protected records are decrypted too (post-handshake messages, the alert) without being HTTP
        size_t decrypted = 0;
        for (const auto &p: cap.packets) if (stateOf(p) == TlsRecordState::Decrypted) ++decrypted;
        EXPECT_GE(decrypted, 4u);
        const auto *alert = [&]() -> const packet::PacketInfo * { for (const auto &p: cap.packets) if (p.info.rfind("Alert", 0) == 0) return &p; return nullptr; }();
        ASSERT_NE(alert, nullptr);
        EXPECT_EQ(alert->protocol, "TLS");
        EXPECT_EQ(alert->info, "Alert (close_notify)");
        EXPECT_FALSE(cap.fp.sessions().hasStateLost());
    }
}

TEST_F(TlsFlow, Http11OverTls12IsDecryptedAndDissected) { checkHttp1OverTls("tls12"); }
TEST_F(TlsFlow, Http11OverTls13IsDecryptedAndDissected) { checkHttp1OverTls("tls13"); }

TEST_F(TlsFlow, ReplayEqualsTheLoadPassForEveryPacket) {
    for (const char *name: {"tls12", "tls13", "tls13_h2", "tls12_raw", "tls13_raw"}) {
        SCOPED_TRACE(name);
        Loaded cap(kDir + name + ".pcapng");
        ASSERT_TRUE(cap.ok) << cap.message;
        expectReplayEqualsLoad(cap);
    }
}

TEST_F(TlsFlow, TheKeysOfThePcapngBlockAreUsedWithoutAnyUserKeys) {
    Loaded cap(kDir + "tls13.pcapng");
    ASSERT_TRUE(cap.ok);
    EXPECT_TRUE(cap.fp.sessions().tlsExternalKeys().empty());
    EXPECT_FALSE(cap.fp.sessions().tlsCaptureKeys().empty());
    EXPECT_NE(std::find_if(cap.packets.begin(), cap.packets.end(), [](const auto &p) { return p.protocol == "HTTP"; }), cap.packets.end());
}

TEST_F(TlsFlow, AKeyLogFileOfTheUserDecryptsACaptureWithoutSecrets) {
    Loaded loaded(kDir + "tls13.pcapng");
    ASSERT_TRUE(loaded.ok);
    const auto bytes = pcapOf(loaded);   // classic pcap: no Decryption Secrets Block
    {   // no keys at all: every protected record says so and shows nothing
        Cap none(bytes, "flow_nokeys.pcap", false);
        ASSERT_TRUE(none.ok);
        size_t noKey = 0;
        for (size_t i = 0; i < none.packets.size(); ++i) {
            EXPECT_NE(none.packets[i].protocol, "HTTP");
            if (stateOf(none.packets[i]) == TlsRecordState::NoKey) ++noKey;
        }
        EXPECT_GE(noKey, 6u);
        const size_t request = indicesWhere(none.packets, [](const auto &p) { return p.info == "Application Data"; }).front();
        const auto d = none.details(request);
        EXPECT_NE(find(d.fields, "Key material: not found"), nullptr);
        EXPECT_NE(find(d.fields, "[Decryption: missing key"), nullptr);
        EXPECT_EQ(find(d.fields, "Decrypted TLS"), nullptr);
        EXPECT_EQ(allText(d.fields).find("GET /index.html"), std::string::npos) << "no plaintext without a key";
        expectReplayEqualsLoad(none);
    }
    {   // the user's key log
        Cap withKeys(bytes, "flow_userkeys.pcap", false, slurp(kDir + "tls13.keys"));
        ASSERT_TRUE(withKeys.ok);
        EXPECT_TRUE(withKeys.fp.sessions().tlsCaptureKeys().empty());
        const auto requests = indicesWhere(withKeys.packets, [](const auto &p) { return p.info == "GET /index.html HTTP/1.1"; });
        ASSERT_EQ(requests.size(), 1u);
        EXPECT_EQ(stateOf(withKeys.packets[requests[0]]), TlsRecordState::Decrypted);
        expectReplayEqualsLoad(withKeys);
    }
}

// ---- HTTP/2 with ALPN h2 over TLS 1.3 -----------------------------------------------------------------------------

TEST_F(TlsFlow, Http2OverTls13WithAlpnH2) {
    const auto doc = testutil::JsonParser(slurp(kDir + "h2.json")).parse();
    Loaded cap(kDir + "tls13_h2.pcapng");
    ASSERT_TRUE(cap.ok) << cap.message;

    const auto *session = cap.fp.sessions().findTlsSession("10.0.0.1", 50000, "10.0.0.2", 443);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->alpn, "h2") << "read from the decrypted EncryptedExtensions of the server";
    EXPECT_EQ(session->inner, dissect::TlsInner::Http2);

    const auto h2 = indicesWhere(cap.packets, [](const auto &p) { return p.protocol == "HTTP2"; });
    const auto &writes = doc.at("writes").items;
    ASSERT_EQ(h2.size(), writes.size()) << "every write of the two ends is one TLS record and one packet";
    for (size_t i = 0; i < h2.size(); ++i) {
        SCOPED_TRACE("write " + std::to_string(i));
        const auto bytes = writes[i].str("bytes");
        const auto d = cap.details(h2[i]);
        EXPECT_EQ(stateOf(cap.packets[h2[i]]), TlsRecordState::Decrypted);
        EXPECT_NE(find(d.fields, "Decrypted TLS (" + std::to_string(bytes.size() / 2) + " bytes)"), nullptr)
            << "the decrypted bytes are exactly what that end wrote";
        EXPECT_NE(find(d.fields, "Hypertext Transfer Protocol 2"), nullptr);
        // client or server: the writer's direction decides who sent the packet
        EXPECT_EQ(cap.packets[h2[i]].dst_port, writes[i].str("who") == "c" ? 443 : 50000);
    }

    // the frames inside: preface + SETTINGS, the GET request on stream 1, the server's SETTINGS / ACK / response / DATA
    EXPECT_EQ(cap.packets[h2[0]].info, "Magic: Connection Preface, SETTINGS: 0 parameter(s)");
    const auto &headers = cap.packets[h2[1]];
    EXPECT_EQ(headers.app_type, 1) << "HEADERS";
    EXPECT_EQ(headers.app_stream, 1u);
    EXPECT_EQ(headers.app_text, "GET");
    EXPECT_EQ(headers.app_text2, "/");
    EXPECT_EQ(cap.packets[h2[4]].app_code, 200) << "the :status of the response HEADERS";
    EXPECT_EQ(cap.packets[h2[5]].info, "DATA[stream 1]: 8 bytes (END_STREAM)");
    EXPECT_NE(find(cap.details(h2[1]).fields, ":authority: imshark.test"), nullptr);
    EXPECT_NE(find(cap.details(h2[4]).fields, ":status: 200"), nullptr);
    EXPECT_NE(find(cap.details(h2[5]).fields, "Data (8 bytes)"), nullptr);
    expectReplayEqualsLoad(cap);
}

TEST_F(TlsFlow, WithoutAlpnTheClientPrefaceDecidesHttp2) {
    Loaded loaded(kDir + "tls13_h2.pcapng");
    ASSERT_TRUE(loaded.ok);
    // only the first application secrets: the server's EncryptedExtensions (handshake keys) cannot be read, so the ALPN is not known
    std::string keys;
    for (const std::string &line: {std::string("CLIENT_TRAFFIC_SECRET_0"), std::string("SERVER_TRAFFIC_SECRET_0")}) {
        std::istringstream in(slurp(kDir + "tls13_h2.keys"));
        for (std::string l; std::getline(in, l);) if (l.rfind(line, 0) == 0) keys += l + "\n";
    }
    ASSERT_FALSE(keys.empty());
    Cap cap(pcapOf(loaded), "flow_noalpn.pcap", false, keys);
    ASSERT_TRUE(cap.ok);
    const auto *session = cap.fp.sessions().findTlsSession("10.0.0.1", 50000, "10.0.0.2", 443);
    ASSERT_NE(session, nullptr);
    EXPECT_EQ(session->alpn, "");
    EXPECT_EQ(session->inner, dissect::TlsInner::Http2) << "sniffed from the client preface";
    const auto h2 = indicesWhere(cap.packets, [](const auto &p) { return p.protocol == "HTTP2"; });
    EXPECT_EQ(h2.size(), 7u);
    EXPECT_EQ(cap.packets[h2[1]].app_text2, "/");
    expectReplayEqualsLoad(cap);
}

// ---- application data that is not HTTP --------------------------------------------------------------------------------

TEST_F(TlsFlow, ApplicationDataThatIsNotHttpIsShownAsBytesWithoutGuessingAProtocol) {
    const auto doc = testutil::JsonParser(slurp(kDir + "raw.json")).parse();
    const size_t clientBytes = doc.str("client").size() / 2, serverBytes = doc.str("server").size() / 2;
    for (const char *name: {"tls12_raw", "tls13_raw"}) {
        SCOPED_TRACE(name);
        Loaded cap(kDir + std::string(name) + ".pcapng");
        ASSERT_TRUE(cap.ok) << cap.message;
        const auto data = indicesWhere(cap.packets, [](const auto &p) { return p.info.rfind("Application Data (decrypted", 0) == 0; });
        ASSERT_EQ(data.size(), 2u);
        EXPECT_EQ(cap.packets[data[0]].protocol, "TLS");
        EXPECT_EQ(cap.packets[data[0]].info, "Application Data (decrypted, " + std::to_string(clientBytes) + " bytes)");
        EXPECT_EQ(cap.packets[data[1]].info, "Application Data (decrypted, " + std::to_string(serverBytes) + " bytes)");
        EXPECT_EQ(stateOf(cap.packets[data[0]]), TlsRecordState::Decrypted);
        const auto d = cap.details(data[0]);
        EXPECT_NE(find(d.fields, "Decrypted TLS (" + std::to_string(clientBytes) + " bytes)"), nullptr);
        EXPECT_NE(find(d.fields, "Protocol: unknown"), nullptr);
        EXPECT_EQ(find(d.fields, "Hypertext Transfer Protocol"), nullptr);
        for (const auto &p: cap.packets) EXPECT_NE(p.protocol, "HTTP");
        expectReplayEqualsLoad(cap);
    }
}

// ---- wrong key, missing key, unsupported suite, state lost ----------------------------------------------------------

TEST_F(TlsFlow, AWrongKeyIsATagFailureAndShowsNoPlaintext) {
    Loaded loaded(kDir + "tls13.pcapng");
    ASSERT_TRUE(loaded.ok);
    // the secrets of another real connection (same cipher suite hash: TLS_AES_256_GCM_SHA384), filed under this client random
    const auto want = expected("tls13");
    const auto doc = testutil::JsonParser(slurp(kDir + "decrypt_tls13.json")).parse();
    std::string other, otherRandom;
    for (const auto &c: doc.at("cases").items) {
        if (c.num("cipher") == 0x1302) { other = c.str("keylog"); otherRandom = c.str("client_random"); }
    }
    ASSERT_FALSE(other.empty());
    ASSERT_EQ(want.num("cipher_suite"), 0x1302);
    Cap cap(pcapOf(loaded), "flow_wrongkey.pcap", false, userKeysFrom(other, otherRandom, want.str("client_random")));
    ASSERT_TRUE(cap.ok);

    size_t failed = 0;
    for (size_t i = 0; i < cap.packets.size(); ++i) {
        const auto &p = cap.packets[i];
        EXPECT_NE(stateOf(p), TlsRecordState::Decrypted) << i;
        EXPECT_NE(p.protocol, "HTTP");
        if (stateOf(p) == TlsRecordState::TagFailure) {
            ++failed;
            const auto d = cap.details(i);
            EXPECT_NE(find(d.fields, "[Decryption: wrong key"), nullptr) << i;
            EXPECT_EQ(find(d.fields, "Decrypted TLS"), nullptr) << i;
            EXPECT_EQ(allText(d.fields).find("GET /index.html"), std::string::npos) << i;
        }
    }
    EXPECT_GE(failed, 6u);
    expectReplayEqualsLoad(cap);
}

TEST_F(TlsFlow, ACipherSuiteOutsideTheSupportedTableIsReportedNotGuessed) {
    Loaded loaded(kDir + "tls12.pcapng");
    ASSERT_TRUE(loaded.ok);
    auto frames = framesOf(loaded);
    const auto want = expected("tls12");
    const auto serverRandom = randomOf(want.str("server_random"));
    size_t patched = 0;
    for (auto &f: frames) {   // the ServerHello names TLS_RSA_WITH_AES_128_CBC_SHA (0x002f): a CBC suite
        auto at = std::search(f.begin(), f.end(), serverRandom.begin(), serverRandom.end(), [](char a, uint8_t b) { return static_cast<uint8_t>(a) == b; });
        if (at == f.end()) continue;
        const size_t sid = static_cast<uint8_t>(*(at + 32));
        *(at + 32 + 1 + sid) = 0x00;
        *(at + 32 + 1 + sid + 1) = 0x2f;
        ++patched;
    }
    ASSERT_EQ(patched, 1u);
    Cap cap(support::pcapBytes(frames), "flow_cbc.pcap", false, slurp(kDir + "tls12.keys"));
    ASSERT_TRUE(cap.ok);
    size_t unsupported = 0;
    for (size_t i = 0; i < cap.packets.size(); ++i) {
        EXPECT_NE(cap.packets[i].protocol, "HTTP");
        if (stateOf(cap.packets[i]) == TlsRecordState::UnsupportedSuite) {
            ++unsupported;
            EXPECT_NE(find(cap.details(i).fields, "[Decryption: unsupported cipher suite"), nullptr);
        }
    }
    EXPECT_GE(unsupported, 4u);
    expectReplayEqualsLoad(cap);
}

TEST_F(TlsFlow, ATableThatRanOutOfRoomSaysStateLostInsteadOfShowingNoKey) {
    Loaded loaded(kDir + "tls13.pcapng");
    ASSERT_TRUE(loaded.ok);
    const size_t needed = loaded.fp.sessions().totalMemoryUsage();
    ASSERT_GT(needed, 0u);
    // enough for the first messages, then the budget of the "tls" table runs out
    const size_t tlsOnly = loaded.fp.sessions().tlsTable().memory();
    Cap cap(pcapOf(loaded), "flow_lost.pcap", false, slurp(kDir + "tls13.keys"), tlsOnly + 100);
    ASSERT_TRUE(cap.ok);
    EXPECT_TRUE(cap.fp.sessions().isTableStateLost("tls"));
    // (the positions of ChangeCipherSpec records are kept without a budget check: at most 16 per connection)
    EXPECT_LE(cap.fp.sessions().totalMemoryUsage(), cap.fp.sessions().maxMemoryPerTable() + 2 * dissect::TlsDirection::kMaxChangeCipherSpecs * sizeof(uint32_t));
    size_t lost = 0;
    bool lostSeen = false;
    for (size_t i = 0; i < cap.packets.size(); ++i) {
        const TlsRecordState state = stateOf(cap.packets[i]);
        EXPECT_NE(state, TlsRecordState::NoKey) << "the key is there";
        EXPECT_NE(state, TlsRecordState::TagFailure);
        if (lostSeen) EXPECT_NE(cap.packets[i].protocol, "HTTP") << "no HTTP once the budget ran out";
        if (state == TlsRecordState::StateLost) {
            ++lost;
            lostSeen = true;
            EXPECT_NE(allText(cap.details(i).fields).find("state lost: too many TLS records"), std::string::npos) << i;
        }
        if (lostSeen) EXPECT_NE(state, TlsRecordState::Decrypted) << "once a record could not be recorded the later ones cannot be numbered";
    }
    EXPECT_GE(lost, 2u);
    expectReplayEqualsLoad(cap);
}

// ---- capture loss ------------------------------------------------------------------------------------------------

namespace {
    uint32_t rawSeq(const std::vector<char> &f) {
        const uint8_t *p = reinterpret_cast<const uint8_t *>(f.data()) + 38;
        return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
    }
    void setRawSeq(std::vector<char> &f, uint32_t v) {
        for (int i = 0; i < 4; ++i) f[38 + i] = static_cast<char>(v >> (24 - 8 * i));
    }
    std::string seqHexOf(uint32_t v) { char b[16]; std::snprintf(b, sizeof b, "%08x", v); return b; }
}

TEST_F(TlsFlow, RecordsAfterLostTcpDataAreCaptureGapNotAWrongKey) {
    Loaded loaded(kDir + "tls13_h2.pcapng");
    ASSERT_TRUE(loaded.ok);
    auto frames = framesOf(loaded);
    const auto h2 = indicesWhere(loaded.packets, [](const auto &p) { return p.protocol == "HTTP2"; });
    ASSERT_EQ(h2.size(), 7u);
    const size_t lostPacket = h2[1], ackPacket = h2[6];   // the client's HEADERS record never reached the capture; its SETTINGS ACK did
    ASSERT_EQ(loaded.packets[ackPacket].src_port, 50000);
    const uint32_t afterHole = rawSeq(frames[ackPacket]);
    // more than the reassembly waits for (1 MB) follows the hole as unrelated bytes, then the capture goes on
    constexpr size_t kJunk = 1400, kCount = 800;
    std::vector<std::vector<char>> out;
    for (size_t i = 0; i < frames.size(); ++i) {
        if (i == lostPacket) continue;
        if (i == ackPacket) {
            for (size_t k = 0; k < kCount; ++k) {
                out.push_back(support::tcpPacket("0a000001", "0a000002", "c350", "01bb", seqHexOf(afterHole + static_cast<uint32_t>(k * kJunk)), "00000000", "18", std::string(kJunk, 'X')));
            }
        }
        if (i >= ackPacket && loaded.packets[i].src_port == 50000) setRawSeq(frames[i], rawSeq(frames[i]) + static_cast<uint32_t>(kJunk * kCount));
        out.push_back(frames[i]);
    }
    Cap cap(support::pcapBytes(out), "flow_gap.pcap", false, slurp(kDir + "tls13_h2.keys"));
    ASSERT_TRUE(cap.ok);

    const auto *session = cap.fp.sessions().findTlsSession("10.0.0.1", 50000, "10.0.0.2", 443);
    ASSERT_NE(session, nullptr);
    EXPECT_TRUE(session->client()->gap) << "the client direction lost data";
    EXPECT_FALSE(session->server()->gap);
    size_t gap = 0, wrong = 0;
    for (size_t i = 0; i < cap.packets.size(); ++i) {
        if (stateOf(cap.packets[i]) == TlsRecordState::CaptureGap) {
            ++gap;
            EXPECT_NE(find(cap.details(i).fields, "[Decryption: not decrypted: data of this direction is missing"), nullptr);
        }
        if (stateOf(cap.packets[i]) == TlsRecordState::TagFailure) ++wrong;
    }
    EXPECT_GE(gap, 1u) << "the records after the hole cannot be numbered";
    EXPECT_EQ(wrong, 0u);
    // the server direction is intact: its responses are still HTTP/2
    EXPECT_NE(std::find_if(cap.packets.begin(), cap.packets.end(), [](const auto &p) { return p.protocol == "HTTP2" && p.src_port == 443 && p.app_code == 200; }),
              cap.packets.end());
    expectReplayEqualsLoad(cap);
}

// ---- truncation and mutation sweeps -------------------------------------------------------------------------------------

namespace {
    // a classic pcap whose frame `cutIndex` was captured only up to `cut` bytes (the wire length is kept)
    std::vector<char> pcapWithCut(const std::vector<std::vector<char>> &frames, size_t cutIndex, size_t cut) {
        std::vector<char> f;
        support::put<uint32_t>(f, 0xa1b2c3d4);
        support::put<uint16_t>(f, 2);
        support::put<uint16_t>(f, 4);
        support::put<int32_t>(f, 0);
        support::put<uint32_t>(f, 0);
        support::put<uint32_t>(f, 65535);
        support::put<uint32_t>(f, 1);
        uint32_t t = 0;
        for (size_t i = 0; i < frames.size(); ++i, ++t) {
            const size_t incl = i == cutIndex ? std::min(cut, frames[i].size()) : frames[i].size();
            support::put<uint32_t>(f, 1700000000 + t / 1000);
            support::put<uint32_t>(f, (t % 1000) * 1000);
            support::put<uint32_t>(f, static_cast<uint32_t>(incl));
            support::put<uint32_t>(f, static_cast<uint32_t>(frames[i].size()));
            f.insert(f.end(), frames[i].begin(), frames[i].begin() + static_cast<std::ptrdiff_t>(incl));
        }
        return f;
    }
}

TEST_F(TlsFlow, EveryCutOfAProtectedPacketLoadsAndShowsNoPlaintextItCouldNotHave) {
    for (const char *name: {"tls13_h2", "tls12"}) {
        SCOPED_TRACE(name);
        Loaded loaded(kDir + std::string(name) + ".pcapng");
        ASSERT_TRUE(loaded.ok);
        const auto frames = framesOf(loaded);
        const std::string keys = slurp(kDir + std::string(name == std::string("tls12") ? "tls12" : "tls13_h2") + ".keys");
        // one application data packet of the client
        const auto candidates = indicesWhere(loaded.packets, [](const auto &p) { return (p.protocol == "HTTP2" || p.protocol == "HTTP") && p.src_port == 50000; });
        ASSERT_FALSE(candidates.empty());
        const size_t victim = candidates.front();
        size_t decryptedWhole = 0;
        for (size_t cut = 0; cut <= frames[victim].size(); ++cut) {
            Cap cap(pcapWithCut(frames, victim, cut), "flow_cut.pcap", false, keys);
            ASSERT_TRUE(cap.ok) << cut;
            ASSERT_EQ(cap.packets.size(), frames.size());
            for (size_t i = 0; i < cap.packets.size(); ++i) {
                const auto d = cap.details(i);
                expectInside(d.fields, d.raw_data.size());
                // a state other than Decrypted never comes with plaintext
                if (stateOf(cap.packets[i]) != TlsRecordState::Decrypted) EXPECT_EQ(find(d.fields, "Decrypted TLS"), nullptr) << cut << " " << i;
                if (stateOf(cap.packets[i]) == TlsRecordState::TagFailure) ADD_FAILURE() << "a cut must not look like a wrong key: " << cut << " " << i;
            }
            if (stateOf(cap.packets[victim]) == TlsRecordState::Decrypted) ++decryptedWhole;
            if (cut == frames[victim].size()) EXPECT_EQ(stateOf(cap.packets[victim]), TlsRecordState::Decrypted);
        }
        EXPECT_GE(decryptedWhole, 1u) << "the uncut frame decrypts";
    }
}

TEST_F(TlsFlow, ADamagedRecordNeverYieldsPlaintext) {
    Loaded loaded(kDir + "tls13.pcapng");
    ASSERT_TRUE(loaded.ok);
    const auto frames = framesOf(loaded);
    const auto requests = indicesWhere(loaded.packets, [](const auto &p) { return p.info == "GET /index.html HTTP/1.1"; });
    ASSERT_EQ(requests.size(), 1u);
    const size_t victim = requests[0];
    const std::string keys = slurp(kDir + "tls13.keys");
    const size_t payload = loaded.packets[victim].payload_offset;
    for (size_t at = payload; at < frames[victim].size(); ++at) {
        auto damaged = frames;
        damaged[victim][at] = static_cast<char>(damaged[victim][at] ^ 0x5a);
        Cap cap(support::pcapBytes(damaged), "flow_flip.pcap", false, keys);
        ASSERT_TRUE(cap.ok) << at;
        const auto d = cap.details(victim);
        expectInside(d.fields, d.raw_data.size());
        EXPECT_EQ(allText(d.fields).find("GET /index.html"), std::string::npos) << "byte " << at << " flipped";
        EXPECT_NE(cap.packets[victim].info, "GET /index.html HTTP/1.1") << at;
    }
}

TEST_F(TlsFlow, KeysThatChangeBetweenLoadsApplyToTheNextLoadOnly) {
    Loaded loaded(kDir + "tls13.pcapng");
    ASSERT_TRUE(loaded.ok);
    const auto bytes = pcapOf(loaded);
    const std::string path = support::writeTemp("flow_reload.pcap", bytes);
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(fp.processPcapFile(path, packets, message));
    EXPECT_EQ(std::count_if(packets.begin(), packets.end(), [](const auto &p) { return p.protocol == "HTTP"; }), 0);

    fp.sessions().tlsExternalKeys().parseText(slurp(kDir + "tls13.keys"));   // what the key log setting does, then a reload
    packets.clear();
    ASSERT_TRUE(fp.processPcapFile(path, packets, message));
    EXPECT_EQ(std::count_if(packets.begin(), packets.end(), [](const auto &p) { return p.protocol == "HTTP"; }), 2);

    fp.sessions().tlsExternalKeys().clear();                                // the setting was cleared
    packets.clear();
    ASSERT_TRUE(fp.processPcapFile(path, packets, message));
    EXPECT_EQ(std::count_if(packets.begin(), packets.end(), [](const auto &p) { return p.protocol == "HTTP"; }), 0);
    std::remove(path.c_str());
}
