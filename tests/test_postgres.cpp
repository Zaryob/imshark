// PostgreSQL frontend/backend protocol 3.0: the messages are packed with Python's struct module following the formats of
// https://www.postgresql.org/docs/current/protocol-message-formats.html (StartupMessage "Int32 length, Int32 196608, name/value
// pairs, 0"; SSLRequest 00 00 00 08 04 d2 16 2f as the documentation spells it; typed messages "Byte1 type, Int32 length
// (counting itself), body"). The independent oracle is that document plus Python's own encoder, not the dissector.
#include <gtest/gtest.h>

#include <core.h>
#include <dissect/postgres.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kSsl = bytes("0000000804d2162f");
    const std::string kGss = bytes("0000000804d21630");
    const std::string kCancel = bytes("0000001004d2162e0000109211223344");
    const std::string kStartup = bytes("00000038000300007573657200616c6963650064617461626173650073686f70"
        "006170706c69636174696f6e5f6e616d65007073716c0000");
    const std::string kAuthOk = bytes("520000000800000000");
    const std::string kAuthMd5 = bytes("520000000c00000005a1b2c3d4");
    const std::string kAuthSasl = bytes("52000000170000000a534352414d2d5348412d3235360000");
    const std::string kPass = bytes("70000000286d6435643431643863643938663030623230346539383030393938"
        "656366383432376500");
    const std::string kParamStatus = bytes("53000000187365727665725f76657273696f6e0031352e3400");
    const std::string kKeyData = bytes("4b0000000c0000109211223344");
    const std::string kReady = bytes("5a0000000549");
    const std::string kQuery = bytes("510000000d53454c454354203100");
    const std::string kRowDesc = bytes("540000002100013f636f6c756d6e3f00000000000000000000170004ffffffff"
        "0000");
    const std::string kDataRow = bytes("440000000b00010000000131");
    const std::string kComplete = bytes("430000000d53454c454354203100");
    const std::string kError = bytes("4500000030534552524f5200433432503031004d72656c6174696f6e20227822"
        "20646f6573206e6f742065786973740000");
    const std::string kParse = bytes("50000000160073656c6563742024313a3a696e74000000");
    const std::string kExecute = bytes("45000000090000000000");
    const std::string kSync = bytes("5300000004");
    const std::string kClose = bytes("430000000b5373746d743100");
    const std::string kTerminate = bytes("5800000004");

    const std::string kClientHello = bytes("160301" "0004" "01000000");
    const std::string kServerHello = bytes("160303" "0004" "02000000");
    const std::string kAppData = bytes("170303" "0010" "00112233445566778899aabbccddeeff");

    bool matches(const std::string &expr, const packet::PacketInfo &p) {
        auto f = filter::Filter::compile(expr);
        EXPECT_TRUE(f.ok) << expr << ": " << f.error.message;
        return f.ok && f.filter.matches(p);
    }

    const packet::Field *find(const std::vector<packet::Field> &fields, const std::string &prefix) {
        for (const auto &f: fields) {
            if (f.text.rfind(prefix, 0) == 0) return &f;
            if (auto *c = find(f.children, prefix)) return c;
        }
        return nullptr;
    }
}

TEST(Postgres, StartupMessageNamesTheUserAndTheDatabase) {
    Flow flow(50000, 5432, "pg_startup");
    flow.client(kStartup);
    flow.load();
    const auto &p = flow.packets()[0];
    EXPECT_EQ(p.protocol, "PGSQL");
    EXPECT_EQ(p.info, "StartupMessage (3.0) user=alice db=shop");
    EXPECT_TRUE(matches("pgsql && pgsql.user == \"alice\"", p));
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Protocol Version: 3.0"), nullptr);
    EXPECT_NE(find(d.fields, "Parameter: application_name = psql"), nullptr);
}

TEST(Postgres, ASessionWithQueriesIsDecodedByDirection) {
    Flow flow(50000, 5432, "pg_session");
    flow.client(kStartup).server(kAuthMd5).client(kPass).server(kAuthOk + kParamStatus + kKeyData + kReady)
        .client(kQuery).server(kRowDesc + kDataRow + kComplete + kReady).client(kParse + kExecute + kSync).server(kError + kReady)
        .client(kClose).client(kTerminate);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[1].info, "Authentication: MD5Password");
    EXPECT_EQ(k[2].info, "PasswordMessage (the password is not shown)");
    EXPECT_NE(k[3].info.find("Authentication: Ok, ParameterStatus: server_version=15.4, BackendKeyData (pid=4242), ReadyForQuery (idle)"), std::string::npos) << k[3].info;
    EXPECT_EQ(k[4].info, "Query: SELECT 1");
    EXPECT_EQ(k[4].app_text, "SELECT 1");
    EXPECT_TRUE(matches("pgsql.type == \"Q\" && pgsql.query == \"SELECT 1\"", k[4]));
    EXPECT_NE(k[5].info.find("RowDescription (1 columns), DataRow (1 columns), CommandComplete: SELECT 1, ReadyForQuery (idle)"), std::string::npos) << k[5].info;
    EXPECT_TRUE(matches("pgsql.type == \"T\"", k[5]));
    EXPECT_NE(k[6].info.find("Parse: select $1::int, Execute: portal <unnamed>, Sync"), std::string::npos) << k[6].info;
    EXPECT_TRUE(matches("pgsql.query == \"select $1::int\"", k[6]));
    EXPECT_NE(k[7].info.find("ErrorResponse: ERROR 42P01 relation \"x\" does not exist"), std::string::npos) << k[7].info;
    EXPECT_TRUE(matches("pgsql.type == \"E\" && pgsql.code == \"42P01\"", k[7]));
    EXPECT_EQ(k[8].info, "Close: statement stmt1") << "'C' from the client is Close, from the server it is CommandComplete";
    EXPECT_EQ(k[9].info, "Terminate") << "an X from the client";
    flow.expectReplayEqualsLoad();
    const auto d = flow.details(3);
    EXPECT_NE(find(d.fields, "Authentication Type: Ok (0)"), nullptr);
    EXPECT_NE(find(d.fields, "Process ID: 4242"), nullptr);
    EXPECT_NE(find(d.fields, "Transaction Status: I (idle)"), nullptr);
    EXPECT_NE(find(flow.details(5).fields, "Column: ?column?"), nullptr);
    EXPECT_NE(find(flow.details(7).fields, "SQLSTATE: 42P01"), nullptr);
}

TEST(Postgres, SaslAuthenticationListsTheMechanisms) {
    Flow flow(50000, 5432, "pg_sasl");
    flow.client(kStartup).server(kAuthSasl);
    flow.load();
    EXPECT_EQ(flow.packets()[1].info, "Authentication: SASL (SCRAM-SHA-256)");
}

TEST(Postgres, SslRequestAnsweredSSwitchesTheConnectionToTls) {
    Flow flow(50000, 5432, "pg_ssl");
    flow.client(kSsl).server("S").client(kClientHello).server(kServerHello).client(kAppData);
    flow.load();
    const auto &k = flow.packets();
    ASSERT_EQ(k.size(), 5u);
    EXPECT_EQ(k[0].info, "SSLRequest");
    EXPECT_TRUE(matches("pgsql.ssl_request", k[0]));
    EXPECT_EQ(k[1].protocol, "PGSQL");
    EXPECT_EQ(k[1].info, "SSLRequest answer: supported (S) - TLS follows") << "the lone byte the dead 1-byte branch never reached";
    EXPECT_EQ(k[2].protocol, "TLS");
    EXPECT_EQ(k[2].info, "Client Hello");
    EXPECT_EQ(k[3].protocol, "TLS");
    EXPECT_EQ(k[4].protocol, "TLS");
    flow.expectReplayEqualsLoad();
}

TEST(Postgres, SslRequestAnsweredNStaysPlain) {
    Flow flow(50000, 5432, "pg_ssl_no");
    flow.client(kSsl).server("N").client(kStartup).server(kAuthOk);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[1].info, "SSLRequest answer: not supported (N)");
    EXPECT_EQ(k[2].info, "StartupMessage (3.0) user=alice db=shop");
    EXPECT_EQ(k[3].info, "Authentication: Ok");
    flow.expectReplayEqualsLoad();
}

TEST(Postgres, GssEncAndCancelRequests) {
    Flow flow(50000, 5432, "pg_cancel");
    flow.client(kGss).client(kCancel);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "GSSENCRequest");
    EXPECT_EQ(flow.packets()[1].info, "CancelRequest (pid=4242)");
}

TEST(Postgres, FourBytePayloadsNeverReadPastTheBuffer) {
    // the audit's reproduction: any payload of exactly 4 bytes (here every first byte) overflowed by one byte
    for (int first = 0; first < 256; ++first) {
        for (size_t n = 1; n <= 6; ++n) {
            std::string payload(n, '\x15');
            payload[0] = static_cast<char>(first);
            const auto pkt = support::parse(support::tcpPacket("0a000001", "0a000002", "c350", "1538", "00000001", "00000001", "18", payload));
            EXPECT_EQ(pkt.protocol, "PGSQL") << first << "/" << n;
        }
    }
}

TEST(PostgresFramer, ALoneAnswerByteDoesNotStallTheStream) {
    using K = dissect::StreamFrame::Kind;
    auto frame = [](const std::string &s) { return dissect::framePostgreSql(s.data(), s.size()); };
    EXPECT_EQ(frame("S").kind, K::Complete);
    EXPECT_EQ(frame("S").length, 1u);
    EXPECT_EQ(frame("N").kind, K::Complete);
    EXPECT_EQ(frame(kSync).kind, K::Complete) << "a Sync message is not the lone S";
    EXPECT_EQ(frame(kSync).length, kSync.size());
    EXPECT_EQ(frame(kQuery.substr(0, 3)).kind, K::NeedMore);
    EXPECT_EQ(frame(kQuery.substr(0, 3)).length, 0u);
    EXPECT_EQ(frame(kQuery.substr(0, 5)).kind, K::NeedMore);
    EXPECT_EQ(frame(kQuery.substr(0, 5)).length, kQuery.size());
    EXPECT_EQ(frame(kQuery + kSync).length, kQuery.size());
    EXPECT_EQ(frame(kStartup.substr(0, 6)).kind, K::NeedMore);
    EXPECT_EQ(frame(kStartup).length, kStartup.size());
    EXPECT_EQ(frame(kSsl).length, 8u);
}

TEST(PostgresFramer, RejectsWhatIsNotPostgres) {
    using K = dissect::StreamFrame::Kind;
    auto frame = [](const std::string &s) { return dissect::framePostgreSql(s.data(), s.size()); };
    EXPECT_EQ(frame(bytes("1603010004" "01000000")).kind, K::Reject) << "a TLS record";
    EXPECT_EQ(frame(bytes("00000004" "00030000")).kind, K::Reject) << "startup packet shorter than 8";
    EXPECT_EQ(frame(bytes("00ffffff" "00030000")).kind, K::Reject) << "startup packet over the server's 10000 byte limit";
    EXPECT_EQ(frame(bytes("510000000100")).kind, K::Reject) << "length below 4";
    EXPECT_EQ(frame(bytes("51ffffffff00")).kind, K::Reject) << "length over the stream buffer";
    EXPECT_EQ(frame(bytes("0141414141")).kind, K::Reject) << "unknown type";
}

TEST(Postgres, SplitAndPipelinedMessagesReassemble) {
    Flow flow(50000, 5432, "pg_split");
    flow.client(kQuery.substr(0, 2)).client(kQuery.substr(2)).server(kRowDesc.substr(0, 10)).server(kRowDesc.substr(10) + kDataRow);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_NE(k[0].info.find("[TCP segment of a reassembled PDU]"), std::string::npos) << k[0].info;
    EXPECT_EQ(k[1].info.rfind("Query: SELECT 1", 0), 0u) << k[1].info;
    EXPECT_NE(k[3].info.find("RowDescription (1 columns), DataRow (1 columns)"), std::string::npos) << k[3].info;
    flow.expectReplayEqualsLoad();
}

TEST(Postgres, TextFromThePacketIsPrintableAndBounded) {
    std::string q = std::string("SELECT '") + "\x01\x02" + std::string(600, 'a');
    std::string msg = std::string("Q") + std::string(1, '\0') + std::string(1, '\0') + std::string(1, static_cast<char>((q.size() + 5) >> 8)) + std::string(1, static_cast<char>((q.size() + 5) & 0xff)) + q + std::string(1, '\0');
    Flow flow(50000, 5432, "pg_text");
    flow.client(msg);
    flow.load();
    const auto &p = flow.packets()[0];
    EXPECT_EQ(p.app_text.rfind("SELECT '??aaa", 0), 0u) << p.app_text;
    EXPECT_LE(p.app_text.size(), 515u);
    EXPECT_LE(p.info.size(), 220u);
}

TEST(Postgres, TruncationAndMutationStayInsideTheFrame) {
    for (const std::string *m: {&kStartup, &kSsl, &kCancel, &kAuthMd5, &kAuthSasl, &kPass, &kParamStatus, &kKeyData, &kQuery, &kRowDesc, &kDataRow,
                                &kComplete, &kError, &kParse, &kExecute, &kClose, &kSync}) {
        appflow::sweepPayload(*m, 5432, 0x5047);
    }
}

TEST(Postgres, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"PGSQL"});
}
