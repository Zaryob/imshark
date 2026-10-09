// MySQL client/server protocol: packets built with Python's struct module from the documented formats
// (https://dev.mysql.com/doc/dev/mysql-server/latest/): "3 byte little-endian payload length, 1 byte sequence id, payload";
// Protocol::Handshake v10; HandshakeResponse41; SSLRequest (32 bytes, CLIENT_SSL 0x0800); OK / ERR (0xff, code, '#', state,
// message) / EOF (0xfe); text resultset (column count, column definition "def"..., EOF, rows). Python's encoder is the oracle.
#include <gtest/gtest.h>

#include <core.h>
#include <dissect/mysql.h>
#include <dissect/registry.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kGreeting = bytes("4a0000000a382e302e3335006300000041424344454647480000aaff02000800"
        "15000000000000000000006162636465666768696a6b6c0063616368696e675f"
        "736861325f70617373776f726400");
    const std::string kLogin = bytes("5600000103a2030000000001ff00000000000000000000000000000000000000"
        "00000000616c6963650014111111111111111111111111111111111111111173"
        "686f700063616368696e675f736861325f70617373776f726400");
    const std::string kSsl = bytes("200000010faa000000000001ff00000000000000000000000000000000000000"
        "00000000");
    const std::string kOk2 = bytes("0700000200000002000000");
    const std::string kOk1 = bytes("0700000100030002000000");
    const std::string kErr = bytes("2d000001ff2804233432303030596f75206861766520616e206572726f722069"
        "6e20796f75722053514c2073796e746178");
    const std::string kColcount = bytes("0100000101");
    const std::string kColdef = bytes("1e000002036465660473686f7001740174016301630c3f000b00000003810000"
        "0000");
    const std::string kEof = bytes("05000003fe00000200");
    const std::string kRow = bytes("0400000403616263");
    const std::string kRowempty = bytes("03000004000178");
    const std::string kQuery = bytes("090000000353454c4543542031");
    const std::string kInitdb = bytes("050000000273686f70");
    const std::string kPing = bytes("010000000e");
    const std::string kQuit = bytes("0100000001");
    const std::string kPrepare = bytes("090000001653454c454354203f");
    const std::string kExecute = bytes("0a00000017070000000001000000");
    const std::string kAuthswitch = bytes("2c000002fe6d7973716c5f6e61746976655f70617373776f7264007878787878"
        "78787878787878787878787878787800");
    const std::string kAuthmore = bytes("020000020103");

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

TEST(MySql, TheGreetingNamesTheServerAndItsCapabilities) {
    Flow flow(50000, 3306, "my_greeting");
    flow.server(kGreeting);
    flow.load();
    const auto &p = flow.packets()[0];
    EXPECT_EQ(p.protocol, "MySQL");
    EXPECT_EQ(p.info, "Server Greeting proto=10 version=8.0.35 conn=99 auth=caching_sha2_password (SSL)");
    EXPECT_TRUE(matches("mysql.from_server && mysql.version == \"8.0.35\" && mysql.packet_number == 0", p));
    EXPECT_NE(find(flow.details(0).fields, "Server Capabilities: 0x0008aa00 (SSL supported)"), nullptr);
}

TEST(MySql, ServerAndClientPacketsAreToldApartByDirection) {
    Flow flow(50000, 3306, "my_session");
    flow.server(kGreeting).client(kLogin).server(kOk2).client(kQuery).server(kColcount).server(kColdef).server(kEof).server(kRow)
        .server(kRowempty).server(kEof).client(kInitdb).server(kOk1).client(kPrepare).client(kExecute).client(kPing).client(kQuit);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[1].info, "Login Request user=alice") << "a login whose first byte is 0x03 was shown as COM_QUERY";
    EXPECT_TRUE(matches("mysql.user == \"alice\" && !mysql.from_server", k[1]));
    EXPECT_FALSE(matches("mysql.command == 3", k[1]));
    EXPECT_EQ(k[2].info, "Response OK (Seq 2, affected rows 0)");
    EXPECT_EQ(k[3].info, "Query: SELECT 1");
    EXPECT_TRUE(matches("mysql.command == 3 && mysql.query == \"SELECT 1\"", k[3]));
    EXPECT_EQ(k[4].info, "Result Set: 1 column") << "a column count was shown as COM_QUIT";
    EXPECT_FALSE(matches("mysql.command == 1", k[4]));
    EXPECT_EQ(k[5].info, "Column Definition: t.c");
    EXPECT_EQ(k[6].info, "Response EOF (Seq 3)");
    // v1.4: a row is read with the column definitions of its result set, so the value carries its column name
    EXPECT_EQ(k[7].info, "Result Row (Seq 4): c=abc") << "a row starting with 0x03 was shown as a query";
    EXPECT_EQ(k[8].info, "Result Row (Seq 4): c=") << "a row of an empty value is not an OK";
    EXPECT_EQ(k[10].info, "Init DB: shop");
    EXPECT_EQ(k[11].info, "Response OK (Seq 1, affected rows 3)");
    EXPECT_EQ(k[12].info, "Prepare: SELECT ?");
    EXPECT_EQ(k[13].info, "Execute: statement 7");
    EXPECT_EQ(k[14].info, "COM_PING");
    EXPECT_EQ(k[15].info, "COM_QUIT");
    flow.expectReplayEqualsLoad();
    EXPECT_NE(find(flow.details(5).fields, "Column: t.c"), nullptr);
    EXPECT_NE(find(flow.details(1).fields, "Authentication Response: (not shown)"), nullptr);
}

TEST(MySql, ErrPacketsCarryTheCodeStateAndMessage) {
    Flow flow(50000, 3306, "my_err");
    flow.client(kQuery).server(kErr);
    flow.load();
    const auto &p = flow.packets()[1];
    EXPECT_EQ(p.info, "Response ERR 1064 42000: You have an error in your SQL syntax");
    EXPECT_EQ(p.app_code, 1064u);
    EXPECT_TRUE(matches("mysql.error_code == 1064", p));
    EXPECT_FALSE(matches("mysql.error_code == 1064", flow.packets()[0]));
}

TEST(MySql, AuthenticationSwitchAndMoreData) {
    Flow flow(50000, 3306, "my_auth");
    flow.server(kAuthswitch).server(kAuthmore);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "Authentication Switch Request plugin=mysql_native_password");
    EXPECT_EQ(flow.packets()[1].info, "Authentication More Data (Seq 2)");
}

TEST(MySql, ADatabaseServerOnAnotherPortIsKnownFromItsGreeting) {
    // Decode As on 13306: the greeting names the server endpoint, so a later OK packet of the server is not read as a client packet
    dissect::Registry registry = dissect::Registry::builtin();
    std::string error;
    ASSERT_TRUE(registry.decodeAs(true, 13306, "MySQL", &error)) << error;
    packet::PacketParser parser(registry);
    auto load = [&](const std::vector<char> &frame) {
        packet::PacketInfo info(1);
        std::vector<char> copy = frame;
        parser.parsePacket(info, copy, dissect::ParseMode::Summary);
        return info;
    };
    const auto greeting = load(support::tcpPacket("0a000002", "0a000001", "33fa", "c350", "00001388", "00000001", "18", kGreeting));
    EXPECT_EQ(greeting.info.rfind("Server Greeting proto=10", 0), 0u) << greeting.info;
    const auto ok = load(support::tcpPacket("0a000002", "0a000001", "33fa", "c350", "000013d6", "00000001", "18", kOk2));
    EXPECT_NE(ok.info.find("Response OK"), std::string::npos) << ok.info;
    packet::PacketParser fresh(registry);
    packet::PacketInfo info(1);
    auto frame = support::tcpPacket("0a000002", "0a000001", "33fa", "c350", "00001388", "00000001", "18", kOk2);
    fresh.parsePacket(info, frame, dissect::ParseMode::Summary);
    EXPECT_EQ(info.info.find("Response OK"), std::string::npos) << "without the greeting nobody knows the sender is the server: " << info.info;
}

TEST(MySql, SslRequestSwitchesTheConnectionToTls) {
    Flow flow(50000, 3306, "my_ssl");
    flow.server(kGreeting).client(kSsl).client(kClientHello).server(kServerHello).client(kAppData);
    flow.load();
    const auto &k = flow.packets();
    ASSERT_EQ(k.size(), 5u);
    EXPECT_EQ(k[1].info, "SSLRequest - TLS follows");
    EXPECT_TRUE(matches("mysql.ssl_request", k[1]));
    EXPECT_EQ(k[2].protocol, "TLS");
    EXPECT_EQ(k[2].info, "Client Hello");
    EXPECT_EQ(k[3].protocol, "TLS");
    EXPECT_EQ(k[4].protocol, "TLS");
    flow.expectReplayEqualsLoad();
}

TEST(MySql, ASegmentedPacketIsReassembled) {
    Flow flow(50000, 3306, "my_split");
    flow.client(kQuery.substr(0, 2)).client(kQuery.substr(2, 5)).client(kQuery.substr(7));
    flow.load();
    const auto &k = flow.packets();
    EXPECT_NE(k[0].info.find("[TCP segment of a reassembled PDU]"), std::string::npos) << k[0].info;
    EXPECT_EQ(k[2].info.rfind("Query: SELECT 1", 0), 0u) << k[2].info;
    flow.expectReplayEqualsLoad();
}

TEST(MySqlFramer, FramesByTheThreeByteLength) {
    using K = dissect::StreamFrame::Kind;
    auto frame = [](const std::string &s) { return dissect::frameMySql(s.data(), s.size()); };
    EXPECT_EQ(frame(kQuery.substr(0, 3)).kind, K::NeedMore);
    EXPECT_EQ(frame(kQuery.substr(0, 6)).kind, K::NeedMore);
    EXPECT_EQ(frame(kQuery.substr(0, 6)).length, kQuery.size());
    EXPECT_EQ(frame(kQuery).kind, K::Complete);
    EXPECT_EQ(frame(kQuery + kPing).length, kQuery.size());
    EXPECT_EQ(frame(bytes("00000000")).kind, K::Complete) << "an empty packet";
    EXPECT_EQ(frame(bytes("ffffff00")).kind, K::Reject) << "a 16 MB payload is more than the stream table buffers";
}

TEST(MySql, AQueryWhoseLengthLooksLikeATlsRecordHeaderIsStillMySql) {
    // payload lengths 788..791 make the first bytes 14 03 00 00 / 15 03 00 00 / 16 03 00 00 / 17 03 00 00: a TLS record type
    // and version. The next two bytes (sequence 0, command 3) would read as a record length of 3.
    for (size_t payload = 788; payload <= 791; ++payload) {
        const std::string text = "SELECT " + std::string(payload - 1 - 7, 'x');
        std::string pkt(4, '\0');
        pkt[0] = static_cast<char>(payload & 0xff);
        pkt[1] = static_cast<char>(payload >> 8);
        pkt += std::string("\x03") + text;
        ASSERT_EQ(pkt.size(), payload + 4);
        for (bool afterOther: {false, true}) {
            Flow flow(50000, 3306, "my_lookalike" + std::to_string(payload));
            if (afterOther) flow.client(kPing);
            flow.client(pkt);
            flow.load();
            const auto &p = flow.packets().back();
            EXPECT_EQ(p.protocol, "MySQL") << payload << (afterOther ? " after another packet" : "");
            EXPECT_EQ(p.info.rfind("Query: SELECT xxx", 0), 0u) << p.info;
        }
    }
}

TEST(MySql, TextFromThePacketIsPrintableAndBounded) {
    std::string q = std::string("\x03") + "SELECT \x01\n" + std::string(700, 'z');
    std::string pkt = std::string(1, static_cast<char>(q.size() & 0xff)) + std::string(1, static_cast<char>(q.size() >> 8)) + std::string(1, '\0') + std::string(1, '\0') + q;
    Flow flow(50000, 3306, "my_text");
    flow.client(pkt);
    flow.load();
    const auto &p = flow.packets()[0];
    EXPECT_EQ(p.app_text.rfind("SELECT ??zzz", 0), 0u) << p.app_text;
    EXPECT_LE(p.app_text.size(), 515u);
    EXPECT_LE(p.info.size(), 230u);
}

TEST(MySql, TruncationAndMutationStayInsideTheFrame) {
    for (const std::string *m: {&kGreeting, &kLogin, &kSsl, &kOk2, &kErr, &kColcount, &kColdef, &kEof, &kRow, &kRowempty, &kQuery, &kInitdb, &kExecute, &kAuthswitch, &kAuthmore}) {
        appflow::sweepPayload(*m, 3306, 0x4d79);
    }
}

TEST(MySql, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"MySQL"});
}
