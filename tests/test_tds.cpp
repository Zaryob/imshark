// TDS ([MS-TDS]): packets packed with Python's struct module from the specification's layouts - packet header "Type, Status,
// Length (BE), SPID (BE), PacketID, Window"; PRELOGIN "(token, offset BE16, length BE16)* 0xFF data"; LOGIN7 with its
// offset/length pairs, UTF-16LE strings and the documented password obfuscation (nibble swap, XOR 0xA5); ALL_HEADERS in front
// of SQL Batch and RPC; Tabular Result tokens (LOGINACK 0xAD, ENVCHANGE 0xE3, ERROR 0xAA, DONE 0xFD). Python's encoder is the
// oracle; the password "S3cret!" must not show up anywhere in a decoded tree (its obfuscated bytes are 90a596a593a582a5f3a5e2a5b7a5).
#include <gtest/gtest.h>

#include <functional>

#include <core.h>
#include <dissect/tds.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kPrelogin = bytes("1201002f0000010000001a000601002000010200210001030022000404002600"
        "01ff0b000c23000001000000000000");
    const std::string kPreloginResp = bytes("0401002f0000010000001a000601002000010200210001030022000404002600"
        "01ff0f0007d0000001000000000000");
    const std::string kPreloginRespOff = bytes("0401002f0000010000001a000601002000010200210001030022000404002600"
        "01ff0f0007d0000002000000000000");
    const std::string kLogin7 = bytes("100100a800000100a0000000040000740010000007000000d204000000000000"
        "e003000000000000090400005e0007006c000200700007007e0006008a000500"
        "9400000094000000940000009400060001020304050600000000000000000000"
        "00000000000057004f0052004b00530054004e007300610090a596a593a582a5"
        "f3a5e2a5b7a5700079007400650073007400730071006c00300031006d006100"
        "7300740065007200");
    const std::string kBatch = bytes("0101003e00330100160000001200000002000000000000000000010000005300"
        "45004c00450043005400200040004000760065007200730069006f006e00");
    const std::string kBatchCont = bytes("01010028003302002000460052004f004d0020007300790073002e0074006100"
        "62006c0065007300");
    const std::string kBatchFirstNonfinal = bytes("0100003000330100160000001200000002000000000000000000010000005300"
        "45004c00450043005400200031002000");
    const std::string kRpc = bytes("030100240033010016000000120000000200000000000000000001000000ffff"
        "0a000000");
    const std::string kRpcNamed = bytes("0301002e00330100160000001200000002000000000000000000010000000600"
        "730070005f00770068006f000000");
    const std::string kLoginok = bytes("0401004000000100ad1600017400000406530051004c002000530065000f0007"
        "d0e30f0001066d006100730074006500720000fd000000000000000000000000");
    const std::string kLoginfail = bytes("0401006600000100aa4e0018480000010e1b004c006f00670069006e00200066"
        "00610069006c0065006400200066006f00720020007500730065007200200027"
        "007300610027002e0005730071006c00300031000001000000fd020000000000"
        "000000000000");
    const std::string kAttention = bytes("0601000800000100");
    const std::string kTlsdata = bytes("1201001100000100160301000401000000");

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

    std::string allText(const std::vector<packet::Field> &fields) {
        std::string out;
        std::function<void(const std::vector<packet::Field> &)> walk = [&](const std::vector<packet::Field> &v) { for (auto &f: v) { out += f.text + "\n"; walk(f.children); } };
        walk(fields);
        return out;
    }
}

TEST(Tds, PreLoginNamesTheVersionAndTheEncryptionOption) {
    Flow flow(50000, 1433, "tds_prelogin");
    flow.client(kPrelogin).server(kPreloginResp);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Pre-Login request version 11.0.3107 ENCRYPT_ON (EOM)");
    EXPECT_EQ(k[1].info, "Pre-Login response version 15.0.2000 ENCRYPT_ON (EOM)");
    EXPECT_TRUE(matches("tds.type == 18 && tds.encryption == 1", k[0]));
    EXPECT_TRUE(matches("tds.type == 4 && tds.encryption == 1", k[1]));
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "VERSION: 11.0.3107"), nullptr);
    EXPECT_NE(find(d.fields, "ENCRYPTION: ENCRYPT_ON (1)"), nullptr);
    EXPECT_NE(find(d.fields, "MARS: off"), nullptr);
    Flow notSup(50000, 1433, "tds_prelogin_off");
    notSup.server(kPreloginRespOff);
    notSup.load();
    EXPECT_EQ(notSup.packets()[0].info, "Pre-Login response version 15.0.2000 ENCRYPT_NOT_SUP (EOM)");
    EXPECT_TRUE(matches("tds.encryption == 2", notSup.packets()[0]));
}

TEST(Tds, Login7ShowsTheNamesAndMasksThePassword) {
    Flow flow(50000, 1433, "tds_login7");
    flow.client(kLogin7);
    flow.load();
    const auto &p = flow.packets()[0];
    EXPECT_EQ(p.info, "Login7 user=sa db=master app=pytest (EOM)");
    EXPECT_TRUE(matches("tds.type == 16 && tds.user == \"sa\"", p));
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "Client Host Name: WORKSTN"), nullptr);
    EXPECT_NE(find(d.fields, "User Name: sa"), nullptr);
    EXPECT_NE(find(d.fields, "Application Name: pytest"), nullptr);
    EXPECT_NE(find(d.fields, "Server Name: sql01"), nullptr);
    EXPECT_NE(find(d.fields, "Database Name: master"), nullptr);
    EXPECT_NE(find(d.fields, "Password: ******* (masked, 7 characters)"), nullptr);
    const std::string text = allText(d.fields) + p.info + p.app_text + p.app_text2;
    EXPECT_EQ(text.find("S3cret"), std::string::npos);
    EXPECT_EQ(text.find("90a596a5"), std::string::npos) << "not even the obfuscated bytes";
    EXPECT_EQ(text.find("3cret"), std::string::npos);
}

TEST(Tds, SqlBatchSkipsAllHeadersAndContinuationPacketsHaveNone) {
    Flow flow(50000, 1433, "tds_batch");
    flow.client(kBatchFirstNonfinal).client(kBatchCont).client(kBatch);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Query: SELECT 1  SPID=51") << "first packet of a message that continues: no (EOM)";
    EXPECT_EQ(k[1].info, "Query:  FROM sys.tables (EOM) SPID=51") << "a continuation packet has no ALL_HEADERS: its text was dropped before";
    EXPECT_EQ(k[2].info, "Query: SELECT @@version (EOM) SPID=51");
    EXPECT_TRUE(matches("tds.query == \"SELECT @@version\" && tds.spid == 51", k[2]));
    EXPECT_NE(find(flow.details(2).fields, "ALL_HEADERS (22 bytes)"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(Tds, RpcNamesTheProcedure) {
    Flow flow(50000, 1433, "tds_rpc");
    flow.client(kRpc).client(kRpcNamed);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "RPC sp_ExecuteSql (EOM) SPID=51");
    EXPECT_EQ(flow.packets()[1].info, "RPC sp_who (EOM) SPID=51");
    EXPECT_TRUE(matches("tds.query == \"sp_who\"", flow.packets()[1]));
}

TEST(Tds, TabularResponsesNameTheirTokensAndTheErrorNumber) {
    Flow flow(50000, 1433, "tds_tokens");
    flow.server(kLoginok).server(kLoginfail).client(kAttention);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[0].info, "Tabular Response: LOGINACK, ENVCHANGE, DONE (EOM)");
    EXPECT_EQ(k[1].info, "Tabular Response: ERROR 18456 (Login failed for user 'sa'.), DONE (EOM)");
    EXPECT_TRUE(matches("tds.error_number == 18456", k[1]));
    EXPECT_FALSE(matches("tds.error_number == 18456", k[0]));
    EXPECT_EQ(k[2].info, "Attention Signal (EOM)");
    EXPECT_NE(find(flow.details(1).fields, "ERROR 18456, state 1, class 14: Login failed for user 'sa'."), nullptr);
}

TEST(Tds, EncryptedConnectionWrapsTheHandshakeThenShowsTls) {
    Flow flow(50000, 1433, "tds_tls");
    flow.client(kPrelogin).server(kPreloginResp).client(kTlsdata).server(kTlsdata).client(kAppData).server(kAppData);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[2].protocol, "TDS");
    EXPECT_EQ(k[2].info, "Pre-Login (TLS handshake) (EOM)");
    EXPECT_EQ(k[4].protocol, "TLS") << "after the wrapped handshake the records come without a TDS header";
    EXPECT_EQ(k[5].protocol, "TLS");
    flow.expectReplayEqualsLoad();
}

TEST(Tds, ATlsRecordOnThePortIsTlsNotATdsTypeOf22) {
    Flow flow(50000, 1433, "tds_tls_first");
    flow.client(bytes("160301" "0004" "01000000")).server(bytes("160303" "0004" "02000000"));
    flow.load();
    EXPECT_EQ(flow.packets()[0].protocol, "TLS");
    EXPECT_EQ(flow.packets()[1].protocol, "TLS");
}

TEST(TdsFramer, FramesByTheHeaderLength) {
    using K = dissect::StreamFrame::Kind;
    auto frame = [](const std::string &s) { return dissect::frameTds(s.data(), s.size()); };
    EXPECT_EQ(frame(kBatch.substr(0, 3)).kind, K::NeedMore);
    EXPECT_EQ(frame(kBatch.substr(0, 20)).kind, K::NeedMore);
    EXPECT_EQ(frame(kBatch.substr(0, 20)).length, kBatch.size());
    EXPECT_EQ(frame(kBatch).kind, K::Complete);
    EXPECT_EQ(frame(kBatch + kAttention).length, kBatch.size());
    EXPECT_EQ(frame(kAttention).length, 8u);
}

TEST(TdsFramer, RejectsWhatIsNotTds) {
    using K = dissect::StreamFrame::Kind;
    auto frame = [](const std::string &s) { return dissect::frameTds(s.data(), s.size()); };
    EXPECT_EQ(frame(bytes("1603010004" "01000000")).kind, K::Reject) << "a TLS record: type 22 is no TDS packet";
    EXPECT_EQ(frame(bytes("17030300" "10001122")).kind, K::Reject);
    EXPECT_EQ(frame(bytes("0100" "0004" "00000100")).kind, K::Reject) << "length below the header";
    EXPECT_EQ(frame(bytes("01e1" "0008" "00000100")).kind, K::Reject) << "reserved status bits";
    EXPECT_EQ(frame(bytes("0101" "0008" "00000105")).kind, K::Reject) << "the Window byte is zero";
    EXPECT_EQ(frame(bytes("63")).kind, K::Reject);
}

TEST(Tds, TextFromThePacketIsPrintableAndBounded) {
    std::string text;
    for (int i = 0; i < 2000; ++i) { text += static_cast<char>(i % 7 == 0 ? 1 : 'q'); text += '\0'; }
    std::string pkt = bytes("0101") + std::string(1, static_cast<char>((8 + text.size()) >> 8)) + std::string(1, static_cast<char>((8 + text.size()) & 0xff)) + bytes("00000200") + text;
    Flow flow(50000, 1433, "tds_text");
    flow.client(pkt);
    flow.load();
    const auto &p = flow.packets()[0];
    EXPECT_EQ(p.app_text.rfind("?qqqqqq?", 0), 0u) << p.app_text;
    EXPECT_LE(p.app_text.size(), 515u);
    EXPECT_LE(p.info.size(), 230u);
}

TEST(Tds, TruncationAndMutationStayInsideTheFrame) {
    for (const std::string *m: {&kPrelogin, &kPreloginResp, &kLogin7, &kBatch, &kBatchCont, &kRpc, &kRpcNamed, &kLoginok, &kLoginfail, &kAttention, &kTlsdata}) {
        appflow::sweepPayload(*m, 1433, 0x7d5);
    }
}

TEST(Tds, RealCapturesWhenAvailable) {
    framesweep::checkCorpus({"TDS"});
}
