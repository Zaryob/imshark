// PostgreSQL extended query, Bind parameters, DataRow values typed by the RowDescription, and COPY (v1.4). Every message is packed
// with Python's struct module following https://www.postgresql.org/docs/current/protocol-message-formats.html ("Byte1 type, Int32
// length counting itself, body"; Parse = name, query, Int16 count, Int32 OIDs; Bind = portal, statement, Int16 format codes, Int16
// parameters each "Int32 length or -1, bytes", Int16 result codes; RowDescription = Int16 count, per column name, table OID, column
// number, type OID, size, modifier, format; DataRow = Int16 count, per column Int32 length or -1 and the bytes). The binary values
// are what the types' send functions produce, computed independently with Python:
//   int4 42 = 0000002a, int8 -5000000000 = struct '>q', float8 1.5 = struct '>d', float4 0.1 = 3dcccccd (struct '>f'),
//   numeric 12345.6789 = digits 1 2345 6789, weight 1, dscale 4 (base 10000 groups built from decimal.Decimal),
//   timestamp 2023-11-14 22:13:20.5 = 753315200500000 microseconds after 2000-01-01 (datetime arithmetic),
//   date 2024-02-29 = 8825 days after 2000-01-01 (datetime.date arithmetic), uuid = uuid.UUID(...).bytes, bytea deadbeef.
// The generator script is in the task report; the expected texts below are those Python values, not the dissector's output.
#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kParse = bytes("500000003973310073656c6563742024313a3a696e74342c2024323a3a746578"
        "742c2024333a3a626f6f6c000003000000170000001900000010");
    const std::string kDescribeS = bytes("440000000853733100");
    const std::string kBind = bytes("420000002c0073310000030001000000010003000000040000002a0000000561"
        "6c696365000000010100010001");
    const std::string kBindText = bytes("420000001d0073310000000003000000022d37ffffffff00000001740000");
    const std::string kExecute = bytes("45000000090000000000");
    const std::string kSync = bytes("5300000004");
    const std::string kParseComplete = bytes("3100000004");
    const std::string kBindComplete = bytes("3200000004");
    const std::string kParamDesc = bytes("74000000120003000000170000001900000010");
    const std::string kRowDescStmt = bytes("54000000e2000b610000000000000000000017ffffffffffff00006200000000"
        "00000000000014ffffffffffff00006300000000000000000002bdffffffffff"
        "ff00006400000000000000000006a4ffffffffffff0000650000000000000000"
        "00045affffffffffff0000660000000000000000000b86ffffffffffff000067"
        "0000000000000000000010ffffffffffff0000680000000000000000000011ff"
        "ffffffffff000069000000000000000000043affffffffffff00006a00000000"
        "000000000002bcffffffffffff00006b0000000000000000000019ffffffffff"
        "ff0000");
    const std::string kDataRowBin = bytes("440000007d000b000000040000002a00000008fffffffed5fa0e00000000083f"
        "f80000000000000000000e0003000100000004000109291a85000000080002ad"
        "22dcee012000000010123e4567e89b12d3a456426614174000ffffffff000000"
        "04deadbeef0000000400002279000000043dcccccd0000000568656c6c6f");
    const std::string kRowDescPortal = bytes("540000002e0002610000000000000000000017ffffffffffff00016200000000"
        "00000000000019ffffffffffff0001");
    const std::string kDataRowTwo = bytes("4400000013000200000004000000070000000178");
    const std::string kRowDescText = bytes("540000004a000369640000000000000000000017ffffffffffff00006e616d65"
        "0000000000000000000019ffffffffffff000073636f72650000000000000000"
        "0002bdffffffffffff0000");
    const std::string kDataRowText = bytes("44000000180003000000013100000005616c696365ffffffff");
    const std::string kDataRowLong = bytes("44000000d20001000000c8787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878"
        "7878787878787878787878787878787878787878787878787878787878787878"
        "78787878787878787878787878787878787878");
    const std::string kCopyOut = bytes("480000000b00000200000000");
    const std::string kCopyDataText = bytes("640000000c3109616c6963650a");
    const std::string kCopyDone = bytes("6300000004");
    const std::string kCompleteCopy = bytes("430000000b434f5059203100");
    const std::string kCopyInBin = bytes("470000000b01000200010001");
    const std::string kCopyDataBin = bytes("64000000175047434f50590aff0d0a000000000000000000");
    const std::string kCopyDataBin2 = bytes("640000000e00010000000400000009");

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

    bool has(const std::string &text, const std::string &part) { return text.find(part) != std::string::npos; }

    const std::string kQuery = "select $1::int4, $2::text, $3::bool";
    const std::string kRowInfo = "a=42, b=-5000000000, c=1.5, d=12345.6789, ...";
}

TEST(PostgresValues, APipelinedExtendedQueryResolvesNamesAndTypesTheParametersAndRow) {
    Flow flow(50000, 5432, "pgv_pipeline");
    flow.client(kParse + kDescribeS + kBind + kExecute + kSync)
        .server(kParseComplete + kParamDesc + kRowDescStmt + kBindComplete + kDataRowBin);
    flow.load();
    const auto &c = flow.packets()[0], &s = flow.packets()[1];
    // Parse names the statement, Describe / Bind / Execute resolve it back to the query; the parameters are typed by Parse's OIDs
    // (int4 binary 00 00 00 2a, text "alice", bool binary 01) and the formats [1, 0, 1]
    EXPECT_EQ(c.info, "Parse: " + kQuery + " (statement s1), Describe: statement s1 (" + kQuery + "), Bind: statement=s1, 3 parameters: 42, alice, true, "
                      "Execute: portal <unnamed> (" + kQuery + "), Sync");
    EXPECT_TRUE(matches("pgsql.statement == \"s1\" && pgsql.query contains \"int4\"", c));
    // the RowDescription answered Describe Statement (formats 0), the Bind asked for binary results: the DataRow is binary
    EXPECT_EQ(s.info, "ParseComplete, ParameterDescription (3 parameters), RowDescription (11 columns): a, b, c, d, ..., BindComplete, DataRow (11 columns): " + kRowInfo);
    const auto d = flow.details(1);
    EXPECT_NE(find(d.fields, "Parameter $1: int4"), nullptr);
    EXPECT_NE(find(d.fields, "Column: a (type int4, text)"), nullptr);
    for (const char *line: {"a (int4): 42", "b (int8): -5000000000", "c (float8): 1.5", "d (numeric): 12345.6789", "e (timestamp): 2023-11-14 22:13:20.5",
                            "f (uuid): 123e4567-e89b-12d3-a456-426614174000", "g (bool): NULL", "h (bytea): \\xdeadbeef", "i (date): 2024-02-29", "j (float4): 0.1",
                            "k (text): hello"}) {
        EXPECT_NE(find(d.fields, line), nullptr) << line;
    }
    const auto dc = flow.details(0);
    EXPECT_NE(find(dc.fields, "Parameter $1 (int4, binary): 42"), nullptr);
    EXPECT_NE(find(dc.fields, "Parameter $2 (text, text): alice"), nullptr);
    EXPECT_NE(find(dc.fields, "Parameter $3 (bool, binary): true"), nullptr);
    EXPECT_NE(find(dc.fields, "Statement: s1"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, TheBindThatFollowsAStatementDescriptionSetsTheResultFormats) {
    // the order of a driver that describes once and binds later: Parse + Describe S, the answers, then Bind + Execute
    Flow flow(50000, 5432, "pgv_split");
    flow.client(kParse + kDescribeS + kSync).server(kParseComplete + kParamDesc + kRowDescStmt)
        .client(kBind + kExecute + kSync).server(kBindComplete).server(kDataRowBin);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[2].info, "Bind: statement=s1, 3 parameters: 42, alice, true, Execute: portal <unnamed> (" + kQuery + "), Sync");
    EXPECT_EQ(k[4].info, "DataRow (11 columns): " + kRowInfo);
    EXPECT_EQ(k[4].app_text, "42, -5000000000, 1.5, 12345.6789, 2023-11-14 22:13:20.5, 123e4567-e89b-12d3-a456-426614174000, NULL, \\xdeadbeef");
    EXPECT_TRUE(matches("pgsql.value contains \"12345.6789\" && pgsql.count == 11 && pgsql.type == \"D\"", k[4]));
    EXPECT_FALSE(matches("pgsql.query contains \"int4\"", k[4])) << "a server message has no query";
    EXPECT_TRUE(matches("pgsql.query contains \"int4\" && pgsql.statement == \"s1\" && pgsql.count == 3", k[2]));
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, TextFormatParametersAndNullsNeedNoTypes) {
    Flow flow(50000, 5432, "pgv_text_bind");
    flow.client(kParse).client(kBindText + kExecute + kSync);
    flow.load();
    // no format codes = all text: "-7", NULL, "t"
    EXPECT_EQ(flow.packets()[1].info, "Bind: statement=s1, 3 parameters: -7, NULL, t, Execute: portal <unnamed> (" + kQuery + "), Sync");
    const auto d = flow.details(1);
    EXPECT_NE(find(d.fields, "Parameter $1 (int4, text): -7"), nullptr);
    EXPECT_NE(find(d.fields, "Parameter $2 (text, text): NULL"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, ABindWithoutItsParseIsShownRawAndSaysSo) {
    Flow flow(50000, 5432, "pgv_noparse");
    flow.client(kBind);
    flow.load();
    // unknown types: the binary parameters are hex, the text one is text
    EXPECT_EQ(flow.packets()[0].info, "Bind: statement=s1, 3 parameters: \\x0000002a, alice, \\x01");
    EXPECT_NE(find(flow.details(0).fields, "[statement not seen in this capture]"), nullptr);
    EXPECT_TRUE(flow.packets()[0].app_text.empty());
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, TextRowsUseTheNamesOfTheRowDescription) {
    Flow flow(50000, 5432, "pgv_rows");
    flow.server(kRowDescText + kDataRowText + kCompleteCopy);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "RowDescription (3 columns): id, name, score, DataRow (3 columns): id=1, name=alice, score=NULL, CommandComplete: COPY 1");
    EXPECT_NE(find(flow.details(0).fields, "name (text): alice"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, ARowDescriptionOfAPortalCarriesItsOwnFormats) {
    Flow flow(50000, 5432, "pgv_portal");
    flow.server(kRowDescPortal).server(kDataRowTwo);   // columns a int4 and b text, both binary
    flow.load();
    EXPECT_EQ(flow.packets()[1].info, "DataRow (2 columns): a=7, b=x");
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, ALongValueIsCutAndTheInfoStaysBounded) {
    Flow flow(50000, 5432, "pgv_long");
    flow.server(kRowDescText).server(kDataRowLong);
    flow.load();
    const auto &p = flow.packets()[1];
    EXPECT_EQ(p.info, "DataRow (1 columns): id=" + std::string(64, 'x') + "... (200 bytes)");
    EXPECT_LE(p.app_text.size(), 100u);
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, ADataRowWithoutADescriptionShowsPlainText) {
    Flow flow(50000, 5432, "pgv_nodesc");
    flow.server(kDataRowText);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "DataRow (3 columns): 1, alice, NULL");
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, ManyColumnsAreCountedNotAllShown) {
    // 300 text columns: the description keeps 128, the DataRow shows 32 in the tree and says how many more there are
    std::string desc, row;
    desc += std::string("\x01\x2c", 2);
    row += std::string("\x01\x2c", 2);
    for (int i = 0; i < 300; ++i) {
        desc += "c" + std::to_string(i) + std::string("\0", 1) + bytes("00000000" "0000" "00000019" "ffff" "ffffffff" "0000");   // name, table OID, column, type text, size, modifier, format
        row += std::string("\0\0\0\x01", 4) + "v";
    }
    const auto message = [](char type, const std::string &body) {
        const uint32_t n = static_cast<uint32_t>(body.size() + 4);
        return std::string(1, type) + std::string{char(n >> 24), char(n >> 16), char(n >> 8), char(n)} + body;
    };
    Flow flow(50000, 5432, "pgv_wide");
    flow.server(message('T', desc) + message('D', row));
    flow.load();
    const auto d = flow.details(0);
    EXPECT_NE(find(d.fields, "c31 (text): v"), nullptr);
    EXPECT_EQ(find(d.fields, "c32 (text): v"), nullptr);
    EXPECT_NE(find(d.fields, "268 more columns not shown"), nullptr);
    EXPECT_EQ(flow.packets()[0].app_stream, 300u);
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, CopyOutShowsTheTextLinesAndEndsAtCopyDone) {
    Flow flow(50000, 5432, "pgv_copy_out");
    flow.server(kCopyOut + kCopyDataText + kCopyDone + kCompleteCopy);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "CopyOutResponse (text, 2 columns), CopyData (8 bytes): 1\\talice\\n, CopyDone, CommandComplete: COPY 1");
    EXPECT_NE(find(flow.details(0).fields, "Data: 1\\talice\\n"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, CopyInBinaryRecognisesTheSignature) {
    Flow flow(50000, 5432, "pgv_copy_in");
    flow.server(kCopyInBin).client(kCopyDataBin + kCopyDataBin2 + kCopyDone);
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "CopyInResponse (binary, 2 columns)");
    EXPECT_EQ(flow.packets()[1].info, "CopyData (19 bytes): binary COPY header (signature PGCOPY), CopyData (10 bytes): \\x00010000000400000009, CopyDone");
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, ANewStartupMessageForgetsTheStatementsOfTheConnectionBefore) {
    Flow flow(50000, 5432, "pgv_restart");
    flow.client(kParse);
    flow.client(bytes("0000001000030000" "75736572" "00610000"));   // StartupMessage user=a
    flow.client(kBind);
    flow.load();
    EXPECT_NE(find(flow.details(2).fields, "[statement not seen in this capture]"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, ABudgetTooSmallLosesTheStateButNeverTheDecoding) {
    Flow flow(50000, 5432, "pgv_budget");
    flow.processor().sessions().setMaxMemoryPerTable(64);
    flow.client(kParse + kDescribeS + kBind + kExecute + kSync).server(kParseComplete + kParamDesc + kRowDescStmt + kBindComplete + kDataRowBin);
    flow.load();
    EXPECT_TRUE(flow.processor().sessions().isTableStateLost("db"));
    EXPECT_TRUE(has(flow.packets()[0].info, "Bind: statement=s1"));
    EXPECT_TRUE(has(flow.packets()[1].info, "DataRow (11 columns)"));
    flow.expectReplayEqualsLoad();
}

TEST(PostgresValues, TruncationAndMutationStayInsideTheFrame) {
    for (const std::string *m: {&kParse, &kDescribeS, &kBind, &kBindText, &kExecute, &kParamDesc, &kRowDescStmt, &kDataRowBin, &kRowDescPortal, &kDataRowTwo,
                                &kRowDescText, &kDataRowText, &kDataRowLong, &kCopyOut, &kCopyDataText, &kCopyInBin, &kCopyDataBin, &kCopyDataBin2}) {
        appflow::sweepPayload(*m, 5432, 0x5056);
    }
}
