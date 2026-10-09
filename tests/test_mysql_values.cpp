// MySQL text and binary result sets, column metadata, and prepared statements (v1.4). The packets are built with Python's struct module
// from https://dev.mysql.com/doc/dev/mysql-server/latest/ ("3 byte little-endian length, sequence id, payload"; Protocol::ColumnDefinition41;
// text rows = one length-encoded string per column, 0xfb = NULL; binary rows = 0x00, NULL bitmap of (columns + 7 + 2) / 8 bytes whose first
// two bits are reserved, then the values by type; COM_STMT_PREPARE_OK = 0x00, id (4), columns (2), parameters (2), filler, warnings (2);
// COM_STMT_EXECUTE = id, flags, iteration count, NULL bitmap, new-params-bound, [types], values). The values are what Python's struct and
// datetime produce: TINY -5, SHORT 65000, LONG 123456, LONGLONG -9000000000000, FLOAT 2.5, DOUBLE 0.1, DATE 2024-02-29,
// DATETIME 2023-11-14 22:13:20.500000, TIME -26:03:04 (negative, 1 day + 02:03:04), BLOB 0xdeadbeef (binary character set), YEAR 2024,
// NEWDECIMAL "12.50"; the expected texts below are those Python values, not the dissector's output.
#include <gtest/gtest.h>

#include <core.h>
#include <filter/filter.h>

#include "app_flow.h"

using appflow::bytes;
using appflow::Flow;

namespace {
    const std::string kGreetingDep = bytes("4a0000000a382e302e333500630000004142434445464748000da22d02000b01"
        "15000000000000000000006162636465666768696a6b6c0063616368696e675f"
        "736861325f70617373776f726400");
    const std::string kLoginDep = bytes("560000010da20b01000000012d00000000000000000000000000000000000000"
        "00000000616c6963650014111111111111111111111111111111111111111173"
        "686f700063616368696e675f736861325f70617373776f726400");
    const std::string kGreetingPlain = bytes("4a0000000a382e302e333500630000004142434445464748000da22d02000b00"
        "15000000000000000000006162636465666768696a6b6c0063616368696e675f"
        "736861325f70617373776f726400");
    const std::string kLoginPlain = bytes("560000010da20b00000000012d00000000000000000000000000000000000000"
        "00000000616c6963650014111111111111111111111111111111111111111173"
        "686f700063616368696e675f736861325f70617373776f726400");
    const std::string kOk2 = bytes("0700000200000002000000");
    const std::string kQuery = bytes("240000000373656c6563742069642c206e616d652c206e6f74652c2070726963"
        "652066726f6d2074");
    const std::string kTCount = bytes("0100000104");
    const std::string kTId = bytes("1e00000203646566026462017401740269640269640c2d000b00000003000000"
        "0000");
    const std::string kTName = bytes("220000030364656602646201740174046e616d65046e616d650c2d000b000000"
        "fd0000000000");
    const std::string kTNote = bytes("220000040364656602646201740174046e6f7465046e6f74650c3f000b000000"
        "fc9000000000");
    const std::string kTPrice = bytes("2400000503646566026462017401740570726963650570726963650c2d000b00"
        "0000f60000000000");
    const std::string kTEof = bytes("05000006fe00000200");
    const std::string kTRow1 = bytes("0e000007013105616c696365fb04392e3939");
    const std::string kTRow2 = bytes("0d00000801320004deadbeef04302e3530");
    const std::string kTEnd = bytes("05000009fe00000200");
    const std::string kDCount = bytes("0100000101");
    const std::string kDCol = bytes("1c0000020364656602646201740174017601760c2d000b000000fd0000000000");
    const std::string kDRow = bytes("060000030568656c6c6f");
    const std::string kDEnd = bytes("07000004fe000002000000");
    const std::string kMQuery = bytes("090000000363616c6c20702829");
    const std::string kMCount = bytes("0100000101");
    const std::string kMCol = bytes("1a000002036465660264620000017801780c2d000b000000030000000000");
    const std::string kMEof = bytes("05000003fe00000200");
    const std::string kMRow = bytes("020000040131");
    const std::string kMEnd = bytes("05000005fe00000a00");
    const std::string kMOk = bytes("0700000600000002000000");
    const std::string kPrep = bytes("0f0000001673656c656374203f2c203f2c203f");
    const std::string kPrepOk = bytes("0c00000100010000000e000300000000");
    const std::string kPrepP0 = bytes("1a000002036465660264620000013f013f0c3f000b000000fd0000000000");
    const std::string kPrepP1 = bytes("1a000003036465660264620000013f013f0c3f000b000000fd0000000000");
    const std::string kPrepP2 = bytes("1a000004036465660264620000013f013f0c3f000b000000fd0000000000");
    const std::string kPrepPeof = bytes("05000005fe00000200");
    const std::string kPrepCols0 = bytes("1c0000060364656602646201740174016101610c3f000b000000010000000000");
    const std::string kPrepCols1 = bytes("1c0000070364656602646201740174016201620c3f000b000000022000000000");
    const std::string kPrepCols2 = bytes("1c0000080364656602646201740174016301630c3f000b000000030000000000");
    const std::string kPrepCols3 = bytes("1c0000090364656602646201740174016401640c3f000b000000080000000000");
    const std::string kPrepCols4 = bytes("1c00000a0364656602646201740174016501650c3f000b000000040000000000");
    const std::string kPrepCols5 = bytes("1c00000b0364656602646201740174016601660c3f000b000000050000000000");
    const std::string kPrepCols6 = bytes("1c00000c0364656602646201740174016701670c3f000b0000000a0000000000");
    const std::string kPrepCols7 = bytes("1c00000d0364656602646201740174016801680c3f000b0000000c0000000000");
    const std::string kPrepCols8 = bytes("1c00000e0364656602646201740174016901690c3f000b0000000b0000000000");
    const std::string kPrepCols9 = bytes("1c00000f0364656602646201740174016a016a0c2d000b000000fd0000000000");
    const std::string kPrepCols10 = bytes("1c0000100364656602646201740174016b016b0c3f000b000000fc9000000000");
    const std::string kPrepCols11 = bytes("1c0000110364656602646201740174016c016c0c3f000b000000060000000000");
    const std::string kPrepCols12 = bytes("1c0000120364656602646201740174016d016d0c3f000b0000000d2000000000");
    const std::string kPrepCols13 = bytes("1c0000130364656602646201740174016e016e0c2d000b000000f60000000000");
    const std::string kPrepCeof = bytes("05000014fe00000200");
    const std::string kExec1 = bytes("220000001701000000000100000002010880fd00050005000000000000800000"
        "00000000f43f");
    const std::string kExec2 = bytes("1c00000017010000000001000000020007000000000000000000000000000440");
    const std::string kClose = bytes("050000001901000000");
    const std::string kReset = bytes("050000001a01000000");
    const std::string kLongdata = bytes("0d00000018010000000100616263646566");
    const std::string kBCount = bytes("010000010e");
    const std::string kBCols0 = bytes("1c0000020364656602646201740174016101610c3f000b000000010000000000");
    const std::string kBCols1 = bytes("1c0000030364656602646201740174016201620c3f000b000000022000000000");
    const std::string kBCols2 = bytes("1c0000040364656602646201740174016301630c3f000b000000030000000000");
    const std::string kBCols3 = bytes("1c0000050364656602646201740174016401640c3f000b000000080000000000");
    const std::string kBCols4 = bytes("1c0000060364656602646201740174016501650c3f000b000000040000000000");
    const std::string kBCols5 = bytes("1c0000070364656602646201740174016601660c3f000b000000050000000000");
    const std::string kBCols6 = bytes("1c0000080364656602646201740174016701670c3f000b0000000a0000000000");
    const std::string kBCols7 = bytes("1c0000090364656602646201740174016801680c3f000b0000000c0000000000");
    const std::string kBCols8 = bytes("1c00000a0364656602646201740174016901690c3f000b0000000b0000000000");
    const std::string kBCols9 = bytes("1c00000b0364656602646201740174016a016a0c2d000b000000fd0000000000");
    const std::string kBCols10 = bytes("1c00000c0364656602646201740174016b016b0c3f000b000000fc9000000000");
    const std::string kBCols11 = bytes("1c00000d0364656602646201740174016c016c0c3f000b000000060000000000");
    const std::string kBCols12 = bytes("1c00000e0364656602646201740174016d016d0c3f000b0000000d2000000000");
    const std::string kBCols13 = bytes("1c00000f0364656602646201740174016e016e0c2d000b000000f60000000000");
    const std::string kBEof = bytes("05000010fe00000200");
    const std::string kBRow = bytes("4f000011000020fbe8fd40e2010000703286d0f7ffff000020409a9999999999"
        "b93f04e807021d0be7070b0e160d1420a107000c010100000002030400000000"
        "0568656c6c6f04deadbeefe8070531322e3530");
    const std::string kBEnd = bytes("05000012fe00000200");

    const std::vector<std::string> kPrepP = {kPrepP0, kPrepP1, kPrepP2};
    const std::vector<std::string> kPrepCols = {kPrepCols0, kPrepCols1, kPrepCols2, kPrepCols3, kPrepCols4, kPrepCols5, kPrepCols6, kPrepCols7, kPrepCols8, kPrepCols9, kPrepCols10, kPrepCols11, kPrepCols12, kPrepCols13};
    const std::vector<std::string> kBCols = {kBCols0, kBCols1, kBCols2, kBCols3, kBCols4, kBCols5, kBCols6, kBCols7, kBCols8, kBCols9, kBCols10, kBCols11, kBCols12, kBCols13};

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

    // a COM_QUERY packet (sequence 0)
    std::string query(const std::string &sql) {
        const uint32_t n = static_cast<uint32_t>(sql.size() + 1);
        return std::string{char(n & 0xff), char((n >> 8) & 0xff), char((n >> 16) & 0xff), 0, 3} + sql;
    }

    // the whole prepare exchange of "select ?, ?, ?" (3 parameters, 14 columns), as the server answers COM_STMT_PREPARE
    std::string prepareResponse() {
        std::string s = kPrepOk;
        for (const auto &p: kPrepP) s += p;
        s += kPrepPeof;
        for (const auto &c: kPrepCols) s += c;
        return s + kPrepCeof;
    }
}

TEST(MySqlValues, ATextResultSetIsReadWithItsColumnDefinitions) {
    Flow flow(50000, 3306, "myv_text");
    flow.server(kGreetingPlain).client(kLoginPlain).server(kOk2).client(kQuery).server(kTCount).server(kTId).server(kTName).server(kTNote).server(kTPrice)
        .server(kTEof).server(kTRow1).server(kTRow2).server(kTEnd);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[4].info, "Result Set: 4 columns");
    EXPECT_EQ(k[5].info, "Column Definition: t.id");
    EXPECT_EQ(k[8].info, "Column Definition: t.price");
    EXPECT_EQ(k[9].info, "Response EOF (Seq 6)");
    EXPECT_EQ(k[10].info, "Result Row (Seq 7): id=1, name=alice, note=NULL, price=9.99");
    EXPECT_EQ(k[11].info, "Result Row (Seq 8): id=2, name=, note=0xdeadbeef, price=0.50") << "BLOB in the binary character set is hexadecimal";
    EXPECT_EQ(k[12].info, "Response EOF (Seq 9)");
    EXPECT_EQ(k[10].app_text, "1, alice, NULL, 9.99");
    EXPECT_TRUE(matches("mysql.value contains \"alice\" && mysql.from_server", k[10]));
    EXPECT_FALSE(matches("mysql.query contains \"alice\"", k[10])) << "a row is not a query";
    const auto d = flow.details(10);
    EXPECT_NE(find(d.fields, "id (LONG): 1"), nullptr);
    EXPECT_NE(find(d.fields, "name (VAR_STRING): alice"), nullptr);
    EXPECT_NE(find(d.fields, "note (BLOB): NULL"), nullptr);
    EXPECT_NE(find(flow.details(7).fields, "Column: t.note (type BLOB, charset 63)"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(MySqlValues, WithDeprecateEofThereIsNoEofAfterTheColumnsAndAnOkEndsTheRows) {
    Flow flow(50000, 3306, "myv_deprecate");
    flow.server(kGreetingDep).client(kLoginDep).server(kOk2).client(query("select v from t")).server(kDCount).server(kDCol).server(kDRow).server(kDEnd);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[4].info, "Result Set: 1 column");
    EXPECT_EQ(k[5].info, "Column Definition: t.v");
    EXPECT_EQ(k[6].info, "Result Row (Seq 3): v=hello");
    EXPECT_EQ(k[7].info, "Response OK (EOF) (Seq 4, affected rows 0)");
    flow.expectReplayEqualsLoad();
}

TEST(MySqlValues, MoreResultsExistsKeepsTheResponseOpen) {
    Flow flow(50000, 3306, "myv_more");
    flow.server(kGreetingPlain).client(kLoginPlain).server(kOk2).client(kMQuery).server(kMCount).server(kMCol).server(kMEof).server(kMRow).server(kMEnd).server(kMOk);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[7].info, "Result Row (Seq 4): x=1");
    EXPECT_EQ(k[8].info, "Response EOF (Seq 5), more results follow");
    EXPECT_EQ(k[9].info, "Response OK (Seq 6, affected rows 0)");
    flow.expectReplayEqualsLoad();
}

TEST(MySqlValues, PreparedStatementsMapTheirIdToTheQueryAndDecodeTheParameters) {
    Flow flow(50000, 3306, "myv_prepare");
    flow.server(kGreetingPlain).client(kLoginPlain).server(kOk2).client(kPrep).server(prepareResponse()).client(kExec1).client(kExec2).client(kLongdata).client(kReset)
        .client(kClose).client(kExec1);
    flow.load();
    const auto &k = flow.packets();
    EXPECT_EQ(k[3].info, "Prepare: select ?, ?, ?");
    EXPECT_EQ(k[4].info.rfind("Prepare OK: statement 1 (14 columns, 3 parameters) (select ?, ?, ?)", 0), 0u) << k[4].info;
    EXPECT_NE(k[4].info.find("Parameter Definition: ?"), std::string::npos);
    EXPECT_TRUE(matches("mysql.statement_id == 1 && mysql.query == \"select ?, ?, ?\" && mysql.from_server", k[4]));
    // 2^63 + 5 unsigned (types 08 80), NULL string, double 1.25; then the same types reused for 7 / NULL / 2.5
    EXPECT_EQ(k[5].info, "Execute: statement 1 (select ?, ?, ?): $1=9223372036854775813, $2=NULL, $3=1.25");
    EXPECT_EQ(k[6].info, "Execute: statement 1 (select ?, ?, ?): $1=7, $2=NULL, $3=2.5") << "new-params-bound 0 uses the types of the execution before";
    EXPECT_EQ(k[7].info, "Send Long Data: statement 1 (select ?, ?, ?), parameter 1, 6 bytes");
    EXPECT_EQ(k[8].info, "Reset: statement 1 (select ?, ?, ?)");
    EXPECT_EQ(k[9].info, "Close: statement 1 (select ?, ?, ?)");
    EXPECT_EQ(k[10].info, "Execute: statement 1") << "the statement was closed";
    EXPECT_NE(find(flow.details(10).fields, "[statement not prepared in this capture]"), nullptr);
    EXPECT_TRUE(matches("mysql.command == 23 && mysql.statement_id == 1 && mysql.query contains \"select ?\"", k[5]));
    EXPECT_FALSE(matches("mysql.query contains \"select ?\"", k[10]));
    const auto d = flow.details(5);
    EXPECT_NE(find(d.fields, "Parameter $1 (LONGLONG): 9223372036854775813"), nullptr);
    EXPECT_NE(find(d.fields, "Parameter $2 (VAR_STRING): NULL"), nullptr);
    EXPECT_NE(find(d.fields, "Statement ID: 1"), nullptr);
    flow.expectReplayEqualsLoad();
}

TEST(MySqlValues, ABinaryResultSetIsDecodedByTheColumnTypes) {
    Flow flow(50000, 3306, "myv_binary");
    flow.server(kGreetingPlain).client(kLoginPlain).server(kOk2).client(kPrep).server(prepareResponse()).client(kExec1).server(kBCount);
    for (const auto &c: kBCols) flow.server(c);
    flow.server(kBEof).server(kBRow).server(kBEnd);
    flow.load();
    const auto &k = flow.packets();
    ASSERT_EQ(k.size(), 7u + 14u + 3u);
    EXPECT_EQ(k[6].info, "Result Set: 14 columns (binary protocol)");
    const auto &row = k[7 + 14 + 1];
    EXPECT_EQ(row.info, "Result Row (Seq 17): a=-5, b=65000, c=123456, d=-9000000000000, ...");
    EXPECT_EQ(row.app_text, "-5, 65000, 123456, -9000000000000, 2.5, 0.1, 2024-02-29, 2023-11-14 22:13:20.500000");
    EXPECT_EQ(k[7 + 14 + 2].info, "Response EOF (Seq 18)");
    const auto d = flow.details(7 + 14 + 1);
    for (const char *line: {"a (TINY): -5", "b (SHORT): 65000", "c (LONG): 123456", "d (LONGLONG): -9000000000000", "e (FLOAT): 2.5", "f (DOUBLE): 0.1", "g (DATE): 2024-02-29",
                            "h (DATETIME): 2023-11-14 22:13:20.500000", "i (TIME): -26:03:04", "j (VAR_STRING): hello", "k (BLOB): 0xdeadbeef", "l (NULL): NULL",
                            "m (YEAR): 2024", "n (NEWDECIMAL): 12.50"}) {
        EXPECT_NE(find(d.fields, line), nullptr) << line;
    }
    flow.expectReplayEqualsLoad();
}

TEST(MySqlValues, ARowWithoutItsColumnDefinitionsKeepsTheOldReading) {
    Flow flow(50000, 3306, "myv_nodefs");
    flow.server(kTRow1);   // a capture that starts in the middle of a result set: no state, the heuristics decide
    flow.load();
    EXPECT_EQ(flow.packets()[0].info, "Result Row (Seq 7): 1");
    flow.expectReplayEqualsLoad();
}

TEST(MySqlValues, ABudgetTooSmallLosesTheStateButNeverTheDecoding) {
    Flow flow(50000, 3306, "myv_budget");
    flow.processor().sessions().setMaxMemoryPerTable(64);
    flow.server(kGreetingPlain).client(kLoginPlain).server(kOk2).client(kQuery).server(kTCount).server(kTId).server(kTName).server(kTNote).server(kTPrice)
        .server(kTEof).server(kTRow1).server(kTEnd);
    flow.load();
    EXPECT_TRUE(flow.processor().sessions().isTableStateLost("db"));
    EXPECT_EQ(flow.packets()[3].info, "Query: select id, name, note, price from t");
    flow.expectReplayEqualsLoad();
}

TEST(MySqlValues, TruncationAndMutationStayInsideTheFrame) {
    for (const std::string *m: {&kTCount, &kTId, &kTNote, &kTRow1, &kTRow2, &kTEnd, &kDEnd, &kMEnd, &kPrepOk, &kPrepCeof, &kExec1, &kExec2, &kClose, &kReset, &kLongdata,
                                &kBCount, &kBRow}) {
        appflow::sweepPayload(*m, 3306, 0x4d56);
    }
    for (const auto *list: {&kPrepP, &kPrepCols, &kBCols}) for (const auto &m: *list) appflow::sweepPayload(m, 3306, 0x4d57);
}
