// The database session table (db_session.h): PostgreSQL statement / portal / column history and the MySQL response state machine,
// driven directly the way the load pass drives it. The packets are built from the protocol documents' layouts (MySQL "Column
// Definition", COM_STMT_PREPARE_OK, EOF / OK terminators with status flags); the expectations are the documented behaviours.
#include <gtest/gtest.h>

#include <dissect/db_session.h>

using namespace dissect;

namespace {
    const std::string kConn = "10.0.0.1:50000|10.0.0.2:5432";
    constexpr size_t kBudget = 1 << 20;

    std::string lenenc(const std::string &s) { return std::string(1, static_cast<char>(s.size())) + s; }

    // Protocol::ColumnDefinition41: lenenc catalog "def", schema, table, org_table, name, org_name, 0x0c, charset (2), length (4), type, flags (2), decimals, filler (2)
    std::string columnDefinition(const std::string &table, const std::string &name, uint8_t type, uint16_t flags = 0, uint16_t charset = 0x2d) {
        std::string s = lenenc("def") + lenenc("db") + lenenc(table) + lenenc(table) + lenenc(name) + lenenc(name);
        s += '\x0c';
        s += static_cast<char>(charset & 0xff); s += static_cast<char>(charset >> 8);
        s += std::string("\x0b\x00\x00\x00", 4);
        s += static_cast<char>(type);
        s += static_cast<char>(flags & 0xff); s += static_cast<char>(flags >> 8);
        s += std::string("\x00\x00\x00", 3);
        return s;
    }
    std::string eofPacket(uint16_t status = 2) { return std::string("\xfe\x00\x00", 3) + static_cast<char>(status & 0xff) + static_cast<char>(status >> 8); }
    // OK terminator of CLIENT_DEPRECATE_EOF: 0xfe, affected rows 0, last insert id 0, status, warnings 0
    std::string okTerminator(uint16_t status) { return std::string("\xfe\x00\x00", 3) + static_cast<char>(status & 0xff) + static_cast<char>(status >> 8) + std::string("\x00\x00", 2); }
    std::string ok(uint16_t status = 2) { return std::string("\x00\x00\x00", 3) + static_cast<char>(status & 0xff) + static_cast<char>(status >> 8) + std::string("\x00\x00", 2); }
    std::string textRow(const std::string &v) { return lenenc(v); }

    struct Pg {
        DbTable t;
        bool lost = false;
        uint32_t packet = 0;
        int32_t seq = 0;
        void next() { ++packet; seq = 0; }
    };

    struct My {
        DbTable t;
        bool lost = false;
        uint32_t packet = 0;
        MyPacket server(const std::string &payload) { return t.myServerPacket(kConn, ++packet, 0, payload, kBudget, lost); }
    };
}

TEST(DbSessionPg, NamedAndUnnamedStatementsResolveTheirQuery) {
    Pg g;
    g.t.pgStart(kConn, kBudget, g.lost);
    const auto *s1 = g.t.pgParse(kConn, 1, 0, "stmt1", "select $1::int", {23}, kBudget, g.lost);
    ASSERT_NE(s1, nullptr);
    EXPECT_EQ(s1->sql(), "select $1::int");
    EXPECT_EQ(s1->name, "stmt1");
    ASSERT_EQ(s1->paramOids.size(), 1u);
    g.t.pgParse(kConn, 2, 0, "", "select 2", {}, kBudget, g.lost);
    const auto *b = g.t.pgBind(kConn, 3, 0, "", "stmt1", {}, kBudget, g.lost);
    ASSERT_NE(b, nullptr);
    EXPECT_EQ(b->sql(), "select $1::int");
    const auto *e = g.t.pgExecute(kConn, 4, 0, "", kBudget, g.lost);
    ASSERT_NE(e, nullptr);
    EXPECT_EQ(e->sql(), "select $1::int");   // the unnamed portal was bound to stmt1
    // the unnamed statement is replaced by the next Parse
    g.t.pgParse(kConn, 5, 0, "", "select 3", {}, kBudget, g.lost);
    EXPECT_EQ(g.t.pgBind(kConn, 6, 0, "p", "", {}, kBudget, g.lost)->sql(), "select 3");
    EXPECT_EQ(g.t.pgExecute(kConn, 7, 0, "p", kBudget, g.lost)->sql(), "select 3");
    // Replay reads the notes, whatever the tables hold afterwards
    EXPECT_EQ(g.t.pgNote(4, 0)->sql(), "select $1::int");
    EXPECT_EQ(g.t.pgNote(7, 0)->sql(), "select 3");
    EXPECT_FALSE(g.lost);
}

TEST(DbSessionPg, CloseForgetsAStatementAndAnUnknownNameResolvesToNothing) {
    Pg g;
    g.t.pgParse(kConn, 1, 0, "s", "select 1", {}, kBudget, g.lost);
    EXPECT_EQ(g.t.pgDescribeClose(kConn, 2, 0, true, "s", false, kBudget, g.lost)->sql(), "select 1");
    EXPECT_EQ(g.t.pgDescribeClose(kConn, 3, 0, true, "s", true, kBudget, g.lost)->sql(), "select 1");   // Close still names it
    EXPECT_EQ(g.t.pgBind(kConn, 4, 0, "", "s", {}, kBudget, g.lost), nullptr);
    EXPECT_EQ(g.t.pgExecute(kConn, 5, 0, "", kBudget, g.lost), nullptr);   // the bind found no statement: no portal
    EXPECT_EQ(g.t.pgNote(2, 0)->sql(), "select 1");
}

TEST(DbSessionPg, AStartupMessageStartsTheConnectionOver) {
    Pg g;
    g.t.pgParse(kConn, 1, 0, "s", "select 1", {}, kBudget, g.lost);
    g.t.pgStart(kConn, kBudget, g.lost);
    EXPECT_EQ(g.t.pgBind(kConn, 3, 0, "", "s", {}, kBudget, g.lost), nullptr);
}

TEST(DbSessionPg, ConnectionsAreIndependent) {
    Pg g;
    g.t.pgParse("a", 1, 0, "s", "select 'a'", {}, kBudget, g.lost);
    g.t.pgParse("b", 2, 0, "s", "select 'b'", {}, kBudget, g.lost);
    EXPECT_EQ(g.t.pgBind("a", 3, 0, "", "s", {}, kBudget, g.lost)->sql(), "select 'a'");
    EXPECT_EQ(g.t.pgBind("b", 4, 0, "", "s", {}, kBudget, g.lost)->sql(), "select 'b'");
}

TEST(DbSessionPg, ColumnsAreInEffectFromTheirRowDescriptionOn) {
    Pg g;
    EXPECT_EQ(g.t.pgRows(kConn, 5, 0).columns, nullptr);
    g.t.pgRowDescription(kConn, 2, 0, {{"a", 23, 0}, {"b", 25, 0}}, 2, kBudget, g.lost);
    g.t.pgRowDescription(kConn, 6, 1, {{"c", 16, 1}}, 1, kBudget, g.lost);
    EXPECT_EQ(g.t.pgRows(kConn, 1, 0).columns, nullptr);
    ASSERT_NE(g.t.pgRows(kConn, 2, 5).columns, nullptr);   // a DataRow in the same packet after the description
    EXPECT_EQ(g.t.pgRows(kConn, 2, 5).columns->pg[1].name, "b");
    EXPECT_EQ(g.t.pgRows(kConn, 6, 0).columns->pg[0].name, "a");   // before the second description in the same packet
    EXPECT_EQ(g.t.pgRows(kConn, 6, 1).columns->pg[0].name, "c");
    EXPECT_EQ(g.t.pgRows(kConn, 9, 0).columns->pg[0].name, "c");
}

TEST(DbSessionPg, ADescribeStatementDescriptionTakesTheFormatsOfTheLatestBind) {
    Pg g;
    g.t.pgParse(kConn, 1, 0, "s", "select 1, 2", {}, kBudget, g.lost);
    g.t.pgServerMessage(kConn, 2, 0, 't', kBudget, g.lost);   // ParameterDescription precedes the statement's RowDescription
    g.t.pgRowDescription(kConn, 2, 1, {{"a", 23, 0}, {"b", 23, 0}}, 2, kBudget, g.lost);
    g.t.pgBind(kConn, 3, 0, "", "s", {1}, kBudget, g.lost);   // one code applies to every column
    const auto rows = g.t.pgRows(kConn, 4, 0);
    ASSERT_NE(rows.columns, nullptr);
    EXPECT_TRUE(rows.columns->fromStatement);
    EXPECT_EQ(rows.format(0), 1);
    EXPECT_EQ(rows.format(1), 1);
    // a Bind with other codes later, and an ordinary description (Describe Portal) that carries its own formats
    g.t.pgBind(kConn, 5, 0, "", "s", {0, 1}, kBudget, g.lost);
    EXPECT_EQ(g.t.pgRows(kConn, 6, 0).format(0), 0);
    EXPECT_EQ(g.t.pgRows(kConn, 6, 0).format(1), 1);
    g.t.pgRowDescription(kConn, 7, 0, {{"a", 23, 1}}, 1, kBudget, g.lost);
    EXPECT_FALSE(g.t.pgRows(kConn, 7, 1).columns->fromStatement);
    EXPECT_EQ(g.t.pgRows(kConn, 7, 1).format(0), 1);
    // a Bind that changes nothing adds no entry
    const size_t before = g.t.memory();
    g.t.pgBind(kConn, 8, 0, "", "s", {0, 1}, kBudget, g.lost);
    g.t.pgBind(kConn, 9, 0, "", "s", {0, 1}, kBudget, g.lost);
    EXPECT_LT(g.t.memory() - before, 2 * 200u);
}

TEST(DbSessionPg, ACopyResponseSetsTheFormatUntilTheCopyEnds) {
    Pg g;
    g.t.pgRowDescription(kConn, 1, 0, {{"a", 23, 0}}, 1, kBudget, g.lost);
    g.t.pgCopyResponse(kConn, 2, 0, 1, 3, kBudget, g.lost);
    EXPECT_EQ(g.t.pgRows(kConn, 3, 0).columns->copyFormat, 1);
    EXPECT_EQ(g.t.pgRows(kConn, 3, 0).format(0), 1);
    g.t.pgServerMessage(kConn, 4, 0, 'c', kBudget, g.lost);   // CopyDone
    ASSERT_NE(g.t.pgRows(kConn, 5, 0).columns, nullptr);
    EXPECT_EQ(g.t.pgRows(kConn, 5, 0).columns->copyFormat, -1);   // back to the row description
    EXPECT_EQ(g.t.pgRows(kConn, 3, 0).columns->copyFormat, 1);    // Replay of the CopyData still sees the COPY
}

TEST(DbSessionPg, BoundsDropOneEntryAndMarkTheTableLost) {
    Pg g;
    for (uint32_t i = 0; i < DbTable::kMaxStatementsPerConnection + 1; ++i) g.t.pgParse(kConn, i + 1, 0, "s" + std::to_string(i), "select 1", {}, kBudget, g.lost);
    EXPECT_TRUE(g.lost);
    g.lost = false;
    DbTable big;
    const std::string longQuery(5000, 'x');
    const auto *s = big.pgParse(kConn, 1, 0, "q", longQuery, std::vector<uint32_t>(200, 23), kBudget, g.lost);
    EXPECT_EQ(s->sql().size(), DbTable::kMaxQuery);
    EXPECT_EQ(s->paramOids.size(), DbTable::kMaxParams);
}

TEST(DbSessionPg, TheMemoryBudgetStopsNewState) {
    DbTable t;
    bool lost = false;
    const std::string q(900, 'x');
    int stored = 0;
    for (uint32_t i = 0; i < 200; ++i) if (t.pgParse(kConn + std::to_string(i), i + 1, 0, "s", q, {}, 20000, lost)) ++stored;
    EXPECT_TRUE(lost);
    EXPECT_LT(stored, 200);
    EXPECT_LE(t.memory(), 20000u);
}

TEST(DbSessionPg, TheSamePacketTwiceChangesNothing) {
    Pg g;
    const auto *a = g.t.pgParse(kConn, 1, 0, "s", "select 1", {}, kBudget, g.lost);
    const size_t memory = g.t.memory();
    const auto *b = g.t.pgParse(kConn, 1, 0, "s", "select 1", {}, kBudget, g.lost);
    EXPECT_EQ(a, b);
    EXPECT_EQ(g.t.memory(), memory);
    g.t.pgRowDescription(kConn, 2, 0, {{"a", 23, 0}}, 1, kBudget, g.lost);
    const size_t m2 = g.t.memory();
    EXPECT_NE(g.t.pgRowDescription(kConn, 2, 0, {{"a", 23, 0}}, 1, kBudget, g.lost), nullptr);
    EXPECT_EQ(g.t.memory(), m2);
}

// ---- MySQL -----------------------------------------------------------------------------------------------------------------

TEST(DbSessionMy, ATextResultSetIsFollowedColumnByColumnToItsEnd) {
    My m;
    m.t.myGreeting(kConn, 0x0000a208, kBudget, m.lost);   // no CLIENT_DEPRECATE_EOF
    m.t.myLogin(kConn, 0x0000a208, kBudget, m.lost);
    EXPECT_EQ(m.server(ok()).kind, MyPacket::Unknown);   // the authentication OK ends the handshake; the dissector names it
    m.t.myCommand(kConn, 0x03, "select a, b from t", kBudget, m.lost);
    const auto count = m.server("\x02");
    EXPECT_EQ(count.kind, MyPacket::ColCount);
    EXPECT_EQ(count.index, 2u);
    EXPECT_FALSE(count.binary);
    const auto d0 = m.server(columnDefinition("t", "a", 3));
    EXPECT_EQ(d0.kind, MyPacket::ColDef);
    EXPECT_EQ(d0.index, 0u);
    const auto d1 = m.server(columnDefinition("t", "b", 253, 0, 0x2d));
    EXPECT_EQ(d1.index, 1u);
    EXPECT_EQ(m.server(eofPacket()).kind, MyPacket::Eof);
    // a row whose first value is empty starts with 0x00 but it is a row, and a row may start with 0xfe only if it is >= 16 MB
    const std::string empty(1, '\0');
    const auto row0 = m.server(empty + textRow("x"));
    EXPECT_EQ(row0.kind, MyPacket::Row);
    ASSERT_NE(row0.columns, nullptr);
    ASSERT_EQ(row0.columns->my.size(), 2u);
    EXPECT_EQ(row0.columns->my[0].name, "a");
    EXPECT_EQ(row0.columns->my[0].type, 3);
    EXPECT_EQ(row0.columns->my[1].table, "t");
    EXPECT_EQ(m.server(textRow("1") + textRow("one")).kind, MyPacket::Row);
    const auto end = m.server(eofPacket());
    EXPECT_EQ(end.kind, MyPacket::RowsEnd);
    EXPECT_FALSE(end.more);
    EXPECT_EQ(m.server(ok()).kind, MyPacket::Unknown);   // idle: nothing in flight
    EXPECT_FALSE(m.lost);
}

TEST(DbSessionMy, ReplayRecoversTheKindOfEveryPacket) {
    My m;
    m.t.myGreeting(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myLogin(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myCommand(kConn, 0x03, "select a", kBudget, m.lost);
    m.server("\x01");                                   // packet 1
    m.server(columnDefinition("t", "a", 3));            // 2
    m.server(eofPacket());                                    // 3
    m.server(textRow("1"));                             // 4
    m.server(textRow("2"));                             // 5
    m.server(eofPacket());                                    // 6
    const MyPacket::Kind expect[] = {MyPacket::ColCount, MyPacket::ColDef, MyPacket::Eof, MyPacket::Row, MyPacket::Row, MyPacket::RowsEnd};
    for (uint32_t i = 0; i < 6; ++i) EXPECT_EQ(m.t.myPacketAt(kConn, i + 1, 0, false).kind, expect[i]) << "packet " << i + 1;
    EXPECT_EQ(m.t.myPacketAt(kConn, 5, 0, false).columns->my[0].name, "a");
    EXPECT_EQ(m.t.myPacketAt(kConn, 7, 0, false).kind, MyPacket::Unknown);   // after the end of the rows
    EXPECT_EQ(m.t.myPacketAt(kConn, 5, 0, true).kind, MyPacket::Unknown);    // the table lost its state
    // the same packets offered again change nothing
    EXPECT_EQ(m.t.myServerPacket(kConn, 3, 0, eofPacket(), kBudget, m.lost).kind, MyPacket::Eof);
}

TEST(DbSessionMy, DeprecateEofHasNoEofAfterTheColumnsAndEndsWithAnOkPacket) {
    My m;
    m.t.myGreeting(kConn, 0x01008208, kBudget, m.lost);   // CLIENT_DEPRECATE_EOF offered ...
    m.t.myLogin(kConn, 0x01008208, kBudget, m.lost);      // ... and used
    m.t.myCommand(kConn, 0x03, "select a", kBudget, m.lost);
    m.server("\x01");
    EXPECT_EQ(m.server(columnDefinition("t", "a", 3)).kind, MyPacket::ColDef);
    // the packet that would be an EOF is the first row: "0xfe" + four bytes is NOT how a row looks, but a 1 byte value is
    EXPECT_EQ(m.server(textRow("7")).kind, MyPacket::Row);
    const auto end = m.server(okTerminator(2));
    EXPECT_EQ(end.kind, MyPacket::RowsEnd);
    EXPECT_FALSE(end.more);
}

TEST(DbSessionMy, WithoutTheCapabilitiesAnEofAfterTheColumnsIsStillRecognised) {
    My m;   // a connection seen from the middle: no greeting, no login
    m.t.myCommand(kConn, 0x03, "select a", kBudget, m.lost);
    m.server("\x01");
    m.server(columnDefinition("t", "a", 3));
    EXPECT_EQ(m.server(eofPacket()).kind, MyPacket::Eof);
    EXPECT_EQ(m.server(textRow("1")).kind, MyPacket::Row);
    EXPECT_EQ(m.server(eofPacket()).kind, MyPacket::RowsEnd);
}

TEST(DbSessionMy, MoreResultsKeepTheResponseOpen) {
    My m;
    m.t.myGreeting(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myLogin(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myCommand(kConn, 0x03, "call p()", kBudget, m.lost);
    m.server("\x01");
    m.server(columnDefinition("", "x", 3));
    m.server(eofPacket());
    m.server(textRow("1"));
    const auto end = m.server(eofPacket(0x000a));   // SERVER_MORE_RESULTS_EXISTS (0x0008) | SERVER_STATUS_AUTOCOMMIT (0x0002)
    EXPECT_EQ(end.kind, MyPacket::RowsEnd);
    EXPECT_TRUE(end.more);
    EXPECT_EQ(m.server("\x01").kind, MyPacket::ColCount);   // the second result set
    m.server(columnDefinition("", "y", 253));
    m.server(eofPacket());
    EXPECT_EQ(m.server(textRow("z")).columns->my[0].name, "y");
    EXPECT_FALSE(m.server(eofPacket(2)).more);
    const auto final = m.server(ok());   // after the last result set the connection is idle again
    EXPECT_EQ(final.kind, MyPacket::Unknown);
}

TEST(DbSessionMy, AnErrAbortsTheResponse) {
    My m;
    m.t.myGreeting(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myCommand(kConn, 0x03, "bad", kBudget, m.lost);
    EXPECT_EQ(m.server(std::string("\xff\x28\x04#42000x", 9)).kind, MyPacket::Err);
    EXPECT_EQ(m.server("\x01").kind, MyPacket::Unknown);
}

TEST(DbSessionMy, APrepareResponseMapsTheStatementIdToItsQuery) {
    My m;
    m.t.myGreeting(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myLogin(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myCommand(kConn, kMyStmtPrepare, "select ? + ?", kBudget, m.lost);
    // COM_STMT_PREPARE_OK: 0x00, statement id (4), columns (2), parameters (2), filler, warnings (2)
    const auto prep = m.server(std::string("\x00\x07\x00\x00\x00\x01\x00\x02\x00\x00\x00\x00", 12));
    ASSERT_EQ(prep.kind, MyPacket::PrepareOk);
    ASSERT_NE(prep.statement, nullptr);
    EXPECT_EQ(prep.statement->id, 7u);
    EXPECT_EQ(prep.statement->params, 2u);
    EXPECT_EQ(prep.statement->columns, 1u);
    EXPECT_EQ(prep.statement->sql(), "select ? + ?");
    EXPECT_EQ(m.server(columnDefinition("", "?", 8)).kind, MyPacket::PrepParamDef);
    EXPECT_EQ(m.server(columnDefinition("", "?", 8)).index, 1u);
    EXPECT_EQ(m.server(eofPacket()).kind, MyPacket::PrepEof);
    EXPECT_EQ(m.server(columnDefinition("", "? + ?", 8)).kind, MyPacket::PrepColDef);
    EXPECT_EQ(m.server(eofPacket()).kind, MyPacket::PrepEof);
    EXPECT_EQ(m.t.myStatement(kConn, 7)->sql(), "select ? + ?");
    EXPECT_EQ(m.t.myNote(1, 0)->id, 7u);   // Replay of the PREPARE_OK
}

TEST(DbSessionMy, ExecutionsKeepTheLastParameterTypesAndCloseForgetsTheStatement) {
    My m;
    m.t.myGreeting(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myLogin(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myCommand(kConn, kMyStmtPrepare, "select ?", kBudget, m.lost);
    m.server(std::string("\x00\x09\x00\x00\x00\x01\x00\x01\x00\x00\x00\x00", 12));
    m.server(columnDefinition("", "?", 8));
    m.server(eofPacket());
    m.server(columnDefinition("", "?", 8));
    m.server(eofPacket());
    const std::vector<uint8_t> types = {0x08, 0x00};   // MYSQL_TYPE_LONGLONG, signed
    EXPECT_TRUE(m.t.myStatement(kConn, 9)->paramTypes.empty());
    const auto *e1 = m.t.myStatementCommand(kConn, 10, 0, 9, &types, false, kBudget, m.lost);
    ASSERT_NE(e1, nullptr);
    EXPECT_EQ(e1->paramTypes, types);
    const auto *e2 = m.t.myStatementCommand(kConn, 11, 0, 9, nullptr, false, kBudget, m.lost);   // new_params_bound = 0
    EXPECT_EQ(e2->paramTypes, types);
    EXPECT_EQ(m.t.myNote(10, 0)->paramTypes, types);
    EXPECT_NE(m.t.myStatementCommand(kConn, 12, 0, 9, nullptr, true, kBudget, m.lost), nullptr);   // COM_STMT_CLOSE names it ...
    EXPECT_EQ(m.t.myStatement(kConn, 9), nullptr);                                                  // ... and forgets it
    EXPECT_EQ(m.t.myStatementCommand(kConn, 13, 0, 9, nullptr, false, kBudget, m.lost), nullptr);
    EXPECT_EQ(m.t.myNote(12, 0)->sql(), "select ?");
}

TEST(DbSessionMy, ABinaryResultSetIsMarkedBinary) {
    My m;
    m.t.myGreeting(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myLogin(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myCommand(kConn, kMyStmtExecute, "", kBudget, m.lost);
    EXPECT_TRUE(m.server("\x01").binary);
    m.server(columnDefinition("t", "a", 3));
    m.server(eofPacket());
    const auto row = m.server(std::string("\x00\x00\x2a\x00\x00\x00", 6));
    EXPECT_EQ(row.kind, MyPacket::Row);
    EXPECT_TRUE(row.binary);
}

TEST(DbSessionMy, CommandsWithoutAResponseLeaveTheStateAlone) {
    My m;
    m.t.myGreeting(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myCommand(kConn, 0x03, "select 1", kBudget, m.lost);
    m.t.myCommand(kConn, kMyStmtClose, "", kBudget, m.lost);   // COM_STMT_CLOSE has no response
    EXPECT_EQ(m.server("\x01").kind, MyPacket::ColCount);
    m.t.myCommand(kConn, 0x01, "", kBudget, m.lost);           // COM_QUIT
    EXPECT_EQ(m.server(ok()).kind, MyPacket::Unknown);
}

TEST(DbSessionMy, AGreetingStartsTheConnectionOver) {
    My m;
    m.t.myGreeting(kConn, 0x0000a208, kBudget, m.lost);
    m.t.myCommand(kConn, kMyStmtPrepare, "select 1", kBudget, m.lost);
    m.server(std::string("\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00", 12));
    EXPECT_NE(m.t.myStatement(kConn, 1), nullptr);
    m.t.myGreeting(kConn, 0x0000a208, kBudget, m.lost);
    EXPECT_EQ(m.t.myStatement(kConn, 1), nullptr);
}

TEST(DbSessionMy, ColumnDefinitionParsing) {
    MyColumn c;
    ASSERT_TRUE(parseMyColumn(columnDefinition("users", "name", 253, 0x1000, 0x2d), c));
    EXPECT_EQ(c.table, "users");
    EXPECT_EQ(c.name, "name");
    EXPECT_EQ(c.type, 253);
    EXPECT_EQ(c.flags, 0x1000);
    EXPECT_EQ(c.charset, 0x2d);
    EXPECT_FALSE(parseMyColumn("\x01x", c));
    EXPECT_FALSE(parseMyColumn(columnDefinition("t", "a", 3).substr(0, 20), c));
    EXPECT_FALSE(parseMyColumn("", c));
}

TEST(DbSessionMy, TheBudgetStopsNewStateAndNeverReadsPastIt) {
    DbTable t;
    bool lost = false;
    t.myGreeting(kConn, 0, 3000, lost);
    t.myLogin(kConn, 0, 3000, lost);
    t.myCommand(kConn, 0x03, "select", 3000, lost);
    for (uint32_t i = 0; i < 400; ++i) t.myServerPacket(kConn, i + 1, 0, i == 0 ? std::string("\x01") : eofPacket(0x000a), 3000, lost);
    EXPECT_LE(t.memory(), 3000u);
}
