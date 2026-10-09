#pragma once

// Database protocols as the load pass sees them (rule 4: decisions are made while the capture loads, detail building only reads).
//
//   connection   one TCP connection, told apart by its two endpoints (dbConnectionKey). Everything below lives inside it. A
//                PostgreSQL StartupMessage and a MySQL greeting start the connection over (everything is forgotten).
//
// PostgreSQL
//   statements   Parse: statement name -> query text and parameter type OIDs (the unnamed statement is replaced by the next Parse; Close
//                'S' forgets a named one). Bind: portal -> statement. Describe / Execute / Close name a statement or portal, the table
//                resolves it to the query. At most 256 statements and 64 portals per connection (then one is dropped and the table is
//                state lost), query text kept to 1024 bytes, 64 parameter OIDs.
//   columns      RowDescription (and CopyIn / CopyOut / CopyBoth responses) -> the column names, type OIDs and format codes DataRow /
//                CopyData are read with, valid from that message on (kept as a position history, not one entry per DataRow). A
//                RowDescription that answers Describe Statement (it follows a ParameterDescription) carries format 0 for every column
//                because no portal exists yet: the result format codes of the latest Bind replace them.
// MySQL
//   state        the capability flags of greeting and login (CLIENT_DEPRECATE_EOF decides whether an EOF follows the column
//                definitions), the command in flight and the phase of its response: column count, N column definitions, [EOF], rows,
//                terminator (and "more results"), or the PREPARE response (OK, parameter definitions, column definitions). The packet
//                kind (a text row is told from an OK by the phase, not by guessing) and the column set are stored as a position history.
//   statements   COM_STMT_PREPARE query + COM_STMT_PREPARE_OK (statement id, columns, parameters) -> id -> query; the parameter types
//                of the last COM_STMT_EXECUTE that sent them are kept for the executions that do not.
//
// Everything counts against one memory budget (the "db" table of SessionTables). When it runs out (or a bound is hit) the table is
// state lost: messages without a note say so and are shown without the resolved query / column types.
#include <cstdint>
#include <deque>
#include <memory>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace dissect {

class ByteReader;

/// Connection identity: the two "ip:port" endpoints in sorted order.
std::string dbConnectionKey(const std::string &ipA, uint16_t portA, const std::string &ipB, uint16_t portB);

/// MySQL length-encoded integer. False if it does not fit (or is the NULL marker 0xfb / the ERR marker 0xff).
bool myLengthEncoded(ByteReader &r, uint64_t &value);

struct PgColumn {
    std::string name;
    uint32_t typeOid = 0;
    int16_t format = 0;      // 0 text, 1 binary
};

struct MyColumn {
    std::string name, table;
    uint8_t type = 0;
    uint16_t flags = 0, charset = 0;
};

/// Parses a MySQL Column Definition (protocol 41) payload. False if it is not one.
bool parseMyColumn(std::string_view payload, MyColumn &out);

struct DbColumnSet {
    std::vector<PgColumn> pg;
    std::vector<MyColumn> my;
    uint16_t total = 0;          // columns the server announced (the first kMaxColumns are described)
    int8_t copyFormat = -1;      // PostgreSQL COPY response: overall format (0 text, 1 binary); -1 = a row description
    bool fromStatement = false;  // PostgreSQL: answers Describe Statement (formats are those of the latest Bind)
};

struct DbStatement {
    uint32_t id = 0;                              // MySQL statement id
    std::string name;                             // PostgreSQL statement name ("" = unnamed)
    std::shared_ptr<const std::string> query;     // SQL text, first 1024 bytes
    std::vector<uint32_t> paramOids;              // PostgreSQL Parse: parameter type OIDs (0 = unspecified), first 64
    uint16_t params = 0, columns = 0;             // MySQL PREPARE_OK counts
    std::vector<uint8_t> paramTypes;              // MySQL: 2 bytes per parameter (type, flags) of the last COM_STMT_EXECUTE that bound them
    const std::string &sql() const { static const std::string none; return query ? *query : none; }
};

/// What a MySQL server packet is, decided by the phase of the response in flight.
struct MyPacket {
    enum Kind : uint8_t {
        Unknown = 0,   // no state (greeting / command not seen, state lost): the dissector falls back to its heuristics
        Ok, Err, Eof, LocalInfile,
        ColCount,      // `index` = number of columns
        ColDef,        // `index` = 0-based column number
        Row,           // `columns`, `binary`
        RowsEnd,       // EOF / OK that ends the rows; `more` = another result set follows
        PrepareOk,     // `statement`
        PrepParamDef, PrepColDef, PrepEof,
    };
    Kind kind = Unknown;
    bool binary = false, more = false;
    uint32_t index = 0;
    const DbColumnSet *columns = nullptr;
    const DbStatement *statement = nullptr;
};

constexpr uint8_t kMyStmtPrepare = 0x16, kMyStmtExecute = 0x17, kMyStmtSendLongData = 0x18, kMyStmtClose = 0x19, kMyStmtReset = 0x1a;
constexpr uint32_t kMyClientDeprecateEof = 0x01000000;

class DbTable {
public:
    static constexpr size_t kMaxColumns = 128, kMaxQuery = 1024, kMaxStatementsPerConnection = 256, kMaxPortalsPerConnection = 64,
                            kMaxParams = 64, kMaxConnections = 4096;

    // ---- PostgreSQL (load pass) --------------------------------------------------------------------------------------------
    void pgStart(const std::string &conn, size_t maxMemory, bool &lost);
    const DbStatement *pgParse(const std::string &conn, uint32_t packet, int32_t seq, const std::string &name, std::string_view query,
                               const std::vector<uint32_t> &oids, size_t maxMemory, bool &lost);
    /// Bind: the portal is bound to the statement; `resultFormats` are the result column format codes of the message.
    const DbStatement *pgBind(const std::string &conn, uint32_t packet, int32_t seq, const std::string &portal, const std::string &statement,
                              const std::vector<int16_t> &resultFormats, size_t maxMemory, bool &lost);
    const DbStatement *pgExecute(const std::string &conn, uint32_t packet, int32_t seq, const std::string &portal, size_t maxMemory, bool &lost);
    /// Describe / Close of a statement ('S') or portal ('P'); Close forgets it.
    const DbStatement *pgDescribeClose(const std::string &conn, uint32_t packet, int32_t seq, bool statement, const std::string &name, bool close,
                                       size_t maxMemory, bool &lost);
    const DbColumnSet *pgRowDescription(const std::string &conn, uint32_t packet, int32_t seq, std::vector<PgColumn> columns, uint16_t total,
                                        size_t maxMemory, bool &lost);
    const DbColumnSet *pgCopyResponse(const std::string &conn, uint32_t packet, int32_t seq, int format, uint16_t columns, size_t maxMemory, bool &lost);
    /// Any other server message by its type letter: 't' ParameterDescription (the RowDescription that follows answers Describe Statement),
    /// 'n' NoData, 'c' CopyDone / 'C' CommandComplete / 'E' ErrorResponse end a COPY.
    void pgServerMessage(const std::string &conn, uint32_t packet, int32_t seq, char letter, size_t maxMemory, bool &lost);

    // ---- PostgreSQL (both passes) ------------------------------------------------------------------------------------------
    /// Statement the client message resolved to (Parse, Bind, Execute, Describe, Close); nullptr if none / state lost.
    const DbStatement *pgNote(uint32_t packet, int32_t seq) const { return note(packet, seq); }
    /// The columns in effect at a DataRow / CopyData, and the result format codes of the latest Bind before it.
    struct PgRows {
        const DbColumnSet *columns = nullptr;
        const std::vector<int16_t> *bindFormats = nullptr;
        /// Format code of column `i` (the Bind's codes win for a statement description).
        int format(size_t i) const;
    };
    PgRows pgRows(const std::string &conn, uint32_t packet, int32_t seq) const;

    // ---- MySQL (load pass) -------------------------------------------------------------------------------------------------
    void myGreeting(const std::string &conn, uint32_t serverCaps, size_t maxMemory, bool &lost);
    void myLogin(const std::string &conn, uint32_t clientCaps, size_t maxMemory, bool &lost);
    /// A command of the client. `arg` is the query of COM_STMT_PREPARE. Commands without a response leave the state alone.
    void myCommand(const std::string &conn, uint8_t command, std::string_view arg, size_t maxMemory, bool &lost);
    /// The prepared statement `id` as the connection knows it now (the packet being decoded is not stored yet).
    const DbStatement *myStatement(const std::string &conn, uint32_t id) const;
    /// COM_STMT_EXECUTE / CLOSE / RESET / SEND_LONG_DATA of statement `id`: stores the note; `newTypes` (2 bytes per parameter) replaces the
    /// remembered types. Close forgets the statement afterwards. Returns the statement (nullptr if the id is unknown).
    const DbStatement *myStatementCommand(const std::string &conn, uint32_t packet, int32_t seq, uint32_t id, const std::vector<uint8_t> *newTypes, bool close,
                                          size_t maxMemory, bool &lost);
    MyPacket myServerPacket(const std::string &conn, uint32_t packet, int32_t seq, std::string_view payload, size_t maxMemory, bool &lost);

    // ---- MySQL (both passes) -----------------------------------------------------------------------------------------------
    MyPacket myPacketAt(const std::string &conn, uint32_t packet, int32_t seq, bool lostState) const;
    const DbStatement *myNote(uint32_t packet, int32_t seq) const { return note(packet, seq); }

    size_t memory() const { return memory_; }
    size_t connectionCount() const { return pg_.size() + my_.size(); }
    size_t statementCount() const { return statements_.size(); }
    void clear();

private:
    struct Pos {
        uint32_t packet = 0;
        int32_t seq = -2;
        bool operator<=(const Pos &o) const { return packet < o.packet || (packet == o.packet && seq <= o.seq); }
        bool operator==(const Pos &o) const { return packet == o.packet && seq == o.seq; }
    };
    struct Event {
        Pos pos;
        uint8_t kind = 0, flags = 0;
        uint32_t set = 0;     // sets_ index + 1
        uint32_t arg = 0;     // kind specific (column number, statement index + 1)
    };
    struct PgBindEvent {
        Pos pos;
        std::vector<int16_t> formats;
    };
    struct PgConn {
        std::vector<Event> columns;                  // PostgreSQL: set in effect from `pos` on (0 = none)
        std::vector<PgBindEvent> binds;
        std::unordered_map<std::string, uint32_t> statements, portals;   // name -> statements_ index + 1
        uint32_t rowSet = 0;                          // latest RowDescription (restored when a COPY ends)
        bool paramDescription = false;
        Pos last;
    };
    struct MyConn {
        std::vector<Event> events;
        std::unordered_map<uint32_t, uint32_t> statements;   // statement id -> statements_ index + 1
        uint32_t serverCaps = 0, clientCaps = 0;
        bool greeting = false, login = false;
        enum Phase : uint8_t { Idle, Handshake, Response, ColDefs, ExpectEof, Rows, PrepParams, PrepParamEof, PrepCols, PrepColEof, FieldList } phase = Idle;
        uint8_t command = 0;
        uint32_t remaining = 0, columnCount = 0, building = 0;   // building: sets_ index + 1
        bool binary = false;
        uint32_t prepareStatement = 0, prepareColumns = 0, prepareParams = 0;   // statements_ index + 1 while a PREPARE response is read
        std::shared_ptr<const std::string> pendingQuery;
        Pos last;
    };

    bool charge(size_t bytes, size_t maxMemory, bool &lost) {
        if (memory_ + bytes > maxMemory) { lost = true; return false; }
        memory_ += bytes;
        return true;
    }
    PgConn *pgConn(const std::string &conn, size_t maxMemory, bool &lost);
    MyConn *myConn(const std::string &conn, size_t maxMemory, bool &lost);
    uint32_t addStatement(DbStatement s, size_t maxMemory, bool &lost);
    uint32_t addSet(DbColumnSet s, size_t maxMemory, bool &lost);
    bool setNote(Pos pos, uint32_t statement1, size_t maxMemory, bool &lost);
    const DbStatement *note(uint32_t packet, int32_t seq) const;
    const DbStatement *statementAt(uint32_t index1) const { return index1 && index1 <= statements_.size() ? &statements_[index1 - 1] : nullptr; }
    const DbColumnSet *setAt(uint32_t index1) const { return index1 && index1 <= sets_.size() ? &sets_[index1 - 1] : nullptr; }
    static const Event *findEvent(const std::vector<Event> &events, Pos pos);
    void pgPushColumns(PgConn &c, Pos pos, uint32_t set, size_t maxMemory, bool &lost);
    MyPacket packetOf(const Event &e) const;
    void myPush(MyConn &c, Pos pos, uint8_t kind, uint8_t flags, uint32_t set, uint32_t arg, size_t maxMemory, bool &lost);
    void pgForgetOne(std::unordered_map<std::string, uint32_t> &m, size_t maxEntries, const std::string &keep, bool &lost);

    std::unordered_map<std::string, PgConn> pg_;
    std::unordered_map<std::string, MyConn> my_;
    std::deque<DbStatement> statements_;
    std::deque<DbColumnSet> sets_;
    std::unordered_map<uint64_t, uint32_t> notes_;   // (packet, seq) -> statements_ index + 1
    size_t memory_ = 0;
};

} // namespace dissect
