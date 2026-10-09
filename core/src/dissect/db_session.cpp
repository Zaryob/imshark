#include "db_session.h"

#include <algorithm>

#include "reader.h"
#include "smb2_session.h"

namespace dissect {

namespace {
constexpr uint8_t kFlagRows = 1, kFlagBinary = 2, kFlagMore = 4;   // MySQL event flags
constexpr uint16_t kServerMoreResults = 0x0008;                    // SERVER_MORE_RESULTS_EXISTS
constexpr size_t kEntryBytes = 64;                                 // what one map / vector entry is charged

uint64_t noteKey(uint32_t packet, int32_t seq) { return (static_cast<uint64_t>(packet) << 32) | static_cast<uint32_t>(seq); }

// Status flags of an EOF (0xfe, warnings, status) or an OK (header, affected rows, last insert id, status, warnings) packet.
uint16_t terminatorStatus(const uint8_t *p, size_t len) {
    if (len >= 5 && p[0] == 0xfe && len < 9) return static_cast<uint16_t>(p[3] | (p[4] << 8));
    ByteReader r(p + 1, len - 1);
    uint64_t skip = 0;
    if (!myLengthEncoded(r, skip) || !myLengthEncoded(r, skip) || r.remaining() < 2) return 0;
    return r.u16_le();
}
} // namespace

std::string dbConnectionKey(const std::string &ipA, uint16_t portA, const std::string &ipB, uint16_t portB) {
    return smb2ConnectionKey(ipA, portA, ipB, portB);
}

bool myLengthEncoded(ByteReader &r, uint64_t &v) {
    if (r.remaining() < 1) return false;
    const uint8_t first = r.u8();
    if (first < 0xfb) { v = first; return true; }
    if (first == 0xfc) { if (r.remaining() < 2) return false; v = r.u16_le(); return true; }
    if (first == 0xfd) { if (r.remaining() < 3) return false; v = r.u24_le(); return true; }
    if (first == 0xfe) { if (r.remaining() < 8) return false; v = r.u64_le(); return true; }
    return false;   // 0xfb is NULL, 0xff is ERR
}

bool parseMyColumn(std::string_view payload, MyColumn &out) {
    ByteReader r(payload);
    const auto str = [&](std::string &s) {
        uint64_t n = 0;
        if (!myLengthEncoded(r, n) || n > r.remaining()) return false;
        s = r.readString(static_cast<size_t>(n));
        return true;
    };
    std::string catalog, schema, orgTable, orgName;
    if (!str(catalog) || catalog != "def" || !str(schema) || !str(out.table) || !str(orgTable) || !str(out.name) || !str(orgName)) return false;
    uint64_t fixed = 0;
    if (!myLengthEncoded(r, fixed) || fixed < 10 || r.remaining() < 10) return false;
    out.charset = r.u16_le();
    r.skip(4);   // column length
    out.type = r.u8();
    out.flags = r.u16_le();
    return true;
}

void DbTable::clear() {
    pg_.clear();
    my_.clear();
    statements_.clear();
    sets_.clear();
    notes_.clear();
    memory_ = 0;
}

uint32_t DbTable::addStatement(DbStatement s, size_t maxMemory, bool &lost) {
    const size_t bytes = sizeof(DbStatement) + s.name.size() + (s.query ? s.query->size() : 0) + s.paramOids.size() * 4 + s.paramTypes.size();
    if (!charge(bytes, maxMemory, lost)) return 0;
    statements_.push_back(std::move(s));
    return static_cast<uint32_t>(statements_.size());
}

uint32_t DbTable::addSet(DbColumnSet s, size_t maxMemory, bool &lost) {
    size_t bytes = sizeof(DbColumnSet);
    for (const auto &c: s.pg) bytes += sizeof(PgColumn) + c.name.size();
    for (const auto &c: s.my) bytes += sizeof(MyColumn) + c.name.size() + c.table.size();
    if (!charge(bytes, maxMemory, lost)) return 0;
    sets_.push_back(std::move(s));
    return static_cast<uint32_t>(sets_.size());
}

bool DbTable::setNote(Pos pos, uint32_t statement1, size_t maxMemory, bool &lost) {
    if (!statement1 || !charge(kEntryBytes, maxMemory, lost)) return false;
    notes_[noteKey(pos.packet, pos.seq)] = statement1;
    return true;
}

const DbStatement *DbTable::note(uint32_t packet, int32_t seq) const {
    const auto it = notes_.find(noteKey(packet, seq));
    return it == notes_.end() ? nullptr : statementAt(it->second);
}

const DbTable::Event *DbTable::findEvent(const std::vector<Event> &events, Pos pos) {
    // last event at or before `pos`
    auto it = std::upper_bound(events.begin(), events.end(), pos, [](const Pos &p, const Event &e) { return !(e.pos <= p); });
    return it == events.begin() ? nullptr : &*(it - 1);
}

// ---- PostgreSQL ---------------------------------------------------------------------------------------------------------------

DbTable::PgConn *DbTable::pgConn(const std::string &conn, size_t maxMemory, bool &lost) {
    auto it = pg_.find(conn);
    if (it != pg_.end()) return &it->second;
    if (pg_.size() >= kMaxConnections || !charge(kEntryBytes + conn.size(), maxMemory, lost)) { lost = true; return nullptr; }
    return &pg_[conn];
}

void DbTable::pgStart(const std::string &conn, size_t maxMemory, bool &lost) {
    pg_.erase(conn);   // the old connection's statements are simply no longer reachable (their memory stays charged until clear())
    pgConn(conn, maxMemory, lost);
}

void DbTable::pgForgetOne(std::unordered_map<std::string, uint32_t> &m, size_t maxEntries, const std::string &keep, bool &lost) {
    if (m.size() < maxEntries) return;
    for (auto it = m.begin(); it != m.end(); ++it) {
        if (it->first == keep) continue;
        m.erase(it);
        break;
    }
    lost = true;   // a statement / portal was dropped: later uses of it cannot be resolved
}

const DbStatement *DbTable::pgParse(const std::string &conn, uint32_t packet, int32_t seq, const std::string &name, std::string_view query,
                                    const std::vector<uint32_t> &oids, size_t maxMemory, bool &lost) {
    if (const DbStatement *n = note(packet, seq)) return n;
    PgConn *c = pgConn(conn, maxMemory, lost);
    const Pos pos{packet, seq};
    if (!c || pos <= c->last) return nullptr;
    c->last = pos;
    DbStatement s;
    s.name = name.substr(0, 64);
    s.query = std::make_shared<const std::string>(query.substr(0, kMaxQuery));
    s.paramOids.assign(oids.begin(), oids.begin() + static_cast<std::ptrdiff_t>(std::min(oids.size(), kMaxParams)));
    const uint32_t idx = addStatement(std::move(s), maxMemory, lost);
    if (!idx) return nullptr;
    pgForgetOne(c->statements, kMaxStatementsPerConnection, name, lost);
    c->statements[name] = idx;
    setNote(pos, idx, maxMemory, lost);
    return statementAt(idx);
}

const DbStatement *DbTable::pgBind(const std::string &conn, uint32_t packet, int32_t seq, const std::string &portal, const std::string &statement,
                                   const std::vector<int16_t> &resultFormats, size_t maxMemory, bool &lost) {
    if (const DbStatement *n = note(packet, seq)) return n;
    PgConn *c = pgConn(conn, maxMemory, lost);
    const Pos pos{packet, seq};
    if (!c || pos <= c->last) return nullptr;
    c->last = pos;
    const auto it = c->statements.find(statement);
    const uint32_t idx = it == c->statements.end() ? 0 : it->second;
    pgForgetOne(c->portals, kMaxPortalsPerConnection, portal, lost);
    if (idx) c->portals[portal] = idx; else c->portals.erase(portal);
    // the result format codes: only a change is a new entry
    const std::vector<int16_t> &current = c->binds.empty() ? std::vector<int16_t>() : c->binds.back().formats;
    if (current != resultFormats && charge(kEntryBytes + resultFormats.size() * 2, maxMemory, lost)) c->binds.push_back({pos, resultFormats});
    setNote(pos, idx, maxMemory, lost);
    return statementAt(idx);
}

const DbStatement *DbTable::pgExecute(const std::string &conn, uint32_t packet, int32_t seq, const std::string &portal, size_t maxMemory, bool &lost) {
    if (const DbStatement *n = note(packet, seq)) return n;
    PgConn *c = pgConn(conn, maxMemory, lost);
    const Pos pos{packet, seq};
    if (!c || pos <= c->last) return nullptr;
    c->last = pos;
    const auto it = c->portals.find(portal);
    const uint32_t idx = it == c->portals.end() ? 0 : it->second;
    setNote(pos, idx, maxMemory, lost);
    return statementAt(idx);
}

const DbStatement *DbTable::pgDescribeClose(const std::string &conn, uint32_t packet, int32_t seq, bool statement, const std::string &name, bool close,
                                            size_t maxMemory, bool &lost) {
    if (const DbStatement *n = note(packet, seq)) return n;
    PgConn *c = pgConn(conn, maxMemory, lost);
    const Pos pos{packet, seq};
    if (!c || pos <= c->last) return nullptr;
    c->last = pos;
    auto &m = statement ? c->statements : c->portals;
    const auto it = m.find(name);
    const uint32_t idx = it == m.end() ? 0 : it->second;
    if (close && it != m.end()) m.erase(it);
    setNote(pos, idx, maxMemory, lost);
    return statementAt(idx);
}

void DbTable::pgPushColumns(PgConn &c, Pos pos, uint32_t set, size_t maxMemory, bool &lost) {
    if (!charge(sizeof(Event), maxMemory, lost)) return;
    Event e;
    e.pos = pos;
    e.set = set;
    c.columns.push_back(e);
}

const DbColumnSet *DbTable::pgRowDescription(const std::string &conn, uint32_t packet, int32_t seq, std::vector<PgColumn> columns, uint16_t total,
                                             size_t maxMemory, bool &lost) {
    PgConn *c = pgConn(conn, maxMemory, lost);
    const Pos pos{packet, seq};
    if (!c) return nullptr;
    if (pos <= c->last) { const Event *e = findEvent(c->columns, pos); return e && e->pos == pos ? setAt(e->set) : nullptr; }
    c->last = pos;
    DbColumnSet s;
    s.total = total;
    s.fromStatement = c->paramDescription;
    c->paramDescription = false;
    if (columns.size() > kMaxColumns) columns.resize(kMaxColumns);
    s.pg = std::move(columns);
    const uint32_t idx = addSet(std::move(s), maxMemory, lost);
    if (!idx) return nullptr;
    c->rowSet = idx;
    pgPushColumns(*c, pos, idx, maxMemory, lost);
    return setAt(idx);
}

const DbColumnSet *DbTable::pgCopyResponse(const std::string &conn, uint32_t packet, int32_t seq, int format, uint16_t columns, size_t maxMemory, bool &lost) {
    PgConn *c = pgConn(conn, maxMemory, lost);
    const Pos pos{packet, seq};
    if (!c) return nullptr;
    if (pos <= c->last) { const Event *e = findEvent(c->columns, pos); return e && e->pos == pos ? setAt(e->set) : nullptr; }
    c->last = pos;
    DbColumnSet s;
    s.total = columns;
    s.copyFormat = static_cast<int8_t>(format);
    const uint32_t idx = addSet(std::move(s), maxMemory, lost);
    if (!idx) return nullptr;
    pgPushColumns(*c, pos, idx, maxMemory, lost);
    return setAt(idx);
}

void DbTable::pgServerMessage(const std::string &conn, uint32_t packet, int32_t seq, char letter, size_t maxMemory, bool &lost) {
    PgConn *c = pgConn(conn, maxMemory, lost);
    const Pos pos{packet, seq};
    if (!c || pos <= c->last) return;
    c->last = pos;
    if (letter == 't') {
        c->paramDescription = true;
    } else if (letter == 'n') {
        c->paramDescription = false;
    } else if (letter == 'c' || letter == 'C' || letter == 'E') {   // CopyDone, CommandComplete, ErrorResponse: a COPY is over
        const Event *e = c->columns.empty() ? nullptr : &c->columns.back();
        const DbColumnSet *s = e ? setAt(e->set) : nullptr;
        if (s && s->copyFormat >= 0) pgPushColumns(*c, pos, c->rowSet, maxMemory, lost);
    }
}

int DbTable::PgRows::format(size_t i) const {
    if (!columns) return 0;
    if (columns->copyFormat >= 0) return columns->copyFormat;
    if (columns->fromStatement && bindFormats) {
        if (bindFormats->size() == 1) return (*bindFormats)[0];
        if (i < bindFormats->size()) return (*bindFormats)[i];
        return 0;
    }
    return i < columns->pg.size() ? columns->pg[i].format : 0;
}

DbTable::PgRows DbTable::pgRows(const std::string &conn, uint32_t packet, int32_t seq) const {
    PgRows r;
    const auto it = pg_.find(conn);
    if (it == pg_.end()) return r;
    const Pos pos{packet, seq};
    if (const Event *e = findEvent(it->second.columns, pos)) r.columns = setAt(e->set);
    const auto &binds = it->second.binds;
    auto b = std::upper_bound(binds.begin(), binds.end(), pos, [](const Pos &p, const PgBindEvent &e) { return !(e.pos <= p); });
    if (b != binds.begin()) r.bindFormats = &(b - 1)->formats;
    return r;
}

// ---- MySQL --------------------------------------------------------------------------------------------------------------------

DbTable::MyConn *DbTable::myConn(const std::string &conn, size_t maxMemory, bool &lost) {
    auto it = my_.find(conn);
    if (it != my_.end()) return &it->second;
    if (my_.size() >= kMaxConnections || !charge(kEntryBytes + conn.size(), maxMemory, lost)) { lost = true; return nullptr; }
    return &my_[conn];
}

void DbTable::myGreeting(const std::string &conn, uint32_t serverCaps, size_t maxMemory, bool &lost) {
    my_.erase(conn);
    MyConn *c = myConn(conn, maxMemory, lost);
    if (!c) return;
    c->greeting = true;
    c->serverCaps = serverCaps;
    c->phase = MyConn::Handshake;
}

void DbTable::myLogin(const std::string &conn, uint32_t clientCaps, size_t maxMemory, bool &lost) {
    MyConn *c = myConn(conn, maxMemory, lost);
    if (!c) return;
    c->login = true;
    c->clientCaps = clientCaps;
}

void DbTable::myCommand(const std::string &conn, uint8_t command, std::string_view arg, size_t maxMemory, bool &lost) {
    MyConn *c = myConn(conn, maxMemory, lost);
    if (!c) return;
    switch (command) {
        case 0x01: c->phase = MyConn::Idle; return;                       // COM_QUIT
        case kMyStmtSendLongData: case kMyStmtClose: return;              // no response
        case 0x11: case 0x12: case 0x13: case 0x15: case 0x1c: case 0x1e: // change user, dumps, register slave, fetch: streams this table does not follow
            c->phase = MyConn::Idle;
            return;
        default: break;
    }
    c->phase = MyConn::Response;
    c->command = command;
    c->remaining = 0;
    if (command == kMyStmtPrepare) {
        auto q = std::make_shared<const std::string>(arg.substr(0, kMaxQuery));
        if (charge(sizeof(std::string) + q->size(), maxMemory, lost)) c->pendingQuery = std::move(q); else c->pendingQuery.reset();
    }
}

const DbStatement *DbTable::myStatement(const std::string &conn, uint32_t id) const {
    const auto it = my_.find(conn);
    if (it == my_.end()) return nullptr;
    const auto s = it->second.statements.find(id);
    return s == it->second.statements.end() ? nullptr : statementAt(s->second);
}

const DbStatement *DbTable::myStatementCommand(const std::string &conn, uint32_t packet, int32_t seq, uint32_t id, const std::vector<uint8_t> *newTypes,
                                               bool close, size_t maxMemory, bool &lost) {
    if (const DbStatement *n = note(packet, seq)) return n;
    const auto cit = my_.find(conn);
    if (cit == my_.end()) return nullptr;
    MyConn &c = cit->second;
    const auto it = c.statements.find(id);
    if (it == c.statements.end()) return nullptr;
    uint32_t idx = it->second;
    if (newTypes && !newTypes->empty() && *newTypes != statementAt(idx)->paramTypes) {
        DbStatement copy = *statementAt(idx);
        copy.paramTypes = *newTypes;
        if (const uint32_t n = addStatement(std::move(copy), maxMemory, lost)) { idx = n; it->second = n; }
    }
    setNote({packet, seq}, idx, maxMemory, lost);
    if (close) c.statements.erase(it);
    return statementAt(idx);
}

void DbTable::myPush(MyConn &c, Pos pos, uint8_t kind, uint8_t flags, uint32_t set, uint32_t arg, size_t maxMemory, bool &lost) {
    if (!charge(sizeof(Event), maxMemory, lost)) return;
    Event e;
    e.pos = pos;
    e.kind = kind;
    e.flags = flags;
    e.set = set;
    e.arg = arg;
    c.events.push_back(e);
    c.last = pos;
}

MyPacket DbTable::packetOf(const Event &e) const {
    MyPacket r;
    r.kind = static_cast<MyPacket::Kind>(e.kind);
    r.binary = e.flags & kFlagBinary;
    r.more = e.flags & kFlagMore;
    r.index = e.arg;
    r.columns = setAt(e.set);
    if (r.kind == MyPacket::PrepareOk) r.statement = statementAt(e.arg);
    return r;
}

MyPacket DbTable::myPacketAt(const std::string &conn, uint32_t packet, int32_t seq, bool lostState) const {
    if (lostState) return {};
    const auto it = my_.find(conn);
    if (it == my_.end()) return {};
    const Pos pos{packet, seq};
    const Event *e = findEvent(it->second.events, pos);
    if (!e) return {};
    if (e->pos == pos) return packetOf(*e);
    if (!(e->flags & kFlagRows)) return {};
    MyPacket r;   // a packet without an event inside a row phase is a row
    r.kind = MyPacket::Row;
    r.binary = e->flags & kFlagBinary;
    r.columns = setAt(e->set);
    return r;
}

MyPacket DbTable::myServerPacket(const std::string &conn, uint32_t packet, int32_t seq, std::string_view payload, size_t maxMemory, bool &lost) {
    const auto cit = my_.find(conn);
    if (cit == my_.end() || payload.empty()) return {};
    MyConn &c = cit->second;
    const Pos pos{packet, seq};
    if (pos <= c.last) return myPacketAt(conn, packet, seq, false);   // decoded before
    const auto *p = reinterpret_cast<const uint8_t *>(payload.data());
    const size_t len = payload.size();
    const uint8_t first = p[0];
    const bool deprecateEof = c.greeting && c.login && (c.serverCaps & c.clientCaps & kMyClientDeprecateEof);

    // stores the packet's kind and returns it (Unknown if the budget refused it)
    const auto make = [&](MyPacket::Kind kind, uint8_t flags, uint32_t set, uint32_t arg) {
        const size_t before = c.events.size();
        myPush(c, pos, kind, flags, set, arg, maxMemory, lost);
        return c.events.size() == before ? MyPacket{} : packetOf(c.events.back());
    };
    const auto isEof = [&] { return first == 0xfe && len < 9; };

    switch (c.phase) {
        case MyConn::Idle: return {};
        case MyConn::Handshake:
            if (first == 0x00 || first == 0xff) c.phase = MyConn::Idle;   // OK / ERR of the authentication: the old heuristics name it
            return {};
        case MyConn::Response: {
            if (first == 0xff) { c.phase = MyConn::Idle; return make(MyPacket::Err, 0, 0, 0); }
            if (c.command == kMyStmtPrepare) {
                if (first != 0x00 || len < 12) { c.phase = MyConn::Idle; return {}; }
                DbStatement s;
                s.id = static_cast<uint32_t>(p[1]) | (static_cast<uint32_t>(p[2]) << 8) | (static_cast<uint32_t>(p[3]) << 16) | (static_cast<uint32_t>(p[4]) << 24);
                s.columns = static_cast<uint16_t>(p[5] | (p[6] << 8));
                s.params = static_cast<uint16_t>(p[7] | (p[8] << 8));
                s.query = c.pendingQuery;
                c.pendingQuery.reset();
                const uint32_t idx = addStatement(s, maxMemory, lost);
                if (!idx) { c.phase = MyConn::Idle; return {}; }
                if (c.statements.size() >= kMaxStatementsPerConnection) { c.statements.erase(c.statements.begin()); lost = true; }
                c.statements[s.id] = idx;
                setNote(pos, idx, maxMemory, lost);
                c.prepareColumns = s.columns;
                c.prepareParams = s.params;
                if (s.params) { c.phase = MyConn::PrepParams; c.remaining = s.params; }
                else if (s.columns) { c.phase = MyConn::PrepCols; c.remaining = s.columns; }
                else c.phase = MyConn::Idle;
                return make(MyPacket::PrepareOk, 0, 0, idx);
            }
            if (c.command == 0x04) {   // COM_FIELD_LIST: column definitions until an EOF
                if (isEof()) { c.phase = MyConn::Idle; return make(MyPacket::Eof, 0, 0, 0); }
                return make(MyPacket::ColDef, 0, 0, c.remaining++);
            }
            if (c.command == 0x03 || c.command == kMyStmtExecute || c.command == 0x0a) {   // query, execute, process info: OK or a result set
                if (first == 0x00) {
                    const bool more = (terminatorStatus(p, len) & kServerMoreResults) != 0;
                    if (!more) c.phase = MyConn::Idle;
                    return make(MyPacket::Ok, more ? kFlagMore : 0, 0, 0);
                }
                if (first == 0xfb && c.command == 0x03) { c.phase = MyConn::Idle; return make(MyPacket::LocalInfile, 0, 0, 0); }
                if (isEof()) { c.phase = MyConn::Idle; return make(MyPacket::Eof, 0, 0, 0); }
                ByteReader r(p, len);
                uint64_t n = 0;
                if (!myLengthEncoded(r, n) || n == 0 || n > 4096 || r.remaining() != 0) { c.phase = MyConn::Idle; return {}; }
                DbColumnSet s;
                s.total = static_cast<uint16_t>(n);
                const uint32_t idx = addSet(std::move(s), maxMemory, lost);
                if (!idx) { c.phase = MyConn::Idle; return {}; }
                c.building = idx;
                c.columnCount = c.remaining = static_cast<uint32_t>(n);
                c.binary = c.command == kMyStmtExecute;
                c.phase = MyConn::ColDefs;
                return make(MyPacket::ColCount, c.binary ? kFlagBinary : 0, idx, static_cast<uint32_t>(n));
            }
            // PING, INIT_DB, RESET, ...: OK / EOF / ERR
            c.phase = MyConn::Idle;
            if (first == 0x00) return make(MyPacket::Ok, 0, 0, 0);
            if (isEof()) return make(MyPacket::Eof, 0, 0, 0);
            return {};
        }
        case MyConn::ColDefs: {
            if (first == 0xff) { c.phase = MyConn::Idle; return make(MyPacket::Err, 0, 0, 0); }
            MyColumn col;
            if (!parseMyColumn(payload, col)) { c.phase = MyConn::Idle; return {}; }
            const uint32_t index = c.columnCount - c.remaining;
            if (c.building && c.building <= sets_.size() && sets_[c.building - 1].my.size() < kMaxColumns) {
                if (charge(sizeof(MyColumn) + col.name.size() + col.table.size(), maxMemory, lost)) sets_[c.building - 1].my.push_back(std::move(col));
            }
            --c.remaining;
            const bool lastColumn = c.remaining == 0;
            if (lastColumn) c.phase = deprecateEof ? MyConn::Rows : MyConn::ExpectEof;
            return make(MyPacket::ColDef, lastColumn ? (kFlagRows | (c.binary ? kFlagBinary : 0)) : 0, c.building, index);
        }
        case MyConn::ExpectEof:
            c.phase = MyConn::Rows;
            if (isEof()) return make(MyPacket::Eof, kFlagRows | (c.binary ? kFlagBinary : 0), c.building, 0);
            [[fallthrough]];   // no EOF (the capabilities were not seen): this is the first row, the last column definition announced rows
        case MyConn::Rows: {
            if (first == 0xff) { c.phase = MyConn::Idle; return make(MyPacket::Err, 0, 0, 0); }
            if (first == 0xfe && len < 0xffffff) {   // EOF / OK that ends the rows
                const bool more = (terminatorStatus(p, len) & kServerMoreResults) != 0;
                c.phase = more ? MyConn::Response : MyConn::Idle;
                return make(MyPacket::RowsEnd, more ? kFlagMore : 0, 0, 0);
            }
            MyPacket r;
            r.kind = MyPacket::Row;
            r.binary = c.binary;
            r.columns = setAt(c.building);
            return r;
        }
        case MyConn::PrepParams:
        case MyConn::PrepCols: {
            if (first == 0xff) { c.phase = MyConn::Idle; return make(MyPacket::Err, 0, 0, 0); }
            const bool params = c.phase == MyConn::PrepParams;
            const uint32_t total = params ? c.prepareParams : c.prepareColumns;
            const uint32_t index = total - c.remaining;
            --c.remaining;
            if (c.remaining == 0) {
                if (params) c.phase = deprecateEof ? (c.prepareColumns ? MyConn::PrepCols : MyConn::Idle) : MyConn::PrepParamEof;
                else c.phase = deprecateEof ? MyConn::Idle : MyConn::PrepColEof;
                if (params && deprecateEof && c.prepareColumns) c.remaining = c.prepareColumns;
            }
            return make(params ? MyPacket::PrepParamDef : MyPacket::PrepColDef, 0, 0, index);
        }
        case MyConn::PrepParamEof:
            if (c.prepareColumns) { c.phase = MyConn::PrepCols; c.remaining = c.prepareColumns; } else c.phase = MyConn::Idle;
            if (isEof()) return make(MyPacket::PrepEof, 0, 0, 0);
            return myServerPacket(conn, packet, seq, payload, maxMemory, lost);   // no EOF: this packet is already the next phase
        case MyConn::PrepColEof:
            c.phase = MyConn::Idle;
            if (isEof()) return make(MyPacket::PrepEof, 0, 0, 0);
            return {};
        case MyConn::FieldList: return {};
    }
    return {};
}

} // namespace dissect
