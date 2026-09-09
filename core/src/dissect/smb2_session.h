#pragma once

// SMB2 as the load pass sees it (rule 4: decisions are made while the capture loads, detail building only reads).
//
//   connection   one TCP connection, told apart by its two endpoints (smb2ConnectionKey). Everything below lives inside it; a
//                Negotiate request starts the connection over (its trees, files and pending requests are forgotten).
//   trees        (SessionId, TreeId) -> share path. Written by a successful Tree Connect response (the path comes from the matched
//                request, the TreeId from the response header), removed by a successful Tree Disconnect or Logoff response.
//   files        FileId (persistent + volatile, 16 bytes) -> file name. Written by a successful Create response (name from the matched
//                request), removed by a successful Close response, a Tree Disconnect of its tree or a Logoff of its session.
//   pending      MessageId -> the request that carried it. A response with the same MessageId (and command) is matched to it: the
//                response learns the request's packet, share, file name and info class, the request learns the response's packet.
//                A STATUS_PENDING interim response (async) leaves the request pending. Cancel requests and the unsolicited
//                MessageId 0xFFFFFFFFFFFFFFFF (oplock break notifications) are never pending.
//   notes        for every command of every message the load pass decoded: what it resolved (share, file, matched packet). Keyed by
//                (packet, TCP stream sequence of the message, command index). Detail building reads the note instead of the
//                tables, which only know the state at the end of the capture (ids are reused after a close).
//   compounds    a request with the "related operations" flag and TreeId / SessionId 0xFFFFFFFF / all ones, or the FileId
//                0xFFFFFFFFFFFFFFFF, uses the values of the command before it ([MS-SMB2] 3.3.5.2.7.2): the name and ids of the
//                previous command of the same message.
//
// Everything counts against one memory budget (the "smb2" table of SessionTables). When it runs out (or the pending requests of a
// connection reach their bound and the oldest is dropped) the table is state lost: commands without a note say so.
//
// Interface for protocols carried over named pipes (DCE/RPC): openFile() answers, in the load pass, whether a FileId is an open
// file of the connection and whether it is a pipe (its tree is an IPC share); for Replay the note of the command carries the same
// answer (Smb2Note::file, kPipe).
#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <utility>

namespace dissect {

constexpr uint16_t kSmb2Negotiate = 0, kSmb2SessionSetup = 1, kSmb2Logoff = 2, kSmb2TreeConnect = 3, kSmb2TreeDisconnect = 4, kSmb2Create = 5,
                   kSmb2Close = 6, kSmb2Cancel = 12;
constexpr uint32_t kSmb2StatusPending = 0x00000103;

/// What the dissector knows about one command when it asks the table (the load pass).
struct Smb2Command {
    uint16_t command = 0;
    bool response = false, async = false, related = false;
    uint32_t status = 0;                 // responses
    uint64_t messageId = 0, sessionId = 0;
    uint32_t treeId = 0;                 // header TreeId (0 for async headers)
    bool hasFileId = false;              // the body carries a FileId (request bodies; Create response)
    uint64_t filePersistent = 0, fileVolatile = 0;
    std::string name;                    // requests: Create file name, Tree Connect share path
    uint8_t shareType = 0;               // Tree Connect response: 1 disk, 2 pipe, 3 print
    uint8_t infoType = 0, infoClass = 0; // Query / Set Info, Query Directory requests
    uint32_t ctlCode = 0;                // IOCTL requests
};

/// What the load pass resolved for one command.
struct Smb2Note {
    enum : uint8_t {
        kMatched = 1,      // response: its request was seen (`requestPacket`)
        kUnmatched = 2,    // response: no pending request had its MessageId
        kPipe = 4,         // the file / share is a named pipe (IPC share)
        kInterim = 8,      // response: STATUS_PENDING, the final response follows
        kRelated = 16,     // ids taken from the command before in the compound
        kAnswered = 32,    // request: its final response was seen (`responsePacket`)
    };
    uint8_t flags = 0;
    uint16_t command = 0;
    uint32_t requestPacket = 0;    // response: packet of the matched request
    uint32_t responsePacket = 0;   // request: packet of the final response
    uint8_t infoType = 0, infoClass = 0;
    uint32_t ctlCode = 0;
    std::string share;             // the share of the tree the command used ("" if unknown)
    std::string file;              // the file the command used (Create name; name of the FileId; "" if unknown)
};

struct Smb2OpenFile {
    std::string name, share;
    bool pipe = false;
    uint64_t session = 0;
    uint32_t tree = 0, openedIn = 0;
};

/// Connection identity: the two "ip:port" endpoints in sorted order.
std::string smb2ConnectionKey(const std::string &ipA, uint16_t portA, const std::string &ipB, uint16_t portB);

class Smb2Table {
public:
    /// Load pass: takes the command number `index` (0-based) of the message at TCP stream sequence `seq` (-1 if none) of `packet`.
    /// Returns the stored note, or nullptr when it could not be stored (budget); `lost` is set when anything was refused or dropped.
    /// Asking twice for the same (packet, seq, index) returns the first answer without touching the state again.
    const Smb2Note *observe(const std::string &connection, uint32_t packet, int64_t seq, uint8_t index, const Smb2Command &cmd, size_t maxMemory, bool &lost);

    const Smb2Note *note(uint32_t packet, int64_t seq, uint8_t index) const;
    /// The open file of the connection with this FileId, as of the commands observed so far.
    const Smb2OpenFile *openFile(const std::string &connection, uint64_t persistent, uint64_t volatileId) const;
    /// The share of a tree of the connection, as of the commands observed so far (nullptr if unknown).
    const std::string *share(const std::string &connection, uint64_t session, uint32_t tree) const;

    size_t memory() const { return memory_; }
    size_t noteCount() const { return notes_.size(); }
    size_t connectionCount() const { return connections_.size(); }
    void clear();

    static constexpr size_t kMaxPendingPerConnection = 4096;

private:
    struct NoteKey {
        uint32_t packet; uint32_t seq; uint8_t index;
        bool operator==(const NoteKey &o) const { return packet == o.packet && seq == o.seq && index == o.index; }
    };
    struct NoteKeyHash {
        size_t operator()(const NoteKey &k) const { return (static_cast<size_t>(k.packet) * 0x9E3779B97F4A7C15ull) ^ (static_cast<size_t>(k.seq) << 8) ^ k.index; }
    };
    struct Pending {
        NoteKey noteKey;
        uint16_t command = 0;
        uint64_t session = 0;
        uint32_t tree = 0;
        uint64_t filePersistent = 0, fileVolatile = 0;
        bool hasFileId = false;
        std::string name, share, file;
        bool pipe = false;
        uint8_t infoType = 0, infoClass = 0;
        uint32_t ctlCode = 0;
    };
    struct Tree {
        std::string share;
        bool pipe = false;
    };
    struct Connection {
        std::map<std::pair<uint64_t, uint32_t>, Tree> trees;
        std::map<std::pair<uint64_t, uint64_t>, Smb2OpenFile> files;
        std::map<uint64_t, Pending> pending;
        // the command before in the current message (for related operations)
        uint64_t lastSession = 0;
        uint32_t lastTree = 0;
        bool lastHasFile = false;
        uint64_t lastPersistent = 0, lastVolatile = 0;
        std::string lastFile;
    };

    static size_t cost(const std::string &a) { return a.capacity(); }
    static size_t noteCost(const Smb2Note &n) { return sizeof(Smb2Note) + sizeof(NoteKey) + 64 + cost(n.share) + cost(n.file); }
    static size_t pendingCost(const Pending &p) { return sizeof(Pending) + 64 + cost(p.name) + cost(p.share) + cost(p.file); }
    static size_t treeCost(const Tree &t) { return sizeof(Tree) + 64 + cost(t.share); }
    static size_t fileCost(const Smb2OpenFile &f) { return sizeof(Smb2OpenFile) + 64 + cost(f.name) + cost(f.share); }
    void forgetConnectionState(Connection &c);
    void dropFilesOf(Connection &c, uint64_t session, bool anyTree, uint32_t tree);

    std::unordered_map<std::string, Connection> connections_;
    std::unordered_map<NoteKey, Smb2Note, NoteKeyHash> notes_;
    size_t memory_ = 0;
};

} // namespace dissect
