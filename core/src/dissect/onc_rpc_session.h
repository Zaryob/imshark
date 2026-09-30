#pragma once

// ONC RPC (RFC 5531) as the load pass sees it (rule 4: decisions are made while the capture loads, detail building only reads).
//
//   records     a TCP record is made of fragments (RFC 5531 section 11: bit 31 of the record mark ends the record). The fragments of one
//               direction of a connection arrive in order; the table follows them (the stream sequence number must continue exactly
//               where the previous fragment ended, otherwise the open record is dropped) and keeps the first kMaxKeptBytes of the
//               assembled record so that the fragment that ends it can be decoded as a whole message.
//   calls       (connection or datagram endpoints, xid) -> program, version, procedure, the arguments a reply needs (GETPORT's mapping,
//               rpcbind's netid) and the packet. A reply finds its call here; a call seen again with the same xid and the same
//               program / version / procedure is a retransmission, a second reply to a call is a duplicate. A reply that comes before
//               its call (a capture that starts in the middle, or a call that was retransmitted after the reply) stays unmatched: what
//               a packet shows is decided when it is loaded and does not change when the call turns up later.
//   notes       for every message the load pass decoded: the fragment it was, the record it completed, the call it belongs to. Keyed by
//               (packet, TCP stream sequence of the fragment; -1 for a datagram). Detail building reads the note, not the tables.
//   programs    what the portmapper / rpcbind answered (GETPORT, DUMP, GETADDR, CALLIT ...): a TCP / UDP port of a host and the program
//               behind it. A later connection (or datagram) to that port is ONC RPC even though no dissector is registered for it.
//               Valid from the packet that carried the answer on, so that a packet's decoding does not change between the load pass and
//               Replay. Only answers to a call the table saw count, and the registry's own ports always win (tcp.cpp / udp.cpp).
//
// Everything counts against one memory budget (the "rpc" table of SessionTables). When it runs out (or a bound below is reached and the
// oldest entry is dropped) the table is state lost: messages without a note say so.
#include <cstdint>
#include <deque>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace dissect {

inline constexpr uint32_t kRpcProgPortmap = 100000, kRpcProgNfs = 100003, kRpcProgMount = 100005;

/// A complete message (a datagram or a record) as far as the table needs to know it.
struct RpcMessage {
    bool call = false;
    uint32_t xid = 0;
    uint32_t prog = 0, vers = 0, proc = 0;            // a call
    uint32_t mapProg = 0, mapVers = 0, mapProt = 0;   // the arguments of a call that names a program (GETPORT, SET, UNSET, CALLIT, rpcbind)
    std::string netid;                                // rpcbind: the network id of the rpcb argument ("tcp", "udp", "tcp6", "udp6")
};

/// What the load pass learned for one fragment / datagram.
struct RpcNote {
    enum : uint16_t {
        kFragment = 1,         // one fragment of a record that has several
        kContinuation = 2,     // not the first fragment of the record
        kCompletes = 4,        // the message is complete here: a datagram, a record of one fragment, or the last fragment of a longer one
        kMatched = 8,          // a reply whose call was seen (callPacket, prog, vers, proc ...), or a retransmitted call (callPacket = the first copy)
        kRetransmission = 16,  // a call seen again (same xid, program, version and procedure)
        kDuplicateReply = 32,  // a second reply to the same call
        kDropped = 64,         // the open record this fragment would continue was dropped (a hole, a bound): it starts a new record
    };
    uint16_t flags = 0;
    uint16_t fragments = 0;       // kCompletes: how many fragments the record had
    uint32_t record = 0;          // kCompletes with more than one fragment: index into RpcTable::record()
    uint32_t callPacket = 0;
    uint32_t replyPacket = 0;     // a call: the first reply (filled in later in the load pass; shown in the detail tree only)
    uint32_t prog = 0, vers = 0, proc = 0;
    uint32_t mapProg = 0, mapVers = 0, mapProt = 0;
    std::string netid;
};

/// A record assembled from several fragments.
struct RpcRecord {
    std::string bytes;            // the first kMaxKeptBytes of the record (without the record marks)
    uint32_t total = 0;           // its whole length
    uint32_t lastStart = 0;       // offset (in the record) of the last fragment
    uint16_t fragments = 0;
    std::vector<uint32_t> packets;
};

/// A program the portmapper told about (valid from `from` on). `prog` 0: more than one program behind the port, none is guessed.
struct RpcMappedProgram {
    uint32_t from = 0;
    uint32_t prog = 0;
    uint32_t vers = 0;            // 0: several versions
};

struct RpcMapping {
    uint32_t prog = 0, vers = 0, prot = 0, port = 0;   // prot 6 = TCP, 17 = UDP
    std::string host;                                  // IPv4 / IPv6 text of the address the answer named, "" if it named none
};

class RpcTable {
public:
    /// Load pass: a fragment (TCP) or datagram of the stream `stream` (one direction of a connection, "" for a datagram). `seq` is the
    /// stream sequence number of the record mark (-1: unknown, the fragment stands alone), `body` the fragment without its mark and
    /// `endSeq` the sequence number after it. Asking twice for the same (packet, seq) returns the first answer.
    const RpcNote *observeFragment(const std::string &stream, uint32_t packet, int64_t seq, std::string_view body, bool last, uint32_t endSeq,
                                   size_t maxMemory, bool &lost);

    /// Load pass: the message the note's fragment completed, decoded by the dissector. Registers a call or matches a reply (the note
    /// gains the call's program / version / procedure and arguments). `conversation` is the sorted endpoint pair, `fromLow` says
    /// whether the sender is the lower of the two (a reply must come from the other side).
    const RpcNote *observeMessage(const std::string &conversation, bool fromLow, uint32_t packet, int64_t seq, const RpcMessage &msg, size_t maxMemory, bool &lost);

    /// Load pass: ports the portmapper answered, valid from `packet` on. `serverIp` is the host that answered.
    void learnPorts(uint32_t packet, const std::string &serverIp, const std::vector<RpcMapping> &mappings, size_t maxMemory, bool &lost);

    const RpcNote *note(uint32_t packet, int64_t seq) const;
    const RpcRecord *record(uint32_t index) const { return index < records_.size() ? &records_[index] : nullptr; }

    /// The program behind `ip`:`port` as of packet `packet` (nullptr: not a port the portmapper announced).
    const RpcMappedProgram *program(const std::string &ip, uint16_t port, bool udp, uint32_t packet) const;

    size_t memory() const { return memory_; }
    size_t noteCount() const { return notes_.size(); }
    size_t callCount() const { return calls_.size(); }
    size_t openRecords() const { return assemblies_.size(); }
    size_t portCount() const { return ports_.size(); }
    void clear();

    static constexpr size_t kMaxKeptBytes = 256u << 10;       // of an assembled record
    static constexpr size_t kMaxRecordBytes = 64u << 20;      // a record longer than this is dropped
    static constexpr size_t kMaxFragments = 65535;
    static constexpr size_t kMaxAssemblies = 4096;
    static constexpr size_t kMaxCalls = 65536;
    static constexpr size_t kMaxPorts = 4096;

private:
    struct NoteKey {
        uint32_t packet; uint32_t seq;
        bool operator==(const NoteKey &o) const { return packet == o.packet && seq == o.seq; }
    };
    struct NoteKeyHash {
        size_t operator()(const NoteKey &k) const { return (static_cast<size_t>(k.packet) * 0x9E3779B97F4A7C15ull) ^ (static_cast<size_t>(k.seq) << 1); }
    };
    struct Assembly {
        std::string bytes;
        uint32_t total = 0;
        uint32_t lastStart = 0;
        uint16_t fragments = 0;
        uint32_t nextSeq = 0;
        std::vector<uint32_t> packets;
        size_t cost = 0;
    };
    struct Call {
        uint32_t packet = 0, prog = 0, vers = 0, proc = 0;
        bool fromLow = false;
        uint32_t replies = 0;
        uint32_t mapProg = 0, mapVers = 0, mapProt = 0;
        std::string netid;
        uint64_t order = 0;
        NoteKey note{0, 0};
    };
    static size_t noteCost(const RpcNote &n) { return sizeof(RpcNote) + sizeof(NoteKey) + 64 + n.netid.capacity(); }
    static size_t callCost(const std::string &key, const Call &c) { return sizeof(Call) + key.capacity() + c.netid.capacity() + 96; }

    std::unordered_map<NoteKey, RpcNote, NoteKeyHash> notes_;
    std::unordered_map<std::string, Assembly> assemblies_;
    std::vector<RpcRecord> records_;
    std::unordered_map<std::string, Call> calls_;
    std::deque<std::pair<std::string, uint64_t>> callOrder_;   // insertion order for the oldest-first eviction
    uint64_t callCounter_ = 0;
    std::unordered_map<std::string, std::vector<RpcMappedProgram>> ports_;   // by "ip:port/tcp|udp", in order of `from`
    size_t memory_ = 0;
};

} // namespace dissect
