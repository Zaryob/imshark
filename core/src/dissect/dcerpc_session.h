#pragma once

// DCE/RPC as the load pass sees it (rule 4: decisions are made while the capture loads, detail building only reads).
//
//   stream       one place PDUs travel: a TCP connection (the two endpoints, sorted), a named pipe handle of an SMB2 connection (the
//                connection plus the FileId) or a connectionless activity (the activity UUID). Everything below lives inside it.
//   contexts     presentation context id -> abstract syntax (interface UUID + version). A Bind / Alter_context proposes them, the
//                matching Bind_ack / Alter_context_resp (same call id) accepts or rejects each one; only accepted ones are kept.
//                A Request / Response / Fault names its context id, so it can be tied to its interface.
//   calls        (stream, call id) -> opnum, interface and request packet. A Request writes it, a Response / Fault reads it (a
//                Response PDU does not carry the opnum). Connectionless PDUs name opnum and interface in every header.
//   assemblies   the fragments of one call and direction ((stream, call id, request or response side)): connection-oriented PDUs
//                arrive in order (PFC_FIRST_FRAG starts, PFC_LAST_FRAG ends); connectionless ones carry a fragment number and may be
//                reordered. The stub data of the endpoint mapper's answers is kept until the last fragment arrives; of every other
//                interface only the sizes are (nothing else reads the bytes).
//   notes        for every PDU the load pass decoded: what it resolved (interface, opnum of the request, the fragment chain it
//                belongs to). Keyed by (packet, TCP stream sequence of the message / SMB2 message, index). Detail building reads
//                the note, not the tables, which only know the state at the end of the capture.
//   endpoints    what the endpoint mapper answered (ept_map / ept_lookup): the host and TCP / UDP port of an interface. A later
//                connection (or datagram) to that port is DCE/RPC with the mapped interface. Valid from the packet that carried the
//                answer on, so that a packet's decoding does not change between the load pass and Replay.
//
// Everything counts against one memory budget (the "dcerpc" table of SessionTables). When it runs out (or a bound below is reached
// and the oldest entry is dropped) the table is state lost: PDUs without a note say so.
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace dissect {

/// Interface UUID of the endpoint mapper (EPM, C706 appendix O) in the text form formatUuid() produces.
inline constexpr const char *kDceEpmUuid = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";

// connection-oriented PDU types (C706 12.6.1); the connectionless ones share the numbers 0 .. 10
constexpr uint8_t kDceRequest = 0, kDceResponse = 2, kDceFault = 3, kDceBind = 11, kDceBindAck = 12, kDceAlterContext = 14, kDceAlterContextResp = 15;

/// One presentation context of a Bind / Alter_context.
struct DceContext {
    uint16_t id = 0;
    std::string uuid;            // abstract syntax, text form
    uint32_t version = 0;        // major in the low 16 bits, minor in the high 16 bits
};

/// What the dissector tells the table about one PDU (the load pass).
struct DcePdu {
    bool connectionless = false;
    uint8_t type = 0;
    uint32_t callId = 0;                 // connection-oriented call_id; connectionless sequence number
    bool first = true, last = true;      // position in a fragmented call (a single PDU is both)
    uint32_t fragment = 0;               // connectionless fragment number
    bool encrypted = false;              // the stub data is sealed (packet privacy) or its framing is unknown: never read as plaintext
    bool little = true;                  // integer representation of the stub data
    uint16_t contextId = 0;              // Request / Response / Fault
    uint16_t opnum = 0;                  // Request; connectionless: every PDU
    std::string interfaceUuid;           // connectionless: the interface in the header
    uint32_t interfaceVersion = 0;
    std::vector<DceContext> contexts;    // Bind / Alter_context: the proposed contexts (in order)
    std::vector<uint16_t> results;       // Bind_ack / Alter_context_resp: the result of each proposed context (0 = acceptance)
};

/// One tower the endpoint mapper answered ([MS-RPCE] 2.2.1.2 / C706 appendix L): interface and the protocol sequence behind it.
struct DceTower {
    std::string uuid;                    // interface
    uint32_t version = 0;                // major in the low 16 bits, minor in the high 16
    std::string protocol;                // "ncacn_ip_tcp", "ncadg_ip_udp", "ncacn_np", "ncalrpc", "ncacn_http", "ncacn_nb_nb", ... or ""
    std::string host;                    // IPv4 address text of the IP floor ("" if there is none)
    uint16_t port = 0;                   // TCP / UDP port of the transport floor
    std::string address;                 // named pipe / local endpoint / NetBIOS name
    bool udp = false;
};

/// A reassembled call (or a single PDU with towers) as the last fragment completed it.
struct DceMessage {
    uint32_t bytes = 0;                  // stub data bytes of all fragments
    uint16_t fragments = 0;
    std::vector<uint32_t> packets;       // packet of each fragment, in fragment order
    bool epm = false;                    // the stub data was read as an endpoint mapper answer
    std::vector<DceTower> towers;        //   the towers it contained
};

/// What the load pass resolved for one PDU.
struct DceNote {
    enum : uint16_t {
        kFragment = 1,         // part of a call split over several PDUs
        kCompletes = 2,        // this PDU completes the call: `message` is valid
        kCompletedLater = 4,   // an earlier fragment of a call completed by `completedIn`
        kMissingStart = 8,     // a fragment that is not the first and whose first fragment was not seen
        kDuplicate = 16,       // connectionless: the fragment number was seen before (first copy wins)
        kUnknownContext = 32,  // Request / Response whose context id no accepted Bind named
        kMatched = 64,         // Response / Fault whose request was seen (`requestPacket`, `opnum`)
        kAssumed = 128,        // the interface was assumed from the endpoint (well known port, port map): no accepted Bind named it
    };
    uint16_t flags = 0;
    uint8_t type = 0;
    uint16_t opnum = 0;            // Request / connectionless: the PDU's; Response / Fault: the matched request's (kMatched)
    uint32_t requestPacket = 0;
    uint32_t completedIn = 0;
    uint32_t message = 0;          // index into DceRpcTable::message() (kCompletes)
    std::string iface;             // interface UUID ("" if unknown)
    uint32_t ifVersion = 0;
};

/// The host + port the endpoint mapper told about (valid from `from` on).
struct DceMappedEndpoint {
    uint32_t from = 0;             // packet that carried the answer
    std::string uuid;
    uint32_t version = 0;
};

/// 16 byte UUID in text form; the first three fields follow the integer representation of the PDU, the rest are bytes.
std::string dceFormatUuid(const uint8_t *b, bool littleEndian);

/// Parses the stub data of an endpoint mapper answer: ept_lookup (opnum 2) or ept_map (opnum 3), NDR with the integer
/// representation `little`. Returns false when the bytes do not hold the answer's layout; `towers` then holds what was read before.
bool parseEpmAnswer(uint16_t opnum, bool little, const uint8_t *data, size_t size, std::vector<DceTower> &towers);

/// Parses one tower (C706 appendix L: floor count, then per floor a left side with the protocol identifier and a right side).
bool parseEpmTower(const uint8_t *data, size_t size, DceTower &out);

class DceRpcTable {
public:
    /// Load pass: takes the PDU `index` of the message at stream sequence `seq` (-1 if none) of `packet`. `stub` is the stub data of
    /// the PDU (the table copies it only when it needs it). `serverIp` is the address of the
    /// sender of an answer (the endpoint mapper's host); `fallbackInterface` names the interface when no accepted Bind did (well
    /// known port or the port map), "" if none. Returns the note stored, or nullptr (budget); `lost` is set when anything was refused
    /// or dropped. Asking twice for the same (packet, seq, index) returns the first answer without touching the state again.
    const DceNote *observe(const std::string &stream, uint32_t packet, int64_t seq, uint8_t index, const DcePdu &pdu, std::string_view stub,
                           const std::string &serverIp, const std::string &fallbackInterface, size_t maxMemory, bool &lost);

    const DceNote *note(uint32_t packet, int64_t seq, uint8_t index) const;
    const DceMessage *message(uint32_t index) const { return index < messages_.size() ? &messages_[index] : nullptr; }

    /// The interface the endpoint mapper mapped `ip`:`port` to, as it was at packet `packet` (nullptr if none).
    const DceMappedEndpoint *endpoint(const std::string &ip, uint16_t port, bool udp, uint32_t packet) const;

    /// Does this stream hold an accepted context named `id`? (diagnostics / tests)
    const DceContext *context(const std::string &stream, uint16_t id) const;

    size_t memory() const { return memory_; }
    size_t noteCount() const { return notes_.size(); }
    size_t messageCount() const { return messages_.size(); }
    size_t endpointCount() const { return endpoints_.size(); }
    void clear();

    static constexpr size_t kMaxProposalsPerStream = 16;
    static constexpr size_t kMaxCalls = 16384;
    static constexpr size_t kMaxAssemblies = 4096;
    static constexpr size_t kMaxMessageBytes = 16u << 20;
    static constexpr size_t kMaxFragments = 4096;
    static constexpr size_t kMaxTowers = 64;

private:
    struct NoteKey {
        uint32_t packet; uint32_t seq; uint8_t index;
        bool operator==(const NoteKey &o) const { return packet == o.packet && seq == o.seq && index == o.index; }
    };
    struct NoteKeyHash {
        size_t operator()(const NoteKey &k) const { return (static_cast<size_t>(k.packet) * 0x9E3779B97F4A7C15ull) ^ (static_cast<size_t>(k.seq) << 8) ^ k.index; }
    };
    struct Stream {
        std::map<uint32_t, std::vector<DceContext>> proposed;   // call id -> the contexts of the Bind that has not been answered
        std::map<uint16_t, DceContext> contexts;                // accepted
    };
    struct Call {
        uint16_t opnum = 0;
        std::string iface;
        uint32_t version = 0;
        uint32_t packet = 0;
        bool assumed = false;           // the interface was assumed, not named by a Bind
    };
    struct Part {
        uint32_t size = 0;
        uint32_t packet = 0;
        std::string bytes;                                      // only when the assembly keeps the stub data
    };
    struct Assembly {
        std::map<uint32_t, Part> parts;                         // fragment number (arrival index for connection-oriented) -> fragment
        std::vector<NoteKey> notes;
        int64_t lastFragment = -1;                              // number of the last fragment once it arrived
        uint32_t next = 0;                                      // connection-oriented: the number of the next fragment
        size_t bytes = 0;
        bool keepBytes = false;
        bool little = true;
        size_t cost = 0;
    };
    static size_t noteCost(const DceNote &n) { return sizeof(DceNote) + sizeof(NoteKey) + 64 + n.iface.capacity(); }
    void dropAssembly(std::unordered_map<std::string, Assembly>::iterator it);

    std::unordered_map<std::string, Stream> streams_;
    std::unordered_map<std::string, Call> calls_;
    std::unordered_map<std::string, Assembly> assemblies_;
    std::unordered_map<NoteKey, DceNote, NoteKeyHash> notes_;
    std::vector<DceMessage> messages_;
    std::unordered_map<std::string, std::vector<DceMappedEndpoint>> endpoints_;   // by "ip:port/tcp|udp", in order of `from`
    size_t memory_ = 0;
};

} // namespace dissect
