#pragma once

#include <cstddef>
#include <functional>
#include <string>

#include <network/ip_reassembly.h>
#include <network/tcp_connection.h>
#include <packet/packet_info.h>
#include <dissect/session.h>

namespace dissect {
    class Registry;
    class TcpStreams;

    /// What a parse run produces.
    enum class ParseMode {
        Summary, // list columns only (protocol, addresses, info); tracks TCP state; no field tree
        Full,    // summary + field tree; tracks TCP state (stand-alone use, e.g. tests)
        Replay,  // summary + field tree for one packet of an already loaded capture: TCP numbers are
                 // taken from the packet instead of the connection table
    };

    /// Everything a dissector may use while decoding one frame.
    struct Context {
        packet::PacketInfo &pack;           // the packet being filled in
        const char *frame;                  // start of the captured frame (for absolute offsets)
        size_t frameLength;
        network::TCPConnection &tcp;        // per-capture TCP state (relative seq/ack)
        const Registry &registry;           // lookup of the next-layer dissector
        ParseMode mode = ParseMode::Full;
        Context(packet::PacketInfo &p, const char *f, size_t fl, network::TCPConnection &t,
                const Registry &r, ParseMode m = ParseMode::Full)
            : pack(p), frame(f), frameLength(fl), tcp(t), registry(r), mode(m) {}

        // IPv4 reassembly. While a capture is read in order, `reassembler` collects the fragments and `completed`
        // receives (fragment packet, completing packet) pairs. In Replay mode of a completing fragment
        // `reassembledPayload` (and `fragmentNumbers`) hold the whole datagram instead.
        network::IpReassembler *reassembler = nullptr;
        std::vector<std::pair<uint32_t, uint32_t>> *completed = nullptr;
        const std::vector<char> *reassembledPayload = nullptr;
        const std::vector<uint32_t> *fragmentNumbers = nullptr;
        uint8_t reassembledProtocol = 0;   // upper layer protocol of `reassembledPayload`

        // TCP message reassembly. While a capture is read in order, `streams` cuts messages out of the byte streams and
        // `completedTcp` receives (earlier segment packet, completing packet) pairs. In Replay mode of a completing packet
        // `tcpPdu` (and `tcpPduPackets`) hold the message and the packets it is made of instead.
        TcpStreams *streams = nullptr;
        std::vector<std::pair<uint32_t, uint32_t>> *completedTcp = nullptr;
        const std::string *tcpPdu = nullptr;
        const std::vector<uint32_t> *tcpPduPackets = nullptr;

        SessionTables *sessions = nullptr;

        /// Addresses of the IP layer below (raw bytes), for the pseudo header of transport checksums.
        struct Addresses {
            bool valid = false;
            uint8_t length = 0;   // 4 or 16
            unsigned char src[16] = {}, dst[16] = {};
        } addrs;

        /// Dissectors skip building the (comparatively expensive) field tree when this is false.
        bool wantFields() const { return mode != ParseMode::Summary; }

        /// Absolute offset of `p` inside the frame.
        size_t offsetOf(const char *p) const { return static_cast<size_t>(p - frame); }

        /// Marks the packet as malformed (keeps an already detected protocol name).
        void markMalformed(const std::string &reason) {
            if (pack.protocol.empty()) pack.protocol = "Malformed";
            pack.info = "[Malformed Packet: " + reason + "]";
        }

        /// Appends a top-level layer to the protocol tree. The reference is only valid until the next
        /// layer is added.
        packet::Field &addLayer(std::string name, size_t offset, size_t length) {
            return pack.fields.emplace_back(packet::Field{std::move(name), static_cast<uint32_t>(offset),
                                                          static_cast<uint32_t>(length), {}});
        }
    };

    /// Answer of a stream framer about the bytes at the start of a message.
    struct StreamFrame {
        enum class Kind {
            Reject,      // these bytes are not this protocol
            NeedMore,    // a message starts here but it is not complete yet
            Complete,    // the first message is `length` bytes long
            UntilClose,  // the message runs until the sender closes the connection (FIN/RST)
        } kind = Kind::Reject;
        size_t length = 0;
    };
    using StreamFramer = std::function<StreamFrame(const char *data, size_t available)>;

    struct Context;
    /// A dissector decodes `length` bytes starting at `data` (never reads beyond them), fills `ctx.pack`
    /// (protocol, info, header copy, field tree) and may hand the payload to the next layer through
    /// `ctx.registry`.
    using Dissector = std::function<void(Context &ctx, const char *data, size_t length)>;

    struct StreamProtocol {
        std::string name;
        StreamFramer frame;
        Dissector dissect;   // decodes ONE complete message
    };
} // namespace dissect
