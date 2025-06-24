//
// Created by Süleyman Poyraz on 12.10.2024.
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <utility>
#include <vector>

namespace network {
    /// One endpoint of a TCP connection.
    struct Endpoint {
        std::string ip;
        uint16_t port = 0;

        bool operator==(const Endpoint &other) const { return port == other.port && ip == other.ip; }
        bool operator<(const Endpoint &other) const {
            return ip != other.ip ? ip < other.ip : port < other.port;
        }
    };

    /// Direction independent connection key: `low` is always the smaller endpoint.
    struct ConnectionID {
        Endpoint low;
        Endpoint high;

        static ConnectionID make(const Endpoint &a, const Endpoint &b) {
            return b < a ? ConnectionID{b, a} : ConnectionID{a, b};
        }

        bool operator==(const ConnectionID &other) const { return low == other.low && high == other.high; }
    };

    /// Per-direction initial sequence number.
    /// What the TCP analysis found about one segment (bit flags).
    enum TcpAnalysisFlag : uint16_t {
        kTcpRetransmission = 1,   // carries data that was already seen
        kTcpOutOfOrder = 2,       // arrives late, filling a gap left by an earlier segment
        kTcpLostSegment = 4,      // a previous segment was not captured (sequence jumped ahead)
        kTcpDuplicateAck = 8,     // pure ACK repeating the previous ACK number
        kTcpZeroWindow = 16,      // the sender advertises a zero receive window
        kTcpKeepAlive = 32,       // 0/1 byte probe one byte behind the next expected sequence number
        kTcpWindowUpdate = 64,    // pure ACK that only changes the advertised window
    };

    struct TcpAnalysis {
        uint16_t flags = 0;
        uint8_t duplicateAckCount = 0;   // "Dup ACK #n" (valid with kTcpDuplicateAck)
    };

    struct DirectionState {
        uint32_t initialSeq = 0;
        bool initialized = false;

        // --- sequence analysis (per direction)
        bool haveNext = false;
        uint32_t nextSeq = 0;                                   // highest sequence number seen + 1
        std::vector<std::pair<uint32_t, uint32_t>> gaps;        // [begin, end) ranges that were skipped
        bool haveAck = false;
        uint32_t lastAck = 0;
        uint32_t lastWindow = 0;
        uint8_t dupAcks = 0;
    };

    struct ConnectionState {
        Endpoint client;        // the side that opened the connection (or was seen first)
        DirectionState toServer; // client -> server
        DirectionState toClient; // server -> client
    };
} // namespace network

namespace std {
    template<>
    struct hash<network::ConnectionID> {
        std::size_t operator()(const network::ConnectionID &cid) const {
            auto combine = [](std::size_t seed, std::size_t v) {
                return seed ^ (v + 0x9e3779b97f4a7c15ull + (seed << 6) + (seed >> 2));
            };
            std::size_t h = std::hash<std::string>()(cid.low.ip);
            h = combine(h, std::hash<uint16_t>()(cid.low.port));
            h = combine(h, std::hash<std::string>()(cid.high.ip));
            h = combine(h, std::hash<uint16_t>()(cid.high.port));
            return h;
        }
    };
} // namespace std
