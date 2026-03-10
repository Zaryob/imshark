//
// Created by Süleyman Poyraz on 12.10.2024.
//

#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>

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
    struct DirectionState {
        uint32_t initialSeq = 0;
        bool initialized = false;
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
