//
// Created by Süleyman Poyraz on 12.10.2024.
//

#pragma once

#include <cstdint>

#include <string>

namespace network {
    struct ConnectionID {
        std::string srcIP;
        std::string dstIP;
        uint16_t srcPort;
        uint16_t dstPort;

        // Define equality and hash functions for unordered_map
        bool operator==(const ConnectionID &other) const {
            return (srcIP == other.srcIP && dstIP == other.dstIP && srcPort == other.srcPort && dstPort == other.dstPort);
        }
    };

    struct ConnectionState {
        uint32_t clientInitialSeq; // Client's initial sequence number (from SYN)
        uint32_t serverInitialSeq; // Server's initial sequence number (from SYN-ACK)
        bool isClientSeqInitialized = false; // Client sequence initialization flag
        bool isServerSeqInitialized = false; // Server sequence initialization flag
    };
} // namespace network

// Custom hash function for ConnectionID
namespace std {
    template <>
    struct hash<network::ConnectionID> {
        std::size_t operator()(const network::ConnectionID &cid) const {
            return hash<std::string>()(cid.srcIP) ^ hash<uint16_t>()(cid.srcPort) + hash<std::string>()(cid.dstIP) ^ hash<uint16_t>()(cid.dstPort);
        }
    };
}
