//
// Created by Süleyman Poyraz on 12.10.2024.
//

#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

#include <network/l4_transport/tcp_header.h>
#include <network/connection.h>

namespace network {

    class TCPConnection {
        std::unordered_map<ConnectionID, ConnectionState> connectionTable;

    public:
        /// Computes the relative (initial-sequence-number based) sequence and acknowledgment numbers of a
        /// segment, the way Wireshark shows them. `relativeAck` is -1 when the ACK flag is not set or the
        /// ISN of the other direction is unknown.
        void trackTCPConnections(int64_t &relativeSeq, int64_t &relativeAck, const std::string &srcIP,
                                 const std::string &dstIP, const TCPHeader &tcpHeader);
    };
} // namespace network
