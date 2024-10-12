//
// Created by Süleyman Poyraz on 12.10.2024.
//

#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>

#include <network/l4_transport/tcp_header.h>
#include <network/connection.h>

namespace network {

    class TCPConnection {
        using connectionStateMap=std::unordered_map<size_t, ConnectionState>;

        connectionStateMap connectionTable;

    public:
        void trackTCPConnections(int64_t& relativeSeq, int64_t& relativeAck, const std::string& srcIP, const std::string& dstIP, const TCPHeader& tcpHeader);

    };
} // namespace network