//
// Created by Süleyman Poyraz on 12.10.2024.
//
#include <network/tcp_connection.h>
#include <network/connection.h>

#include <network/byteorder.h>

void network::TCPConnection::trackTCPConnections(int64_t &relativeSeq, int64_t &relativeAck,
                                                 const std::string &srcIP, const std::string &dstIP,
                                                 const network::TCPHeader &tcpHeader) {
    const Endpoint src{srcIP, network::ntoh16(tcpHeader.src_port)};
    const Endpoint dst{dstIP, network::ntoh16(tcpHeader.dest_port)};
    const uint32_t seqNum = network::ntoh32(tcpHeader.seq_num);
    const uint32_t ackNum = network::ntoh32(tcpHeader.ack_num);

    const bool syn = tcpHeader.flags & network::TCPFlags::SYN;
    const bool ack = tcpHeader.flags & network::TCPFlags::ACK;

    const ConnectionID id = ConnectionID::make(src, dst);
    auto it = connectionTable.find(id);

    // A fresh SYN with a different ISN on a known 4-tuple is a new connection (port reuse).
    if (it != connectionTable.end() && syn && !ack) {
        const ConnectionState &old = it->second;
        const DirectionState &dir = old.client == src ? old.toServer : old.toClient;
        if (dir.initialized && dir.initialSeq != seqNum) {
            connectionTable.erase(it);
            it = connectionTable.end();
        }
    }

    if (it == connectionTable.end()) {
        ConnectionState state;
        // The opener is the sender of the SYN. A SYN-ACK first means we joined mid-handshake:
        // then the receiver is the client. Otherwise the first sender is assumed to be the client.
        state.client = (syn && ack) ? dst : src;
        it = connectionTable.emplace(id, state).first;
    }

    ConnectionState &state = it->second;
    const bool fromClient = state.client == src;
    DirectionState &mine = fromClient ? state.toServer : state.toClient;
    const DirectionState &other = fromClient ? state.toClient : state.toServer;

    // The first segment seen in a direction defines its ISN (for a SYN, that is the real ISN).
    if (!mine.initialized) {
        mine.initialSeq = seqNum;
        mine.initialized = true;
    }

    relativeSeq = static_cast<uint32_t>(seqNum - mine.initialSeq);
    relativeAck = (ack && other.initialized) ? static_cast<int64_t>(static_cast<uint32_t>(ackNum - other.initialSeq)) : -1;
}
