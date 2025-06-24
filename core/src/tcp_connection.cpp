//
// Created by Süleyman Poyraz on 12.10.2024.
//
#include <algorithm>

#include <network/tcp_connection.h>
#include <network/connection.h>

#include <network/byteorder.h>

void network::TCPConnection::trackTCPConnections(int64_t &relativeSeq, int64_t &relativeAck,
                                                 const std::string &srcIP, const std::string &dstIP,
                                                 const network::TCPHeader &tcpHeader) {
    trackAndAnalyze(relativeSeq, relativeAck, srcIP, dstIP, tcpHeader, 0);
}

network::TcpAnalysis network::TCPConnection::trackAndAnalyze(int64_t &relativeSeq, int64_t &relativeAck,
                                                             const std::string &srcIP, const std::string &dstIP,
                                                             const network::TCPHeader &tcpHeader, uint32_t payloadLength) {
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

    // ---- sequence analysis -------------------------------------------------------------------------
    TcpAnalysis result;
    const bool rst = tcpHeader.flags & network::TCPFlags::RST;
    const bool fin = tcpHeader.flags & network::TCPFlags::FIN;
    const uint32_t window = network::ntoh16(tcpHeader.window);
    const uint32_t segLen = payloadLength + (syn ? 1 : 0) + (fin ? 1 : 0); // sequence space used by the segment
    const uint32_t endSeq = seqNum + segLen;
    const auto ahead = [](uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b); }; // a - b with wrap-around

    const bool keepAlive = !syn && !fin && !rst && payloadLength <= 1 && mine.haveNext && seqNum + 1 == mine.nextSeq;
    if (keepAlive) {
        result.flags |= kTcpKeepAlive;
    } else if (segLen > 0) {
        if (!mine.haveNext) {
            mine.nextSeq = endSeq; // first segment seen in this direction: nothing to compare with
            mine.haveNext = true;
        } else if (ahead(seqNum, mine.nextSeq) > 0) {
            result.flags |= kTcpLostSegment;
            mine.gaps.emplace_back(mine.nextSeq, seqNum);
            if (mine.gaps.size() > 32) mine.gaps.erase(mine.gaps.begin());
            mine.nextSeq = endSeq;
        } else if (ahead(seqNum, mine.nextSeq) == 0) {
            mine.nextSeq = endSeq;
        } else {
            // starts before the next expected byte: fills a gap (out of order) or repeats data (retransmission)
            bool fillsGap = false;
            for (auto it = mine.gaps.begin(); it != mine.gaps.end();) {
                const uint32_t gapBegin = it->first, gapEnd = it->second;
                const bool overlaps = ahead(seqNum, gapEnd) < 0 && ahead(endSeq, gapBegin) > 0;
                if (!overlaps) { ++it; continue; }
                fillsGap = true;
                // remove the covered part of the gap
                const bool cutsFront = ahead(seqNum, gapBegin) <= 0, cutsBack = ahead(endSeq, gapEnd) >= 0;
                if (cutsFront && cutsBack) { it = mine.gaps.erase(it); continue; }
                if (cutsFront) it->first = endSeq;
                else if (cutsBack) it->second = seqNum;
                else { // the segment sits in the middle: split the gap
                    const uint32_t oldEnd = it->second;
                    it->second = seqNum;
                    it = mine.gaps.insert(it + 1, {endSeq, oldEnd}) + 1;
                    continue;
                }
                ++it;
            }
            result.flags |= fillsGap ? kTcpOutOfOrder : kTcpRetransmission;
            if (ahead(endSeq, mine.nextSeq) > 0) mine.nextSeq = endSeq;
        }
    } else if (!mine.haveNext && !rst) {
        mine.nextSeq = seqNum; // a pure ACK as the first segment still tells where the stream stands
        mine.haveNext = true;
    }

    // acknowledgment behaviour: only for segments without data (and not SYN/FIN/RST)
    if (!syn && !fin && !rst) {
        if (window == 0) result.flags |= kTcpZeroWindow;
        if (payloadLength == 0 && ack && !keepAlive) {
            if (mine.haveAck && ackNum == mine.lastAck && window == mine.lastWindow && window != 0) {
                result.flags |= kTcpDuplicateAck;
                mine.dupAcks = static_cast<uint8_t>(std::min<int>(mine.dupAcks + 1, 255));
                result.duplicateAckCount = mine.dupAcks;
            } else {
                if (mine.haveAck && ackNum == mine.lastAck && window != mine.lastWindow && window != 0) result.flags |= kTcpWindowUpdate;
                mine.dupAcks = 0;
            }
        } else if (payloadLength > 0) {
            mine.dupAcks = 0;
        }
        if (ack) {
            mine.haveAck = true;
            mine.lastAck = ackNum;
            mine.lastWindow = window;
        }
    }
    return result;
}
