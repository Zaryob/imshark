//
// Created by Süleyman Poyraz on 12.10.2024.
//
#include <network/tcp_connection.h>
#include <network/connection.h>

void network::TCPConnection::trackTCPConnections(int64_t& relativeSeq, int64_t& relativeAck, const std::string& srcIP, const std::string& dstIP, const network::TCPHeader& tcpHeader) {
        uint16_t srcPort = ntohs(tcpHeader.src_port);
        uint16_t dstPort = ntohs(tcpHeader.dest_port);
        // Create a connection ID based on the IPs and ports (this could be either direction)
        network::ConnectionID connectionID = {srcIP, dstIP, srcPort, dstPort};
        network::ConnectionID reverseConnectionID = {dstIP, srcIP, dstPort, srcPort};  // Reverse for server-to-client direction

        size_t connectionHash = std::hash<network::ConnectionID>{}(connectionID);
        size_t reverseConnectionHash = std::hash<network::ConnectionID>{}(reverseConnectionID);

        // std::cout<<connectionHash<<":"<<reverseConnectionHash<<std::endl;
        // Initialize sequence and acknowledgment numbers
        uint32_t seqNum = ntohl(tcpHeader.seq_num);
        uint32_t ackNum = ntohl(tcpHeader.ack_num);

        // If no SYN packet was seen, treat the first packet as the start of the session
        if (connectionTable.find(connectionHash) == connectionTable.end() && connectionTable.find(reverseConnectionHash) == connectionTable.end()) {
            // This is the first packet seen for this connection, initialize state
            connectionTable[connectionHash] = network::ConnectionState();
            connectionTable[connectionHash].clientInitialSeq = seqNum;
            connectionTable[connectionHash].isClientSeqInitialized = true;
            // std::cout << "First observed packet for connection: Client ISN = " << seqNum << std::endl;
        }

        // Check for SYN packet (initialization)
        if (tcpHeader.flags & network::TCPFlags::SYN && !(tcpHeader.flags & network::TCPFlags::ACK)) {  // SYN, but not ACK
            // Client initiates the connection (SYN packet)
            if (connectionTable.find(connectionHash) != connectionTable.end()) {
                connectionTable[connectionHash].clientInitialSeq = seqNum;
                connectionTable[connectionHash].isClientSeqInitialized = true;
                // std::cout << "New connection: Client ISN = " << seqNum << std::endl;
                relativeSeq=0;
                relativeAck=-1;
            }
        } else if (tcpHeader.flags & network::TCPFlags::SYN && tcpHeader.flags & network::TCPFlags::ACK) {  // SYN-ACK
            // Server responds (SYN-ACK packet)
            if (connectionTable.find(reverseConnectionHash) != connectionTable.end()) {
                connectionTable[reverseConnectionHash].serverInitialSeq = seqNum;
                connectionTable[reverseConnectionHash].isServerSeqInitialized = true;
                // std::cout << "Server ISN = " << seqNum << std::endl;
                relativeSeq=0;
                relativeAck=1;
            }
        }

        // Handle regular packets and calculate relative sequence and acknowledgment numbers
        if (!(tcpHeader.flags & network::TCPFlags::SYN)) {  // Not SYN, regular packets
            if (connectionTable.find(connectionHash) != connectionTable.end()) {
                // Client to Server packet
                network::ConnectionState& state = connectionTable[connectionHash];
                if (!state.isClientSeqInitialized) {
                    state.clientInitialSeq = seqNum;  // Treat this as the first observed sequence number if SYN wasn't seen
                    state.isClientSeqInitialized = true;
                    // std::cout << "Initializing client sequence number from first observed packet." << std::endl;
                }
                relativeAck = ackNum - state.serverInitialSeq;
                relativeSeq = seqNum - state.clientInitialSeq;
                // std::cout << "Client->Server: Relative Seq = " << relativeSeq << ", Relative Ack = " << relativeAck << std::endl;
            } else if (connectionTable.find(reverseConnectionHash) != connectionTable.end()) {
                // Server to Client packet
                network::ConnectionState& state = connectionTable[reverseConnectionHash];
                if (!state.isServerSeqInitialized) {
                    state.serverInitialSeq = seqNum;  // Treat this as the first observed sequence number if SYN-ACK wasn't seen
                    state.isServerSeqInitialized = true;
                    // std::cout << "Initializing server sequence number from first observed packet." << std::endl;
                }
                relativeSeq = seqNum - state.serverInitialSeq;
                relativeAck = ackNum - state.clientInitialSeq;
                // std::cout << "Server->Client: Relative Seq = " << relativeSeq << ", Relative Ack = " << relativeAck << std::endl;
            }
        }
    }