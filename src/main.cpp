#include <imgui/imgui.h>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <unordered_map>


#include <GLFW/glfw3.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

#include <ip/ethernet_header.h>
#include <pcap/global_header.h>
#include <pcap/packet_header.h>

#include <pcapng/block_header.h>
#include <pcapng/interface_description_block.h>
#include <pcapng/section_header_block.h>
#include <pcapng/simple_packet_block.h>
#include <pcapng/enhanced_packet_block.h>
#include <pcapng/interface_statistics_block.h>
#include <pcapng/name_resolution_block.h>

#include <arpa/inet.h>


struct PacketInfo {
    int number;
    double time;
    std::string source;
    std::string destination;
    std::string protocol;
    uint32_t length;
    std::string info;
    PacketInfo(int num) : number(num){}

    PacketInfo(int num, double t, const std::string& src, const std::string& dest,
               const std::string& proto, uint32_t len, const std::string& inf)
        : number(num), time(t), source(src), destination(dest), protocol(proto), length(len), info(inf) {}
};



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

// Custom hash function for ConnectionID
namespace std {
    template <>
    struct hash<ConnectionID> {
        std::size_t operator()(const ConnectionID &cid) const {
            return hash<std::string>()(cid.srcIP) ^ hash<uint16_t>()(cid.srcPort) + hash<std::string>()(cid.dstIP) ^ hash<uint16_t>()(cid.dstPort);
        }
    };
}


struct ConnectionState {
    uint32_t clientInitialSeq; // Client's initial sequence number (from SYN)
    uint32_t serverInitialSeq; // Server's initial sequence number (from SYN-ACK)
    bool isClientSeqInitialized = false; // Client sequence initialization flag
    bool isServerSeqInitialized = false; // Server sequence initialization flag
};


using connectionStateMap=std::unordered_map<size_t, ConnectionState>;


void trackTCPConnections(int64_t& relativeSeq, int64_t& relativeAck, const std::string& srcIP, const std::string& dstIP, const TCPHeader& tcpHeader, connectionStateMap& connectionTable) {
    uint16_t srcPort = ntohs(tcpHeader.src_port);
    uint16_t dstPort = ntohs(tcpHeader.dest_port);

    // Create a connection ID based on the IPs and ports (this could be either direction)
    ConnectionID connectionID = {srcIP, dstIP, srcPort, dstPort};
    ConnectionID reverseConnectionID = {dstIP, srcIP, dstPort, srcPort};  // Reverse for server-to-client direction

    size_t connectionHash = std::hash<ConnectionID>{}(connectionID);
    size_t reverseConnectionHash = std::hash<ConnectionID>{}(reverseConnectionID);

    // std::cout<<connectionHash<<":"<<reverseConnectionHash<<std::endl;
    // Initialize sequence and acknowledgment numbers
    uint32_t seqNum = ntohl(tcpHeader.seq_num);
    uint32_t ackNum = ntohl(tcpHeader.ack_num);

    // If no SYN packet was seen, treat the first packet as the start of the session
    if (connectionTable.find(connectionHash) == connectionTable.end() && connectionTable.find(reverseConnectionHash) == connectionTable.end()) {
        // This is the first packet seen for this connection, initialize state
        connectionTable[connectionHash] = ConnectionState();
        connectionTable[connectionHash].clientInitialSeq = seqNum;
        connectionTable[connectionHash].isClientSeqInitialized = true;
        // std::cout << "First observed packet for connection: Client ISN = " << seqNum << std::endl;
    }

    // Check for SYN packet (initialization)
    if (tcpHeader.flags & TCP_SYN && !(tcpHeader.flags & TCP_ACK)) {  // SYN, but not ACK
        // Client initiates the connection (SYN packet)
        if (connectionTable.find(connectionHash) != connectionTable.end()) {
            connectionTable[connectionHash].clientInitialSeq = seqNum;
            connectionTable[connectionHash].isClientSeqInitialized = true;
            // std::cout << "New connection: Client ISN = " << seqNum << std::endl;
            relativeSeq=0;
            relativeAck=-1;
        }
    } else if (tcpHeader.flags & TCP_SYN && tcpHeader.flags & TCP_ACK) {  // SYN-ACK
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
    if (!(tcpHeader.flags & TCP_SYN)) {  // Not SYN, regular packets
        if (connectionTable.find(connectionHash) != connectionTable.end()) {
            // Client to Server packet
            ConnectionState& state = connectionTable[connectionHash];
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
            ConnectionState& state = connectionTable[reverseConnectionHash];
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

std::string parseDomainName(const char* data, size_t& offset, size_t length) {
    std::string domain;
    while (offset < length) {
        uint8_t labelLength = data[offset++];
        if (labelLength == 0) break; // End of domain name
        if (!domain.empty()) domain += ".";
        domain += std::string(data + offset, labelLength);
        offset += labelLength;
    }
    return domain;
}

void parseDNSQuestion(const char* data, size_t& offset, size_t length, std::ostringstream& oss) {
    std::string domainName = parseDomainName(data, offset, length);
    uint16_t qType = ntohs(*(uint16_t*)(data + offset));
    offset += 2;
    uint16_t qClass = ntohs(*(uint16_t*)(data + offset));
    offset += 2;

    std::string qTypeStr = (qType == 1) ? "A" : (qType == 28) ? "AAAA" : std::to_string(qType);
    oss << " " << qTypeStr << " " << domainName;
}

void parseDNSAnswer(const char* data, size_t& offset, size_t length, std::ostringstream& oss) {
    // Parse the domain name
    std::string domainName = parseDomainName(data, offset, length);

    uint16_t type = ntohs(*(uint16_t*)(data + offset));
    offset += 2;
    uint16_t classCode = ntohs(*(uint16_t*)(data + offset));
    offset += 2;
    uint32_t ttl = ntohl(*(uint32_t*)(data + offset));
    offset += 4;
    uint16_t dataLength = ntohs(*(uint16_t*)(data + offset));
    offset += 2;

    oss << " " << domainName;

    // Check the type of the record
    if (type == 1 && dataLength == 4) {  // A record (IPv4)
        uint32_t ipAddr = *(uint32_t*)(data + offset);
        struct in_addr ip;
        ip.s_addr = ipAddr;
        oss << " A " << inet_ntoa(ip);
    } else if (type == 28 && dataLength == 16) {  // AAAA record (IPv6)
        char ipv6Addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, data + offset, ipv6Addr, INET6_ADDRSTRLEN);
        oss << " AAAA " << ipv6Addr;
    } else if (type == 6) {  // SOA record
        // SOA is a bit more complicated; it contains multiple fields (mname, rname, serial, refresh, retry, expire, minimum)
        oss << " SOA";  // You could parse the SOA fields here as needed
    }

    offset += dataLength;
}

void parseDNSPacket(const char* data, size_t length, PacketInfo& packetInfo) {
    if (length < sizeof(DNSHeader)) {
        std::cerr << "Invalid DNS packet" << std::endl;
        return;
    }

    DNSHeader* dnsHeader = (DNSHeader*)data;
    uint16_t transactionID = ntohs(dnsHeader->transactionID);
    uint16_t flags = ntohs(dnsHeader->flags);
    uint16_t questions = ntohs(dnsHeader->questions);
    uint16_t answerRRs = ntohs(dnsHeader->answerRRs);
    uint16_t authorityRRs = ntohs(dnsHeader->authorityRRs);
    uint16_t additionalRRs = ntohs(dnsHeader->additionalRRs);

    std::ostringstream oss;

    if (flags & 0x8000) {
        // This is a response
        oss << "Standard query response 0x" << std::hex << transactionID << std::dec;
    } else {
        // This is a query
        oss << "Standard query 0x" << std::hex << transactionID << std::dec;
    }

    size_t offset = sizeof(DNSHeader);

    // Parse the DNS questions
    for (int i = 0; i < questions; ++i) {
        parseDNSQuestion(data, offset, length, oss);
    }

    // Parse the DNS answers (if it's a response)
    for (int i = 0; i < answerRRs; ++i) {
        parseDNSAnswer(data, offset, length, oss);
    }

    /*oss << "DNS [Transaction ID: " << transactionID
        << ", Flags: 0x" << std::hex << flags << std::dec
        << ", Questions: " << questions
        << ", Answer RRs: " << answerRRs
        << ", Authority RRs: " << authorityRRs
        << ", Additional RRs: " << additionalRRs << "]";
    */
    packetInfo.info = oss.str();
}

void parseICMP(const char* data, size_t length, PacketInfo& packetInfo) {
    if (length < sizeof(ICMPHeader)) {
        std::cerr << "Invalid ICMP packet" << std::endl;
        return;
    }

    ICMPHeader* icmpHeader = (ICMPHeader*)data;
    std::ostringstream oss;

    switch (icmpHeader->type) {
        case 8: // Echo Request (Ping)
            oss << "ICMP Echo Request, Identifier=" << ntohs(icmpHeader->identifier)
                << ", Sequence=" << ntohs(icmpHeader->sequence);
        break;
        case 0: // Echo Reply
            oss << "ICMP Echo Reply, Identifier=" << ntohs(icmpHeader->identifier)
                << ", Sequence=" << ntohs(icmpHeader->sequence);
        break;
        case 3: // Destination Unreachable
            oss << "ICMP Destination Unreachable, Code=" << (int)icmpHeader->code;
        break;
        case 11: // Time Exceeded
            oss << "ICMP Time Exceeded, Code=" << (int)icmpHeader->code;
        break;
        default:
            oss << "ICMP Type=" << (int)icmpHeader->type << ", Code=" << (int)icmpHeader->code;
        break;
    }

    packetInfo.info = oss.str();
}


void displayPackets(const std::vector<PacketInfo>& packets) {
    if (ImGui::BeginChild("Packet List")) {
        if (ImGui::BeginTable("Packets", 7, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable)) {
            ImGui::TableSetupColumn("No.");
            ImGui::TableSetupColumn("Time");
            ImGui::TableSetupColumn("Source");
            ImGui::TableSetupColumn("Destination");
            ImGui::TableSetupColumn("Protocol");
            ImGui::TableSetupColumn("Length");
            ImGui::TableSetupColumn("Info");
            ImGui::TableHeadersRow();

            for (const auto& packet : packets) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%d", packet.number);
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%.6lf", packet.time);
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%s", packet.source.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%s", packet.destination.c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%s", packet.protocol.c_str());
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("%u", packet.length);
                ImGui::TableSetColumnIndex(6);
                ImGui::Text("%s", packet.info.c_str());
            }

            ImGui::EndTable();
        }
        ImGui::EndChild();
    }
}

void HexView(const char* title, const char* mem, size_t len,  std::vector<PacketInfo>& packets) {
    if (ImGui::Begin(title)) {
        /*for (size_t i = 0; i < len; i += 16) {
            ImGui::Text("%08X ", i);
            for (size_t j = 0; j < 16 && i + j < len; ++j) {
                ImGui::SameLine();
                ImGui::Text("%02X ", (unsigned char)mem[i + j]);
            }
            ImGui::SameLine(400);
            for (size_t j = 0; j < 16 && i + j < len; ++j) {
                char c = isprint((unsigned char)mem[i + j]) ? mem[i + j] : '.';
                ImGui::Text("%c", c);
            }
        }*/
        displayPackets(packets);
    }
    ImGui::End();
}

bool isPcapng(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    uint32_t magic_number;
    if (file.read(reinterpret_cast<char*>(&magic_number), sizeof(magic_number))) {
        // Check against PCAPNG magic numbers
        return (magic_number == 0x0A0D0D0A);
    }
    return false;
}

std::string getMACAddressString(const uint8_t sender_hw_addr[6]) {
    std::ostringstream ss;
    for (int i = 0; i < 6; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sender_hw_addr[i]);
        if (i < 5) // Don't add a colon after the last byte
            ss << ":";
    }
    return ss.str();

}
// Function to parse and print TCP flags
std::string getTCPFlags(const TCPHeader& tcpHeader) {
    std::string flags;
    if (tcpHeader.flags & TCP_FIN) flags += "FIN";
    if (tcpHeader.flags & TCP_SYN) flags = flags + (flags.empty() ? "" : ", ") + "SYN";
    if (tcpHeader.flags & TCP_RST) flags = flags + (flags.empty() ? "" : ", ") +  "RST";
    if (tcpHeader.flags & TCP_PSH) flags = flags + (flags.empty() ? "" : ", ") +  "PSH";
    if (tcpHeader.flags & TCP_ACK) flags = flags + (flags.empty() ? "" : ", ") +  "ACK";
    if (tcpHeader.flags & TCP_URG) flags = flags + (flags.empty() ? "" : ", ") +  "URG";
    return flags;
}

void parseARP(ARPHeader arp_header, PacketInfo& packetInfo) {
    std::ostringstream oss;
    oss << "ARP ";
    if (ntohs(arp_header.opcode) == 1) {
        oss << "Request: Who has " << inet_ntoa(*(struct in_addr*)&arp_header.target_hw_addr)
            << "? Tell " << inet_ntoa(*(struct in_addr*)&arp_header.sender_hw_addr);
    } else if (ntohs(arp_header.opcode) == 2) {
        oss << "Reply: " << inet_ntoa(*(struct in_addr*)&arp_header.sender_hw_addr)
            << " is at " << getMACAddressString(arp_header.sender_hw_addr);
    }
    packetInfo.info = oss.str();
}

void parseDHCP(const DHCPHeader* dhcpHeader, PacketInfo& pack) {
    // Extract DHCP fields and format them for display
    std::ostringstream oss;

    // Message type: 1 = BOOTREQUEST, 2 = BOOTREPLY
    oss << "DHCP ";
    if (dhcpHeader->op == 1) {
        oss << "Request";
    } else if (dhcpHeader->op == 2) {
        oss << "Reply";
    }

    oss << ", XID: 0x" << std::hex << ntohl(dhcpHeader->xid) << std::dec;
    oss << ", Client IP: " << inet_ntoa(*(struct in_addr*)&dhcpHeader->ciaddr);
    oss << ", Your IP: " << inet_ntoa(*(struct in_addr*)&dhcpHeader->yiaddr);
    oss << ", Server IP: " << inet_ntoa(*(struct in_addr*)&dhcpHeader->siaddr);
    oss << ", Gateway IP: " << inet_ntoa(*(struct in_addr*)&dhcpHeader->giaddr);

    // Format hardware address
    oss << ", Client MAC: ";
    for (int i = 0; i < 6; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)dhcpHeader->chaddr[i];
        if (i != 5) oss << ":";
    }

    pack.info = oss.str();
}
void parseSNMP(const char* data, size_t length, PacketInfo& pack) {
    // SNMP is encoded in ASN.1/BER (Binary Encoded Rules), which is complex to fully decode.
    // We can just extract basic information for now.

    std::ostringstream oss;
    oss << "SNMP message (length: " << length << ")";

    pack.info = oss.str();
}

void parseTelnet(const char* data, size_t length, PacketInfo& pack) {
    std::string telnetData(data, length);
    std::ostringstream oss;
    oss << "[ Telnet data: " << telnetData.substr(0, 50) << "... ]"; // Show a snippet of the Telnet data.

    pack.info += oss.str();
}

void parseBGP(const char* data, size_t length, PacketInfo& pack) {
    // Basic BGP message parsing, BGP messages can be OPEN, UPDATE, NOTIFICATION, KEEPALIVE.
    std::ostringstream oss;
    uint8_t messageType = data[18];  // BGP message type is at the 19th byte of the BGP message.

    oss << " [ BGP: ";
    switch (messageType) {
        case 1: oss << "OPEN"; break;
        case 2: oss << "UPDATE"; break;
        case 3: oss << "NOTIFICATION"; break;
        case 4: oss << "KEEPALIVE"; break;
        default: oss << "Unknown";
    }
    oss << " ]";
    pack.info += oss.str();
}

void parseSMTP(const char* data, size_t length, PacketInfo& pack) {
    std::string smtpData(data, length);
    std::ostringstream oss;
    oss << "SMTP data: " << smtpData.substr(0, 50) << "..."; // Show the first part of the SMTP command/data.

    pack.info = oss.str();
}

void processPacket(PacketInfo& pack, std::vector<char>& packetData, connectionStateMap& connectionMap) {
    EthernetHeader* ethHeader = reinterpret_cast<EthernetHeader*>(packetData.data());
    // std::cout << "EthHeader: " << std::hex << ethHeader->type << std::dec
    //          << " Ethernet Packet: Dest MAC: " << getMACAddressString(ethHeader->dest_mac) << std::endl;

    if (ntohs(ethHeader->type) == 0x0800) { // IP packet
        IPHeader* ipHeader = reinterpret_cast<IPHeader*>(packetData.data() + sizeof(EthernetHeader));

        struct in_addr dest_addr;
        dest_addr.s_addr = ipHeader->daddr;
        struct in_addr src_addr;
        src_addr.s_addr = ipHeader->saddr;
        std::string destination(inet_ntoa(dest_addr));
        std::string source(inet_ntoa(src_addr));

        pack.destination = destination;
        pack.source = source;

        switch (ipHeader->protocol) {
            case 1: { // ICMP
                ICMPHeader* icmpHeader = reinterpret_cast<ICMPHeader*>(packetData.data() + sizeof(EthernetHeader) + (ipHeader->ihl * 4));
                pack.protocol = "ICMP";
                parseICMP(reinterpret_cast<char*>(icmpHeader), ntohs(ipHeader->tot_length) - (ipHeader->ihl * 4), pack);
            } break;
            case 6: { // TCP
                char* tcp_data = packetData.data() + sizeof(EthernetHeader) + (ipHeader->ihl * 4);
                TCPHeader* tcpHeader = reinterpret_cast<TCPHeader*>(tcp_data);
                // std::cout << "TCP Packet: Src Port: " << ntohs(tcpHeader->src_port)
                //          << ", Dest Port: " << ntohs(tcpHeader->dest_port) << ", Size: "<<ntohs(ipHeader->tot_length)<<", Ihl: "<<(ipHeader->ihl * 4)<< ", DataOffset: "<<(tcpHeader->data_offset*4)<<std::endl;
                uint8_t data_offset = (tcpHeader->data_offset >> 4) & 0x0F;  // Extract upper 4 bits

                pack.length = ntohs(ipHeader->tot_length) - ((ipHeader->ihl * 4) + (data_offset * 4));
                pack.protocol = "TCP";
                std::string flags = getTCPFlags(*tcpHeader);

                int64_t seq, ack;
                trackTCPConnections(seq, ack, source, destination, *tcpHeader, connectionMap);

                //uint32_t seq= ntohl(tcpHeader->seq_num);
                //uint32_t ack= ntohl(tcpHeader->ack_num);

                uint16_t window= ntohs(tcpHeader->window);
                pack.info = std::to_string(ntohs(tcpHeader->src_port)) + " -> " + std::to_string(ntohs(tcpHeader->dest_port)) + " [" + flags + "] " +
                    (seq >= 0 ? (" Seq=" + std::to_string(seq) ): "" ) +
                    (ack >= 0 ? (" Ack=" + std::to_string(ack) ): "" ) +
                    (window > 0 ? (" Win=" + std::to_string(window) ): "" );

                uint16_t src_port = ntohs(tcpHeader->src_port);
                uint16_t dest_port = ntohs(tcpHeader->dest_port);
                if (src_port == 23 || dest_port == 23) { // Telnet port detection
                    pack.protocol = "Telnet";
                    std::cout<<"Telnet"<<std::endl;
                    const char* telnetData = tcp_data + (data_offset * 4);
                    parseTelnet(telnetData, pack.length, pack);
                }
                else if (src_port == 25 || dest_port == 25) {
                    pack.protocol = "SMTP";
                    const char* smtpData = tcp_data + (data_offset * 4);
                    size_t smtpLength = pack.length;
                    parseSMTP(smtpData, smtpLength, pack);
                }
                else if (src_port == 179 || dest_port == 179) { // BGP port detection
                    pack.protocol = "BGP";
                    std::cout<<"BGP"<<std::endl;

                    const char* bgpData = tcp_data + (data_offset * 4);
                    parseBGP(bgpData, pack.length, pack);
                }
            } break;

            case 17: { // UDP
                char* udp_data = packetData.data() + sizeof(EthernetHeader) + (ipHeader->ihl * 4);
                UDPHeader* udpHeader = reinterpret_cast<UDPHeader*>(udp_data);

                uint16_t srcPort = ntohs(udpHeader->src_port);
                uint16_t dstPort = ntohs(udpHeader->dest_port);


                if (srcPort == 53 || dstPort == 53) {
                    pack.protocol = "DNS";
                    parseDNSPacket(udp_data + sizeof(UDPHeader), ntohs(udpHeader->len) - sizeof(UDPHeader), pack);
                } else if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68) { // Detect DHCP over UDP
                    pack.protocol = "DHCP";
                    DHCPHeader* dhcpHeader = reinterpret_cast<DHCPHeader*>(udp_data + sizeof(UDPHeader));
                    parseDHCP(dhcpHeader, pack);
                }
                if (srcPort == 161 || dstPort == 161 || srcPort == 162 || dstPort == 162) { // SNMP port detection
                    pack.protocol = "SNMP";
                    const char* snmpData = udp_data + sizeof(UDPHeader);
                    parseSNMP(snmpData, ntohs(udpHeader->len) - sizeof(UDPHeader), pack);
                } else {
                    pack.protocol = "UDP";
                    pack.info = std::to_string(srcPort) + " -> " + std::to_string(dstPort) + " Len=" + std::to_string(ntohs(udpHeader->len) - sizeof(UDPHeader));
                }
                pack.length = ntohs(udpHeader->len);
            } break;

            default:
                // std::cout << "Other IP Protocol: " << static_cast<int>(ipHeader->protocol) << std::endl;
                pack.protocol = "Other";
        }
    } else if (ntohs(ethHeader->type) == 0x0806) { // ARP packet
        ARPHeader* arpHeader = reinterpret_cast<ARPHeader*>(packetData.data() + sizeof(EthernetHeader));
        // std::cout << "ARP Packet: Opcode " << ntohs(arpHeader->opcode) << std::endl;
        pack.protocol = "ARP";
        pack.length = sizeof(ARPHeader);
        parseARP(*arpHeader, pack);
    }
}

/// PCAP FILE PROCESSING

void processPcapFile(const std::string& filepath, std::vector<PacketInfo>& packets,connectionStateMap& connectionMap) {
    std::ifstream file(filepath, std::ios::binary);
    GlobalHeader gHeader;
    file.read(reinterpret_cast<char*>(&gHeader), sizeof(GlobalHeader));

    if (gHeader.magic_number != 0xa1b2c3d4) {
        std::cerr << "Incompatible PCAP file format" << std::endl;
        return;
    }

    uint32_t tsTimeOffset = 0;
    uint32_t usTimeOffset = 0;
    int packetNumber = 0;

    while (file.peek() != EOF) {
        PacketHeader pHeader = {0};
        file.read(reinterpret_cast<char*>(&pHeader), sizeof(PacketHeader));

        std::vector<char> packetData(pHeader.incl_len);
        file.read(packetData.data(), pHeader.incl_len);

        PacketInfo pack(++packetNumber);
        pack.time = (pHeader.ts_sec) + 10e-7 * (pHeader.ts_usec) - (tsTimeOffset + 10e-7 * (usTimeOffset));
        // Process the packet data using the shared packet processor
        processPacket(pack, packetData, connectionMap);

        packets.emplace_back(pack);
    }

    file.close();
}

/// PCAPNG FILE PROCESSING


void processSectionHeaderBlock(std::ifstream& file, SectionHeaderBlock section) {

    // std::cout << "Section Header Block:" << std::endl;
    // std::cout << "Magic Number: " << std::hex << section.magicNumber << std::dec << std::endl;
    // std::cout << "Version: " << section.versionMajor << "." << section.versionMinor << std::endl;
    // std::cout << "Section Length: " << section.sectionLength << std::endl;

    // Skip any options and the footer (optional to handle if needed)
    //uint32_t remainingBytes = blockTotalLength - sizeof(section) - sizeof(uint32_t);
    //file.seekg(remainingBytes, std::ios::cur);
    // Verify block length trailer to match header
    if (section.blockTotalLength != section.blockTotalLengthRedundant) {
        std::cerr<< "Mismatched block length at end of block. Expected: " <<section.blockTotalLength <<", Got: "<< section.blockTotalLengthRedundant<< std::endl;
        file.close();
        return;
    }

}

void processEnhancedPacketBlock(EnhancedPacketBlock& section, PacketInfo& pack, uint32_t& tsTimeOffset, uint32_t& usTimeOffset, connectionStateMap& connectionMap) {
    // std::cout << "Process Packet Block" << std::endl;

    // Check for mismatched block length
    if (section.blockTotalLength != section.blockTotalLengthRedundant) {
        std::cerr << "Mismatched block length at end of block" << std::endl;
        return;
    }

    double timestampResolution = 1.0 / 1000; // Default milliseconds
    uint64_t fullTimestamp = ((uint64_t)section.timestampUpper << 32) | section.timestampLower;
    fullTimestamp *= timestampResolution;
    uint64_t seconds = fullTimestamp / 1'000'000;
    uint64_t milliseconds = fullTimestamp % 1'000'000;

    if (tsTimeOffset == 0) tsTimeOffset = seconds;
    if (usTimeOffset == 0) usTimeOffset = milliseconds;

    pack.time = (seconds + 10e-7 * (milliseconds)) - (tsTimeOffset + 10e-7 * (usTimeOffset));

    // Process the packet data using the shared packet processor
    processPacket(pack, section.packetData, connectionMap);
}

void processInterfaceDescriptionBlock(std::ifstream& file, InterfaceDescriptionBlock& idb) {
    // Read the fixed-length fields of the Interface Description Block
    //file.read(reinterpret_cast<char*>(&section), sizeof(section));

    // std::cout << "Interface Description Block: " << std::endl;
    // std::cout << "Block Type: " << std::hex << idb.blockType << std::dec << std::endl;
    // std::cout << "Block Total Length: " << idb.blockTotalLength << std::endl;
    // std::cout << "Link Type: " << idb.linkType << std::endl;
    // std::cout << "Snap Length: " << idb.snapLen << std::endl;
    // std::cout << "TL Red Length: " << idb.blockTotalLengthRedundant << std::endl;
    if (idb.blockTotalLength != idb.blockTotalLengthRedundant) {
        std::cerr<< "Mismatched block length at end of block. Expected: " <<idb.blockTotalLength <<", Got: "<< idb.blockTotalLengthRedundant<< std::endl;
        file.close();
        return;
    }

}


void processSimplePacketBlock(SimplePacketBlock spb, PacketInfo& pack, uint32_t& tsTimeOffset, uint32_t& usTimeOffset) {

    if (spb.blockTotalLength != spb.blockTotalLengthRedundant) {
        std::cerr<< "Mismatched block length at end of block. Expected: " <<spb.blockTotalLength <<", Got: "<< spb.blockTotalLengthRedundant<< std::endl;
        exit(0);
        return;
    }
}

// Function to print the statistics data
void printStatistics(InterfaceStatisticsBlock isb) {
    if (isb.blockTotalLength != isb.blockTotalLengthRedundant) {
        std::cerr<< "Mismatched block length at end of block. Expected: " <<isb.blockTotalLength <<", Got: "<< isb.blockTotalLengthRedundant<< std::endl;
        exit(0);
        return;
    }
    uint64_t fullTimestamp = ((uint64_t)isb.timestampHigh << 32) | isb.timestampLow;
    // std::cout << "Interface ID: " << isb.interfaceID << std::endl;
    // std::cout << "Timestamp: " << fullTimestamp << " (high: " << isb.timestampHigh << ", low: " << isb.timestampLow << ")" << std::endl;
    // std::cout << "Options Size: " << isb.options.size() << " bytes" << std::endl;

    // Additional parsing of options could be done here (if required).
}

// Function to print the name resolution records
void printNameResolutionRecords(NameResolutionBlock nrb) {
    // std::cout << "Name Resolution Records:" << std::endl;
    for (const auto& record : nrb.records) {
        // std::cout << "Address: " << record.address << ", Resolved Name: " << record.resolvedName << std::endl;
    }
}
void processPcapngFile(const std::string& filepath, std::vector<PacketInfo>& packets, connectionStateMap& connectionMap) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr<< "Failed to open file: " << filepath << std:: endl;
        return;
    }

    uint64_t blockIdx = 0;
    uint32_t packetNumber = 0;
    uint32_t tsTimeOffset=0;
    uint32_t usTimeOffset=0;

    while (file.peek() != EOF) {
        BlockHeader header;
        header.deserialize(file);
        // std::cout << "Block Type: "<<std::setfill('0') << std::setw(8) << std::hex << header.blockTotalLength << std::dec<< std::endl;
        // std::cout << "Block Length: "<< header.blockTotalLength << std::endl;
        switch (header.blockType) {
            case BT_SHB: // BT_SHB
            {
                SectionHeaderBlock section(header);
                // Read SHB fields
                section.deserializeSectionFields(file);
                processSectionHeaderBlock(file, section);
            }
            break;
            case BT_IDB:
            {
                InterfaceDescriptionBlock idb(header);
                idb.deserializeInterfaceFields(file);
                processInterfaceDescriptionBlock(file, idb);
            }
            break;
            case BT_SPB:
            {
                SimplePacketBlock spb(header);

                spb.deserializePacketFields(file);

                PacketInfo pack(++packetNumber);
                processSimplePacketBlock(spb, pack, tsTimeOffset, usTimeOffset);
                packets.emplace_back(pack);
            }
            break;
            case BT_ISB:
            {
                InterfaceStatisticsBlock isb(header);
                isb.deserializeStatisticsFields(file);

                // Process Interface Statistics Block
                printStatistics(isb);
            }
            break;
            case BT_EPB:
            {
                EnhancedPacketBlock pb(header);
                pb.deserializeEnhancedFields(file);
                PacketInfo pack(++packetNumber);
                processEnhancedPacketBlock(pb, pack, tsTimeOffset, usTimeOffset, connectionMap);

                packets.emplace_back(pack);
            }
            break;
            case BT_NRB:
            {
                NameResolutionBlock nrb(header);
                nrb.deserializeNameResolutionFields(file);

                // Process Name Resolution Block
                printNameResolutionRecords(nrb);
            }
            break;
            // Add cases for other block types...
            default:
                // std::cout << "Unhandled block type:" << std::hex << header.blockType << std::dec <<std::endl;
                // Skip unknown block
                file.seekg(header.blockTotalLength - sizeof(BlockHeader), std::ios::cur);
            break;
        }
    }

    // std::cout <<"File processed successfully"<<std::endl;
    file.close();
    return;
}

int main() {
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return -1;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); // 3.2+ only
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

    GLFWwindow* window = glfwCreateWindow(1280, 720, "PCAP Hex Viewer", nullptr, nullptr);
    if (window == nullptr) {
        glfwTerminate();
        std::cerr << "Failed to create GLFW window" << std::endl;
        return -1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 150");

    //std::string filepath = "/Users/zaryob/Downloads/udp.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/netlink-nflog.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/iperf3-udp.pcapng";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/ipv4frags.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/dhcp.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/telnet-raw.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/bgpsec.pcap";  // Example file path
    std::string filepath = "/Users/zaryob/Downloads/smtp.pcap";  // Example file path

    std::vector<char> buffer;
    std::vector<PacketInfo> packets;
    connectionStateMap connectionTable;

    // std::cout <<"Sizeof Vector"<<sizeof(std::vector<char>)<<std::endl<<
    //           "Sizeof BlockHeader "<<sizeof(BlockHeader)<<std::endl<<
    //           "Sizeof Interface Description Block "<<sizeof(InterfaceDescriptionBlock)<<std::endl<<
    //           "Sizeof Simple Packet Block "<<sizeof(SimplePacketBlock)<<std::endl<<
    //           "Sizeof Section Header Block "<<sizeof(SectionHeaderBlock)<<std::endl;

    if(std::filesystem::is_regular_file(filepath))
    {
        if (isPcapng(filepath)) {
            processPcapngFile(filepath, packets, connectionTable);
        } else {
            processPcapFile(filepath, packets, connectionTable);
        }
    }else {
        std::cerr << "Invalid file path: " << filepath << std::endl;
    }

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        HexView("PCAP File Hex Viewer", buffer.data(), buffer.size(),packets);

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}


