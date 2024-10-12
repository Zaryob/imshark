//
// Created by Süleyman Poyraz on 12.10.2024.
//

#include <packet/packet_parser.h>

#include <iostream>
#include <iomanip>
#include <sstream>

#include <arpa/inet.h>

#include <network/utils.h>

void packet::PacketParser::parseDNSQuestion(const char* data, size_t& offset, size_t length, std::ostringstream& oss) {
    std::string domainName = network::getDomainName(data, offset, length);
    uint16_t qType = ntohs(*(uint16_t*)(data + offset));
    offset += 2;
    uint16_t qClass = ntohs(*(uint16_t*)(data + offset));
    offset += 2;

    std::string qTypeStr = (qType == 1) ? "A" : (qType == 28) ? "AAAA" : std::to_string(qType);
    oss << " " << qTypeStr << " " << domainName;
}

void packet::PacketParser::parseDNSAnswer(const char* data, size_t& offset, size_t length, std::ostringstream& oss) {
    // Parse the domain name
    std::string domainName = network::getDomainName(data, offset, length);

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

void packet::PacketParser::parseDNSPacket(const char* data, size_t length) {
    if (length < sizeof(network::DNSHeader)) {
        std::cerr << "Invalid DNS packet" << std::endl;
        return;
    }

    network::DNSHeader* dnsHeader = (network::DNSHeader*)data;
    uint16_t transactionID = ntohs(dnsHeader->transaction_id);
    uint16_t flags = ntohs(dnsHeader->flags);
    uint16_t questions = ntohs(dnsHeader->questions);
    uint16_t answerRRs = ntohs(dnsHeader->answer_rrs);
    uint16_t authorityRRs = ntohs(dnsHeader->authority_rrs);
    uint16_t additionalRRs = ntohs(dnsHeader->additional_rrs);

    std::ostringstream oss;

    if (flags & 0x8000) {
        // This is a response
        oss << "Standard query response 0x" << std::hex << transactionID << std::dec;
    } else {
        // This is a query
        oss << "Standard query 0x" << std::hex << transactionID << std::dec;
    }

    size_t offset = sizeof(network::DNSHeader);

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
    pack.info = oss.str();
}

void packet::PacketParser::parseICMP(const char* data) {
    if (pack.length < sizeof(network::ICMPHeader)) {
        std::cerr << "Invalid ICMP packet" << std::endl;
        return;
    }

    network::ICMPHeader* icmpHeader = (network::ICMPHeader*)data;
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

    pack.info = oss.str();
}

void packet::PacketParser::parseARP(network::ARPHeader arp_header) {
    std::ostringstream oss;
    oss << "ARP ";
    switch (ntohs(arp_header.opcode)) {
        case 1:
            oss << "Request: Who has " << inet_ntoa(*(struct in_addr*)&arp_header.target_protocol_addr)
                << "? Tell " << inet_ntoa(*(struct in_addr*)&arp_header.sender_protocol_addr);
            break;
        case 2:
            oss << "Reply: " << inet_ntoa(*(struct in_addr*)&arp_header.sender_protocol_addr)
                << " is at " << network::getMACAddressString(arp_header.sender_hw_addr);
            break;
        case 3:
            oss << "Announce: My IP is associated with MAC " << network::getMACAddressString(arp_header.sender_hw_addr);
            break;
        default:
            oss << "Unknown operation";
    }
    pack.info = oss.str();
}

void packet::PacketParser::parseDHCP(const network::DHCPHeader* dhcpHeader) {
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
    oss << ", Client IP: " << inet_ntoa(*(struct in_addr*)&dhcpHeader->cip_addr);
    oss << ", Your IP: " << inet_ntoa(*(struct in_addr*)&dhcpHeader->yip_addr);
    oss << ", Server IP: " << inet_ntoa(*(struct in_addr*)&dhcpHeader->sip_addr);
    oss << ", Gateway IP: " << inet_ntoa(*(struct in_addr*)&dhcpHeader->gip_addr);

    // Format hardware address
    oss << ", Client MAC: ";
    for (int i = 0; i < 6; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int)dhcpHeader->ch_addr[i];
        if (i != 5) oss << ":";
    }

    pack.info = oss.str();
}

void packet::PacketParser::parseSNMP(const char* data, size_t length) {
    // SNMP is encoded in ASN.1/BER (Binary Encoded Rules), which is complex to fully decode.
    // We can just extract basic information for now.

    std::ostringstream oss;
    oss << "SNMP message (length: " << length << ")";

    pack.info = oss.str();
}

void packet::PacketParser::parseTelnet(const char* data, size_t length) {
    std::string telnetData(data, length);
    std::ostringstream oss;
    oss << "[ Telnet data: " << telnetData.substr(0, 50) << "... ]"; // Show a snippet of the Telnet data.

    pack.info += oss.str();
}

void packet::PacketParser::parseBGP(const char* data, size_t length) {
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

void packet::PacketParser::parseSMTP(const char* data, size_t length) {
    std::string smtpData(data, length);
    std::ostringstream oss;
    oss << "SMTP data: " << smtpData.substr(0, 50) << "..."; // Show the first part of the SMTP command/data.

    pack.info = oss.str();
}


void packet::PacketParser::parseProtocolPacket(char* pack_data, uint8_t protocol){
    switch (protocol) {
        case 1: { // ICMP
            network::ICMPHeader* icmpHeader = reinterpret_cast<network::ICMPHeader*>(pack_data);
            pack.l4_header = *icmpHeader;
            pack.protocol = "ICMP";
            parseICMP(reinterpret_cast<char*>(icmpHeader));
        } break;
        case 6: { // TCP
            network::TCPHeader* tcpHeader = reinterpret_cast<network::TCPHeader*>(pack_data);
            pack.l4_header = *tcpHeader;
            // std::cout << "TCP Packet: Src Port: " << ntohs(tcpHeader->src_port)
            //          << ", Dest Port: " << ntohs(tcpHeader->dest_port) << ", Size: "<<ntohs(ipHeader->tot_length)<<", Ihl: "<<(ipHeader->ihl * 4)<< ", DataOffset: "<<(tcpHeader->data_offset*4)<<std::endl;
            uint8_t data_offset = (tcpHeader->data_offset >> 4) & 0x0F;  // Extract upper 4 bits

            pack.length = pack.length - (data_offset * 4);
            pack.protocol = "TCP";
            std::string flags = getTCPFlags(*tcpHeader);

            int64_t seq, ack;
            connection.trackTCPConnections(seq, ack, pack.source, pack.destination, *tcpHeader);

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
                const char* telnetData = pack_data + (data_offset * 4);
                parseTelnet(telnetData, pack.length);
            }
            else if (src_port == 25 || dest_port == 25) {
                pack.protocol = "SMTP";
                const char* smtpData = pack_data + (data_offset * 4);
                size_t smtpLength = pack.length;
                parseSMTP(smtpData, smtpLength);
            }
            else if (src_port == 179 || dest_port == 179) { // BGP port detection
                pack.protocol = "BGP";
                std::cout<<"BGP"<<std::endl;

                const char* bgpData = pack_data + (data_offset * 4);
                parseBGP(bgpData, pack.length);
            }
        } break;
        case 17: { // UDP
            network::UDPHeader* udpHeader = reinterpret_cast<network::UDPHeader*>(pack_data);
            pack.l4_header = *udpHeader;

            uint16_t srcPort = ntohs(udpHeader->src_port);
            uint16_t dstPort = ntohs(udpHeader->dest_port);


            if (srcPort == 53 || dstPort == 53) {
                pack.protocol = "DNS";
                parseDNSPacket(pack_data + sizeof(network::UDPHeader), ntohs(udpHeader->len) - sizeof(network::UDPHeader));
            }
            else if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68) { // Detect DHCP over UDP
                pack.protocol = "DHCP";
                network::DHCPHeader* dhcpHeader = reinterpret_cast<network::DHCPHeader*>(pack_data + sizeof(network::UDPHeader));
                pack.l7_header = *dhcpHeader;
                parseDHCP(dhcpHeader);
            }
            else if (srcPort == 161 || dstPort == 161 || srcPort == 162 || dstPort == 162) { // SNMP port detection
                pack.protocol = "SNMP";
                const char* snmpData = pack_data + sizeof(network::UDPHeader);
                parseSNMP(snmpData, ntohs(udpHeader->len) - sizeof(network::UDPHeader));
            } else {
                pack.protocol = "UDP";
                pack.info = std::to_string(srcPort) + " -> " + std::to_string(dstPort) + " Len=" + std::to_string(ntohs(udpHeader->len) - sizeof(network::UDPHeader));
            }
            pack.length = ntohs(udpHeader->len);
        } break;
        case 58: { // ICMPv6
            network::ICMPHeader* icmpHeader = reinterpret_cast<network::ICMPHeader*>(pack_data);
            pack.l4_header = *icmpHeader;
            pack.protocol = "ICMPv6";
            parseICMP(reinterpret_cast<char*>(icmpHeader));
        } break;
        default:
            // std::cout << "Other IP Protocol: " << static_cast<int>(ipHeader->protocol) << std::endl;
            pack.protocol = "Other";
    }

}

void packet::PacketParser::parsePacket(packet::PacketInfo& packet, std::vector<char>& packetData) {
    pack=packet;
    network::EthernetHeader* ethHeader = reinterpret_cast<network::EthernetHeader*>(packetData.data());
    // std::cout << "EthHeader: " << std::hex << ethHeader->type << std::dec
    //          << " Ethernet Packet: Dest MAC: " << getMACAddressString(ethHeader->dest_mac) << std::endl;
    pack.l2_header = *ethHeader;
    if (ntohs(ethHeader->type) == 0x0800) { // IP packet
        network::IPHeader* ipHeader = reinterpret_cast<network::IPHeader*>(packetData.data() + sizeof(network::EthernetHeader));
        pack.l3_header = *ipHeader;

        struct in_addr dest_addr;
        dest_addr.s_addr = ipHeader->dst_addr;
        struct in_addr src_addr;
        src_addr.s_addr = ipHeader->src_addr;
        std::string destination(inet_ntoa(dest_addr));
        std::string source(inet_ntoa(src_addr));

        pack.destination = destination;
        pack.source = source;
        pack.length = ntohs(ipHeader->tot_length) - (ipHeader->ihl * 4);
        char* pack_data = packetData.data() + sizeof(network::EthernetHeader) + (ipHeader->ihl * 4);
        parseProtocolPacket(pack_data, ipHeader->protocol);

    } else if (ntohs(ethHeader->type) == 0x86DD){ // IPv6 packet
        network::IPv6Header* ipv6Header = reinterpret_cast<network::IPv6Header*>(packetData.data() + sizeof(network::EthernetHeader));
        pack.l3_header = *ipv6Header;
        // Extract IPv6 addresses
        char srcIP[INET6_ADDRSTRLEN];
        char dstIP[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ipv6Header->src_addr, srcIP, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET6, &ipv6Header->dst_addr, dstIP, INET6_ADDRSTRLEN);

        pack.source = std::string(srcIP);
        pack.destination = std::string(dstIP);
        //std::cout<< "Source: "<<pack.source<<"  Destionation: "<<pack.destination<<std::endl;
        pack.protocol = "IPv6";

        // Parse version, traffic class, and flow label

        // Format the extracted information into the packet info
        std::ostringstream infoStream;
        infoStream << "IPv6 Version: " << (int)ipv6Header->version
                   << ", Traffic Class: " << (int)ipv6Header->traffic_class
                   << ", Flow Label: " << ipv6Header->flow_label
                   << ", Hop Limit: " << (int)ipv6Header->hop_limit;
        pack.info = infoStream.str();

        pack.length = ntohs(ipv6Header->payload_len); // No need to subtract the header size

        // Handle the next header (protocol) and parse further based on the protocol type
        char* pack_data = packetData.data() + sizeof(network::EthernetHeader) + sizeof(network::IPv6Header);

        parseProtocolPacket(pack_data, ipv6Header->next_header);

    } else if (ntohs(ethHeader->type) == 0x0806) { // ARP packet
        network::ARPHeader* arpHeader = reinterpret_cast<network::ARPHeader*>(packetData.data() + sizeof(network::EthernetHeader));
        // std::cout << "ARP Packet: Opcode " << ntohs(arpHeader->opcode) << std::endl;
        pack.l3_header = *arpHeader;
        pack.protocol = "ARP";
        pack.length = sizeof(network::ARPHeader);
        pack.destination = network::getMACAddressString(arpHeader->target_hw_addr);
        pack.source = network::getMACAddressString(arpHeader->sender_hw_addr);
        if(pack.destination == "00:00:00:00:00:00"){
            pack.destination = "Broadcast";
        }
        parseARP(*arpHeader);
    }
    else if (ntohs(ethHeader->type) == 0x8035) { // RARP packet
        network::ARPHeader* rarpHeader = reinterpret_cast<network::ARPHeader*>(packetData.data() + sizeof(network::EthernetHeader));
        pack.l3_header = *rarpHeader;
        pack.protocol = "RARP";
        pack.length = sizeof(network::ARPHeader);
        pack.destination = network::getMACAddressString(rarpHeader->target_hw_addr);
        pack.source = network::getMACAddressString(rarpHeader->sender_hw_addr);
        if (pack.destination == pack.source) {
            pack.destination = "Broadcast";
        }

        // Since RARP is typically used to request an IP from a known MAC address,
        // the function could be enhanced to handle such requests or to log them
        // depending on what `parseARP` or an equivalent `parseRARP` function does.
        // Here, for simplicity, we can just reuse the ARP parsing logic if it fits:
        parseARP(*rarpHeader);
    }
    packet = pack;

}
