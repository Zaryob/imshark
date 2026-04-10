//
// Created by Süleyman Poyraz on 12.10.2024.
//

#include <packet/packet_parser.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

#include <arpa/inet.h>

#include <network/utils.h>

namespace {
    using packet::Field;

    std::string hexString(uint32_t value, int width) {
        std::ostringstream ss;
        ss << "0x" << std::hex << std::setw(width) << std::setfill('0') << value;
        return ss.str();
    }

    // Copies a T out of [base, base + avail) at `off`. Returns false if it does not fit.
    // memcpy (instead of reinterpret_cast) also avoids unaligned-access UB.
    template<typename T>
    bool readStruct(const char *base, size_t avail, size_t off, T &out) {
        if (off > avail || avail - off < sizeof(T)) return false;
        std::memcpy(&out, base + off, sizeof(T));
        return true;
    }

    uint16_t be16(const char *p) {
        uint16_t v;
        std::memcpy(&v, p, sizeof(v));
        return ntohs(v);
    }

    uint32_t be32(const char *p) {
        uint32_t v;
        std::memcpy(&v, p, sizeof(v));
        return ntohl(v);
    }

    // `addr` points to 4 bytes in network byte order.
    std::string ip4(const void *addr) {
        char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, addr, buf, sizeof(buf));
        return buf;
    }

    std::string ip4(uint32_t addr) { return ip4(&addr); }
} // namespace

void packet::PacketParser::markMalformed(const std::string &reason) {
    if (pack.protocol.empty()) pack.protocol = "Malformed";
    pack.info = "[Malformed Packet: " + reason + "]";
}

bool packet::PacketParser::parseDNSQuestion(const char *data, size_t &offset, size_t length, std::ostringstream &oss) {
    std::string domainName = network::getDomainName(data, offset, length);
    if (length < offset || length - offset < 4) return false;
    uint16_t qType = be16(data + offset);
    offset += 4; // type + class

    std::string qTypeStr = (qType == 1) ? "A" : (qType == 28) ? "AAAA" : std::to_string(qType);
    oss << " " << qTypeStr << " " << domainName;
    return true;
}

bool packet::PacketParser::parseDNSAnswer(const char *data, size_t &offset, size_t length, std::ostringstream &oss) {
    std::string domainName = network::getDomainName(data, offset, length);
    if (length < offset || length - offset < 10) return false;

    uint16_t type = be16(data + offset);
    uint16_t dataLength = be16(data + offset + 8);
    offset += 10; // type, class, ttl, rdlength

    if (length - offset < dataLength) return false;

    oss << " " << domainName;

    if (type == 1 && dataLength == 4) { // A record (IPv4)
        oss << " A " << ip4(data + offset);
    } else if (type == 28 && dataLength == 16) { // AAAA record (IPv6)
        char ipv6Addr[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, data + offset, ipv6Addr, INET6_ADDRSTRLEN);
        oss << " AAAA " << ipv6Addr;
    } else if (type == 6) { // SOA record
        oss << " SOA";
    }

    offset += dataLength;
    return true;
}

void packet::PacketParser::parseDNSPacket(const char *data, size_t length) {
    network::DNSHeader dnsHeader;
    if (!readStruct(data, length, 0, dnsHeader)) {
        markMalformed("DNS message too short");
        return;
    }

    uint16_t transactionID = ntohs(dnsHeader.transaction_id);
    uint16_t flags = ntohs(dnsHeader.flags);
    uint16_t questions = ntohs(dnsHeader.questions);
    uint16_t answerRRs = ntohs(dnsHeader.answer_rrs);

    {
        const size_t o = offsetOf(data);
        Field &l = pack.fields.emplace_back(Field{std::string("Domain Name System (") + ((flags & 0x8000) ? "response" : "query") + ")",
                                                  static_cast<uint32_t>(o), static_cast<uint32_t>(length), {}});
        l.add("Transaction ID: " + hexString(transactionID, 4), o, 2);
        l.add("Flags: " + hexString(flags, 4), o + 2, 2);
        l.add("Questions: " + std::to_string(questions), o + 4, 2);
        l.add("Answer RRs: " + std::to_string(answerRRs), o + 6, 2);
        l.add("Authority RRs: " + std::to_string(ntohs(dnsHeader.authority_rrs)), o + 8, 2);
        l.add("Additional RRs: " + std::to_string(ntohs(dnsHeader.additional_rrs)), o + 10, 2);
        if (length > sizeof(network::DNSHeader)) {
            l.add("Records (" + std::to_string(length - sizeof(network::DNSHeader)) + " bytes)", o + sizeof(network::DNSHeader),
                  length - sizeof(network::DNSHeader));
        }
    }

    std::ostringstream oss;
    oss << ((flags & 0x8000) ? "Standard query response 0x" : "Standard query 0x")
        << std::hex << transactionID << std::dec;

    size_t offset = sizeof(network::DNSHeader);
    bool ok = true;

    for (int i = 0; ok && i < questions; ++i) {
        ok = parseDNSQuestion(data, offset, length, oss);
    }
    for (int i = 0; ok && i < answerRRs; ++i) {
        ok = parseDNSAnswer(data, offset, length, oss);
    }
    if (!ok) oss << " [Malformed Packet: truncated DNS record]";

    pack.info = oss.str();
}

void packet::PacketParser::parseICMP(const char *data, size_t length) {
    network::ICMPHeader icmpHeader;
    if (!readStruct(data, length, 0, icmpHeader)) {
        markMalformed("ICMP message too short");
        return;
    }

    std::ostringstream oss;
    switch (icmpHeader.type) {
        case 8: // Echo Request (Ping)
            oss << "ICMP Echo Request, Identifier=" << ntohs(icmpHeader.identifier)
                << ", Sequence=" << ntohs(icmpHeader.sequence);
            break;
        case 0: // Echo Reply
            oss << "ICMP Echo Reply, Identifier=" << ntohs(icmpHeader.identifier)
                << ", Sequence=" << ntohs(icmpHeader.sequence);
            break;
        case 3: // Destination Unreachable
            oss << "ICMP Destination Unreachable, Code=" << (int) icmpHeader.code;
            break;
        case 11: // Time Exceeded
            oss << "ICMP Time Exceeded, Code=" << (int) icmpHeader.code;
            break;
        default:
            oss << "ICMP Type=" << (int) icmpHeader.type << ", Code=" << (int) icmpHeader.code;
            break;
    }

    pack.info = oss.str();
}

void packet::PacketParser::parseARP(const network::ARPHeader &arp_header) {
    std::ostringstream oss;
    oss << "ARP ";
    switch (ntohs(arp_header.opcode)) {
        case 1:
            oss << "Request: Who has " << ip4(arp_header.target_protocol_addr)
                << "? Tell " << ip4(arp_header.sender_protocol_addr);
            break;
        case 2:
            oss << "Reply: " << ip4(arp_header.sender_protocol_addr)
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

void packet::PacketParser::parseDHCP(const network::DHCPHeader *dhcpHeader) {
    std::ostringstream oss;

    // Message type: 1 = BOOTREQUEST, 2 = BOOTREPLY
    oss << "DHCP ";
    if (dhcpHeader->op == 1) {
        oss << "Request";
    } else if (dhcpHeader->op == 2) {
        oss << "Reply";
    }

    oss << ", XID: 0x" << std::hex << ntohl(dhcpHeader->xid) << std::dec;
    oss << ", Client IP: " << ip4(dhcpHeader->cip_addr);
    oss << ", Your IP: " << ip4(dhcpHeader->yip_addr);
    oss << ", Server IP: " << ip4(dhcpHeader->sip_addr);
    oss << ", Gateway IP: " << ip4(dhcpHeader->gip_addr);

    oss << ", Client MAC: ";
    for (int i = 0; i < 6; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int) dhcpHeader->ch_addr[i];
        if (i != 5) oss << ":";
    }

    pack.info = oss.str();
}

void packet::PacketParser::parseSNMP(const char *data, size_t length) {
    // SNMP is encoded in ASN.1/BER, which is complex to fully decode; only the size is reported for now.
    (void) data;
    std::ostringstream oss;
    oss << "SNMP message (length: " << length << ")";

    pack.info = oss.str();
}

void packet::PacketParser::parseTelnet(const char *data, size_t length) {
    std::string telnetData(data, std::min<size_t>(length, 50)); // snippet only
    pack.info += "[ Telnet data: " + telnetData + (length > 50 ? "..." : "") + " ]";
}

void packet::PacketParser::parseBGP(const char *data, size_t length) {
    // BGP message type is the 19th byte of the BGP message (after 16 marker + 2 length bytes).
    if (length < 19) {
        pack.info += " [ BGP: truncated ]";
        return;
    }
    uint8_t messageType = static_cast<uint8_t>(data[18]);

    std::ostringstream oss;
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

void packet::PacketParser::parseSMTP(const char *data, size_t length) {
    std::string smtpData(data, std::min<size_t>(length, 50)); // first part of the command/data
    pack.info = "SMTP data: " + smtpData + (length > 50 ? "..." : "");
}

std::string packet::PacketParser::describeTCPOptions(const char *p, size_t len) {
    std::string out;
    size_t i = 0;
    while (i < len) {
        const uint8_t kind = static_cast<uint8_t>(p[i]);
        if (kind == 0) break;                  // end of option list
        if (kind == 1) { ++i; continue; }      // NOP padding
        if (i + 1 >= len) break;
        const size_t optLen = static_cast<uint8_t>(p[i + 1]);
        if (optLen < 2 || optLen > len - i) break; // malformed option, stop decoding
        switch (kind) {
            case 2: if (optLen == 4) out += " MSS=" + std::to_string(be16(p + i + 2)); break;
            case 3: if (optLen == 3) out += " WS=" + std::to_string(static_cast<uint8_t>(p[i + 2])); break;
            case 4: out += " SACK_PERM"; break;
            case 5: out += " SACK"; break;
            case 8:
                if (optLen == 10)
                    out += " TSval=" + std::to_string(be32(p + i + 2)) + " TSecr=" + std::to_string(be32(p + i + 6));
                break;
            default: break;
        }
        i += optLen;
    }
    return out;
}

namespace {
    std::string etherTypeName(uint16_t type) {
        switch (type) {
            case 0x0800: return "IPv4";
            case 0x86DD: return "IPv6";
            case 0x0806: return "ARP";
            case 0x8035: return "RARP";
            case 0x8100: return "802.1Q VLAN";
            case 0x88A8: return "802.1ad VLAN";
            default: return "unknown";
        }
    }

    std::string linkTypeName(uint32_t type) {
        switch (type) {
            case 0: return "NULL";
            case 1: return "Ethernet";
            case 12:
            case 14:
            case 101: return "Raw IP";
            case 108: return "OpenBSD loopback";
            case 113: return "Linux cooked v1";
            case 276: return "Linux cooked v2";
            default: return "unsupported";
        }
    }

    std::string tcpFlagNames(uint8_t flags) {
        static const std::pair<uint8_t, const char *> names[] = {
            {0x80, "CWR"}, {0x40, "ECE"}, {0x20, "URG"}, {0x10, "ACK"}, {0x08, "PSH"}, {0x04, "RST"}, {0x02, "SYN"}, {0x01, "FIN"}};
        std::string out;
        for (const auto &[bit, name]: names) {
            if (flags & bit) out += (out.empty() ? "" : ", ") + std::string(name);
        }
        return out;
    }

    // Printable preview of a payload for the details tree
    std::string asciiPreview(const char *data, size_t length, size_t max = 40) {
        std::string out;
        for (size_t i = 0; i < std::min(length, max); ++i) {
            const auto c = static_cast<unsigned char>(data[i]);
            out += (c >= 32 && c < 127) ? static_cast<char>(c) : '.';
        }
        if (length > max) out += "...";
        return out;
    }
} // namespace

// Adds a layer that only shows its payload as raw data (Telnet, SMTP, BGP, SNMP)
void packet::PacketParser::addDataLayer(const std::string &name, const char *payload, size_t length) {
    const size_t o = offsetOf(payload);
    Field &l = pack.fields.emplace_back(Field{name, static_cast<uint32_t>(o), static_cast<uint32_t>(length), {}});
    if (length > 0) l.add("Data (" + std::to_string(length) + " bytes): " + asciiPreview(payload, length), o, length);
}

// `length` is the number of bytes actually available at pack_data (captured, clamped to the IP payload).
void packet::PacketParser::parseProtocolPacket(const char *pack_data, size_t length, uint8_t protocol) {
    const size_t o = offsetOf(pack_data);
    switch (protocol) {
        case 1: // ICMP
        case 58: { // ICMPv6
            network::ICMPHeader icmpHeader;
            if (!readStruct(pack_data, length, 0, icmpHeader)) {
                markMalformed("ICMP message too short");
                break;
            }
            pack.l4_header = icmpHeader;
            pack.protocol = (protocol == 1) ? "ICMP" : "ICMPv6";
            parseICMP(pack_data, length);

            Field &l = pack.fields.emplace_back(Field{protocol == 1 ? "Internet Control Message Protocol"
                                                                    : "Internet Control Message Protocol v6",
                                                      static_cast<uint32_t>(o), static_cast<uint32_t>(length), {}});
            l.add("Type: " + std::to_string(icmpHeader.type), o, 1);
            l.add("Code: " + std::to_string(icmpHeader.code), o + 1, 1);
            l.add("Checksum: " + hexString(ntohs(icmpHeader.checksum), 4), o + 2, 2);
            l.add("Identifier: " + std::to_string(ntohs(icmpHeader.identifier)), o + 4, 2);
            l.add("Sequence Number: " + std::to_string(ntohs(icmpHeader.sequence)), o + 6, 2);
            if (length > sizeof(icmpHeader)) {
                l.add("Data (" + std::to_string(length - sizeof(icmpHeader)) + " bytes)", o + sizeof(icmpHeader),
                      length - sizeof(icmpHeader));
            }
        } break;
        case 6: { // TCP
            network::TCPHeader tcpHeader;
            if (!readStruct(pack_data, length, 0, tcpHeader)) {
                markMalformed("TCP header truncated");
                pack.protocol = "TCP";
                break;
            }
            const size_t headerLen = static_cast<size_t>((tcpHeader.data_offset >> 4) & 0x0F) * 4;
            pack.l4_header = tcpHeader;
            pack.protocol = "TCP";
            if (headerLen < sizeof(network::TCPHeader) || headerLen > length) {
                markMalformed("invalid TCP data offset");
                break;
            }

            pack.length = pack.length >= headerLen ? pack.length - headerLen : 0;
            const char *payload = pack_data + headerLen;
            const size_t payloadLen = std::min<size_t>(pack.length, length - headerLen);

            std::string flags = getTCPFlags(tcpHeader);

            int64_t seq = -1, ack = -1;
            connection.trackTCPConnections(seq, ack, pack.source, pack.destination, tcpHeader);

            uint16_t window = ntohs(tcpHeader.window);
            uint16_t src_port = ntohs(tcpHeader.src_port);
            uint16_t dest_port = ntohs(tcpHeader.dest_port);
            const std::string options = describeTCPOptions(pack_data + sizeof(network::TCPHeader),
                                                           headerLen - sizeof(network::TCPHeader));
            pack.info = std::to_string(src_port) + " -> " + std::to_string(dest_port) + " [" + flags + "] " +
                        (seq >= 0 ? (" Seq=" + std::to_string(seq)) : "") +
                        (ack >= 0 ? (" Ack=" + std::to_string(ack)) : "") +
                        (window > 0 ? (" Win=" + std::to_string(window)) : "") + options;

            {
                Field &l = pack.fields.emplace_back(Field{
                    "Transmission Control Protocol, Src Port: " + std::to_string(src_port) + ", Dst Port: " +
                        std::to_string(dest_port) + (seq >= 0 ? ", Seq: " + std::to_string(seq) : "") +
                        ", Len: " + std::to_string(payloadLen),
                    static_cast<uint32_t>(o), static_cast<uint32_t>(headerLen + payloadLen), {}});
                l.add("Source Port: " + std::to_string(src_port), o, 2);
                l.add("Destination Port: " + std::to_string(dest_port), o + 2, 2);
                l.add("Sequence Number: " + (seq >= 0 ? std::to_string(seq) + " (relative), " : std::string()) +
                          std::to_string(ntohl(tcpHeader.seq_num)) + " (raw)", o + 4, 4);
                l.add("Acknowledgment Number: " + (ack >= 0 ? std::to_string(ack) + " (relative), " : std::string()) +
                          std::to_string(ntohl(tcpHeader.ack_num)) + " (raw)", o + 8, 4);
                l.add("Header Length: " + std::to_string(headerLen) + " bytes", o + 12, 1);
                Field &f = l.add("Flags: " + hexString(tcpHeader.flags, 3) + " (" + tcpFlagNames(tcpHeader.flags) + ")", o + 13, 1);
                static const std::pair<uint8_t, const char *> bits[] = {
                    {0x80, "Congestion Window Reduced"}, {0x40, "ECN-Echo"}, {0x20, "Urgent"}, {0x10, "Acknowledgment"},
                    {0x08, "Push"}, {0x04, "Reset"}, {0x02, "Syn"}, {0x01, "Fin"}};
                for (const auto &[bit, name]: bits) {
                    f.add(std::string(name) + ": " + ((tcpHeader.flags & bit) ? "Set" : "Not set"), o + 13, 1);
                }
                l.add("Window: " + std::to_string(window), o + 14, 2);
                l.add("Checksum: " + hexString(ntohs(tcpHeader.checksum), 4), o + 16, 2);
                l.add("Urgent Pointer: " + std::to_string(ntohs(tcpHeader.urgent_pointer)), o + 18, 2);
                if (headerLen > sizeof(network::TCPHeader)) {
                    l.add("Options:" + (options.empty() ? std::string(" (no decoded options)") : options), o + 20,
                          headerLen - sizeof(network::TCPHeader));
                }
                if (payloadLen > 0) l.add("TCP payload (" + std::to_string(payloadLen) + " bytes)", o + headerLen, payloadLen);
            }

            if (src_port == 23 || dest_port == 23) {
                pack.protocol = "Telnet";
                parseTelnet(payload, payloadLen);
                addDataLayer("Telnet", payload, payloadLen);
            } else if (src_port == 25 || dest_port == 25) {
                pack.protocol = "SMTP";
                parseSMTP(payload, payloadLen);
                addDataLayer("Simple Mail Transfer Protocol", payload, payloadLen);
            } else if (src_port == 179 || dest_port == 179) {
                pack.protocol = "BGP";
                parseBGP(payload, payloadLen);
                addDataLayer("Border Gateway Protocol", payload, payloadLen);
            }
        } break;
        case 17: { // UDP
            network::UDPHeader udpHeader;
            if (!readStruct(pack_data, length, 0, udpHeader)) {
                markMalformed("UDP header truncated");
                pack.protocol = "UDP";
                break;
            }
            pack.l4_header = udpHeader;

            uint16_t srcPort = ntohs(udpHeader.src_port);
            uint16_t dstPort = ntohs(udpHeader.dest_port);
            const size_t udpLen = ntohs(udpHeader.len);
            pack.length = udpLen;
            if (udpLen < sizeof(network::UDPHeader)) {
                pack.protocol = "UDP";
                markMalformed("invalid UDP length");
                break;
            }

            const char *payload = pack_data + sizeof(network::UDPHeader);
            const size_t payloadLen = std::min(udpLen, length) - sizeof(network::UDPHeader);

            {
                Field &l = pack.fields.emplace_back(Field{
                    "User Datagram Protocol, Src Port: " + std::to_string(srcPort) + ", Dst Port: " + std::to_string(dstPort),
                    static_cast<uint32_t>(o), static_cast<uint32_t>(sizeof(network::UDPHeader) + payloadLen), {}});
                l.add("Source Port: " + std::to_string(srcPort), o, 2);
                l.add("Destination Port: " + std::to_string(dstPort), o + 2, 2);
                l.add("Length: " + std::to_string(udpLen), o + 4, 2);
                l.add("Checksum: " + hexString(ntohs(udpHeader.checksum), 4), o + 6, 2);
                if (payloadLen > 0) l.add("UDP payload (" + std::to_string(payloadLen) + " bytes)", o + 8, payloadLen);
            }

            if (srcPort == 53 || dstPort == 53) {
                pack.protocol = "DNS";
                parseDNSPacket(payload, payloadLen);
            } else if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68) { // DHCP over UDP
                pack.protocol = "DHCP";
                network::DHCPHeader dhcpHeader;
                if (readStruct(payload, payloadLen, 0, dhcpHeader)) {
                    pack.l7_header = dhcpHeader;
                    parseDHCP(&dhcpHeader);

                    const size_t p = offsetOf(payload);
                    Field &l = pack.fields.emplace_back(Field{"Dynamic Host Configuration Protocol", static_cast<uint32_t>(p),
                                                              static_cast<uint32_t>(payloadLen), {}});
                    l.add("Message type: " + std::string(dhcpHeader.op == 1 ? "Boot Request (1)" : dhcpHeader.op == 2 ? "Boot Reply (2)"
                                                                                                                       : std::to_string(dhcpHeader.op)), p, 1);
                    l.add("Hardware type: " + hexString(dhcpHeader.hw_type, 2), p + 1, 1);
                    l.add("Hardware address length: " + std::to_string(dhcpHeader.hw_len), p + 2, 1);
                    l.add("Hops: " + std::to_string(dhcpHeader.hops), p + 3, 1);
                    l.add("Transaction ID: " + hexString(ntohl(dhcpHeader.xid), 8), p + 4, 4);
                    l.add("Seconds elapsed: " + std::to_string(ntohs(dhcpHeader.secs)), p + 8, 2);
                    l.add("Flags: " + hexString(ntohs(dhcpHeader.flags), 4), p + 10, 2);
                    l.add("Client IP address: " + ip4(dhcpHeader.cip_addr), p + 12, 4);
                    l.add("Your (client) IP address: " + ip4(dhcpHeader.yip_addr), p + 16, 4);
                    l.add("Next server IP address: " + ip4(dhcpHeader.sip_addr), p + 20, 4);
                    l.add("Relay agent IP address: " + ip4(dhcpHeader.gip_addr), p + 24, 4);
                    l.add("Client MAC address: " + network::getMACAddressString(dhcpHeader.ch_addr), p + 28, 6);
                } else {
                    markMalformed("DHCP message too short");
                }
            } else if (srcPort == 161 || dstPort == 161 || srcPort == 162 || dstPort == 162) { // SNMP
                pack.protocol = "SNMP";
                parseSNMP(payload, payloadLen);
                addDataLayer("Simple Network Management Protocol", payload, payloadLen);
            } else {
                pack.protocol = "UDP";
                pack.info = std::to_string(srcPort) + " -> " + std::to_string(dstPort) +
                            " Len=" + std::to_string(udpLen - sizeof(network::UDPHeader));
            }
        } break;
        default:
            pack.protocol = "Other";
    }
}

namespace {
    constexpr uint32_t kLinkNull = 0, kLinkEthernet = 1, kLinkRawBsd = 12, kLinkRawOpenBsd = 14,
            kLinkRaw = 101, kLinkLoop = 108, kLinkLinuxSll = 113, kLinkLinuxSll2 = 276;
} // namespace

void packet::PacketParser::parsePacket(packet::PacketInfo &packet, std::vector<char> &packetData) {
    pack = packet;
    pack.vlan_ids.clear();
    pack.fields.clear();
    const char *base = packetData.data();
    frame_ = base;
    const size_t len = packetData.size();
    pack.length = static_cast<uint32_t>(len);

    {
        Field &frame = pack.fields.emplace_back(Field{"Frame " + std::to_string(pack.number) + ": " + std::to_string(len) +
                                                          " bytes on wire", 0, static_cast<uint32_t>(len), {}});
        frame.add("Frame Number: " + std::to_string(pack.number));
        frame.add("Frame Length: " + std::to_string(len) + " bytes", 0, len);
        frame.add("Link type: " + std::to_string(pack.link_type) + " (" + linkTypeName(pack.link_type) + ")");
    }

    // Link layer: find out where the network header starts and which protocol it carries.
    uint16_t etherType = 0;
    size_t l3Offset = 0;
    network::EthernetHeader ethHeader{};
    bool haveEthernet = false;

    switch (pack.link_type) {
        case kLinkEthernet: {
            if (!readStruct(base, len, 0, ethHeader)) {
                markMalformed("frame too short for Ethernet header");
                packet = pack;
                return;
            }
            haveEthernet = true;
            pack.l2_header = ethHeader;
            etherType = ntohs(ethHeader.type);
            l3Offset = sizeof(network::EthernetHeader);
            const uint16_t outerType = etherType;
            // 802.1Q / 802.1ad (QinQ) tags: 2 bytes TCI + 2 bytes inner EtherType each
            while (etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100) {
                if (len < l3Offset || len - l3Offset < 4) {
                    markMalformed("VLAN tag truncated");
                    pack.protocol = "VLAN";
                    pack.l2_size = static_cast<uint16_t>(std::min<size_t>(l3Offset, UINT16_MAX));
                    packet = pack;
                    return;
                }
                pack.vlan_ids.push_back(be16(base + l3Offset) & 0x0FFF);
                etherType = be16(base + l3Offset + 2);
                l3Offset += 4;
            }

            Field &eth = pack.fields.emplace_back(Field{"Ethernet II, Src: " + network::getMACAddressString(ethHeader.src_mac) +
                                                            ", Dst: " + network::getMACAddressString(ethHeader.dest_mac),
                                                        0, static_cast<uint32_t>(l3Offset), {}});
            eth.add("Destination: " + network::getMACAddressString(ethHeader.dest_mac), 0, 6);
            eth.add("Source: " + network::getMACAddressString(ethHeader.src_mac), 6, 6);
            eth.add("Type: " + etherTypeName(outerType) + " (" + hexString(outerType, 4) + ")", 12, 2);
            for (size_t i = 0; i < pack.vlan_ids.size(); ++i) {
                eth.add("802.1Q Virtual LAN, ID: " + std::to_string(pack.vlan_ids[i]), 14 + 4 * i, 4);
            }
        } break;
        case kLinkNull:
        case kLinkLoop: { // 4-byte address family; byte order of the capturing host (NULL) or network (LOOP)
            if (len < 4) { markMalformed("frame too short for loopback header"); packet = pack; return; }
            uint32_t af;
            std::memcpy(&af, base, sizeof(af));
            if (pack.link_type == kLinkLoop) af = ntohl(af); // OpenBSD loop: always network order
            else if (af > 0xFFFF) af = __builtin_bswap32(af); // NULL: written by a host of the other endianness
            etherType = af == 2 ? 0x0800 : (af == 10 || af == 24 || af == 28 || af == 30) ? 0x86DD : 0;
            l3Offset = 4;
        } break;
        case kLinkRaw:
        case kLinkRawBsd:
        case kLinkRawOpenBsd: { // no link header: the IP version nibble tells v4 from v6
            if (len < 1) { markMalformed("empty frame"); packet = pack; return; }
            const uint8_t version = static_cast<uint8_t>(base[0]) >> 4;
            etherType = version == 4 ? 0x0800 : version == 6 ? 0x86DD : 0;
            l3Offset = 0;
        } break;
        case kLinkLinuxSll: { // "cooked" capture v1: 16 bytes, protocol in the last 2
            if (len < 16) { markMalformed("frame too short for Linux cooked header"); packet = pack; return; }
            etherType = be16(base + 14);
            l3Offset = 16;
        } break;
        case kLinkLinuxSll2: { // "cooked" capture v2: 20 bytes, protocol first
            if (len < 20) { markMalformed("frame too short for Linux cooked v2 header"); packet = pack; return; }
            etherType = be16(base);
            l3Offset = 20;
        } break;
        default:
            pack.protocol = "Unknown";
            pack.info = "Unsupported link type " + std::to_string(pack.link_type);
            packet = pack;
            return;
    }
    pack.l2_size = static_cast<uint16_t>(l3Offset);
    if (!haveEthernet && l3Offset > 0) {
        pack.fields.emplace_back(Field{linkTypeName(pack.link_type) + " link header", 0, static_cast<uint32_t>(l3Offset), {}});
    }

    if (etherType == 0x0800) { // IPv4
        network::IPHeader ipHeader;
        if (!readStruct(base, len, l3Offset, ipHeader)) {
            markMalformed("IPv4 header truncated");
            pack.protocol = "IPv4";
            packet = pack;
            return;
        }
        pack.l3_header = ipHeader;
        pack.destination = ip4(ipHeader.dst_addr);
        pack.source = ip4(ipHeader.src_addr);

        const size_t ipHeaderLen = static_cast<size_t>(ipHeader.ihl) * 4;
        if (ipHeaderLen < sizeof(network::IPHeader) || l3Offset + ipHeaderLen > len) {
            markMalformed("invalid IPv4 header length");
            pack.protocol = "IPv4";
            packet = pack;
            return;
        }

        const size_t totalLen = ntohs(ipHeader.tot_length);
        {
            const size_t o = l3Offset;
            Field &l = pack.fields.emplace_back(Field{"Internet Protocol Version 4, Src: " + pack.source + ", Dst: " + pack.destination,
                                                      static_cast<uint32_t>(o), static_cast<uint32_t>(ipHeaderLen), {}});
            l.add("Version: " + std::to_string(ipHeader.version), o, 1);
            l.add("Header Length: " + std::to_string(ipHeaderLen) + " bytes (" + std::to_string(ipHeader.ihl) + ")", o, 1);
            l.add("Differentiated Services: " + hexString(ipHeader.tos, 2), o + 1, 1);
            l.add("Total Length: " + std::to_string(totalLen), o + 2, 2);
            l.add("Identification: " + hexString(ntohs(ipHeader.id), 4) + " (" + std::to_string(ntohs(ipHeader.id)) + ")", o + 4, 2);
            Field &flags = l.add("Flags: " + hexString(ipHeader.flags(), 1) + ((ipHeader.flags() & 2) ? ", Don't fragment" : "") +
                                     ((ipHeader.flags() & 1) ? ", More fragments" : ""), o + 6, 1);
            flags.add(std::string("Don't fragment: ") + ((ipHeader.flags() & 2) ? "Set" : "Not set"), o + 6, 1);
            flags.add(std::string("More fragments: ") + ((ipHeader.flags() & 1) ? "Set" : "Not set"), o + 6, 1);
            l.add("Fragment Offset: " + std::to_string(ipHeader.fragmentOffset() * 8), o + 6, 2);
            l.add("Time to Live: " + std::to_string(ipHeader.ttl), o + 8, 1);
            l.add("Protocol: " + std::to_string(ipHeader.protocol), o + 9, 1);
            l.add("Header Checksum: " + hexString(ntohs(ipHeader.check), 4), o + 10, 2);
            l.add("Source Address: " + pack.source, o + 12, 4);
            l.add("Destination Address: " + pack.destination, o + 16, 4);
            if (ipHeaderLen > sizeof(network::IPHeader)) l.add("Options", o + 20, ipHeaderLen - sizeof(network::IPHeader));
        }
        pack.length = totalLen >= ipHeaderLen ? totalLen - ipHeaderLen : 0;
        const size_t avail = std::min<size_t>(pack.length, len - l3Offset - ipHeaderLen); // drops Ethernet padding
        parseProtocolPacket(base + l3Offset + ipHeaderLen, avail, ipHeader.protocol);
    } else if (etherType == 0x86DD) { // IPv6
        network::IPv6Header ipv6Header;
        if (!readStruct(base, len, l3Offset, ipv6Header)) {
            markMalformed("IPv6 header truncated");
            pack.protocol = "IPv6";
            packet = pack;
            return;
        }
        pack.l3_header = ipv6Header;

        pack.source = network::getIPv6AddressString(ipv6Header.src_addr);
        pack.destination = network::getIPv6AddressString(ipv6Header.dst_addr);
        pack.protocol = "IPv6";

        std::ostringstream infoStream;
        infoStream << "IPv6 Version: " << (int) ipv6Header.version()
                   << ", Traffic Class: " << (int) ipv6Header.trafficClass()
                   << ", Flow Label: " << ipv6Header.flowLabel()
                   << ", Hop Limit: " << (int) ipv6Header.hop_limit;
        pack.info = infoStream.str();

        pack.length = ntohs(ipv6Header.payload_len); // payload only, no need to subtract the header size
        size_t l4Offset = l3Offset + sizeof(network::IPv6Header);
        size_t avail = std::min<size_t>(pack.length, len - l4Offset);
        uint8_t nextHeader = ipv6Header.next_header;

        Field *ipv6Layer = nullptr;
        {
            const size_t o = l3Offset;
            Field &l = pack.fields.emplace_back(Field{"Internet Protocol Version 6, Src: " + pack.source + ", Dst: " + pack.destination,
                                                      static_cast<uint32_t>(o), static_cast<uint32_t>(sizeof(network::IPv6Header)), {}});
            l.add("Version: " + std::to_string(ipv6Header.version()), o, 1);
            l.add("Traffic Class: " + hexString(ipv6Header.trafficClass(), 2), o, 2);
            l.add("Flow Label: " + hexString(ipv6Header.flowLabel(), 5), o + 1, 3);
            l.add("Payload Length: " + std::to_string(ntohs(ipv6Header.payload_len)), o + 4, 2);
            l.add("Next Header: " + std::to_string(ipv6Header.next_header), o + 6, 1);
            l.add("Hop Limit: " + std::to_string(ipv6Header.hop_limit), o + 7, 1);
            l.add("Source Address: " + pack.source, o + 8, 16);
            l.add("Destination Address: " + pack.destination, o + 24, 16);
            ipv6Layer = &l;
        }

        // Skip extension headers (hop-by-hop, routing, fragment, destination options, AH)
        while (nextHeader == 0 || nextHeader == 43 || nextHeader == 44 || nextHeader == 51 || nextHeader == 60) {
            if (avail < 8) { markMalformed("IPv6 extension header truncated"); packet = pack; return; }
            const uint8_t following = static_cast<uint8_t>(base[l4Offset]);
            const size_t extLen = nextHeader == 44 ? 8
                                  : nextHeader == 51 ? (static_cast<size_t>(static_cast<uint8_t>(base[l4Offset + 1])) + 2) * 4
                                  : (static_cast<size_t>(static_cast<uint8_t>(base[l4Offset + 1])) + 1) * 8;
            if (extLen > avail) { markMalformed("IPv6 extension header truncated"); packet = pack; return; }
            ipv6Layer->add("Extension Header (type " + std::to_string(nextHeader) + ", " + std::to_string(extLen) + " bytes)", l4Offset, extLen);
            l4Offset += extLen;
            avail -= extLen;
            nextHeader = following;
        }
        parseProtocolPacket(base + l4Offset, avail, nextHeader);
    } else if (etherType == 0x0806 || etherType == 0x8035) { // ARP / RARP
        network::ARPHeader arpHeader;
        if (!readStruct(base, len, l3Offset, arpHeader)) {
            markMalformed("ARP packet truncated");
            pack.protocol = (etherType == 0x0806) ? "ARP" : "RARP";
            packet = pack;
            return;
        }
        pack.l3_header = arpHeader;
        pack.protocol = (etherType == 0x0806) ? "ARP" : "RARP";
        pack.length = sizeof(network::ARPHeader);
        pack.destination = network::getMACAddressString(arpHeader.target_hw_addr);
        pack.source = network::getMACAddressString(arpHeader.sender_hw_addr);
        if (etherType == 0x0806 ? pack.destination == "00:00:00:00:00:00" : pack.destination == pack.source) {
            pack.destination = "Broadcast";
        }
        parseARP(arpHeader);

        const size_t o = l3Offset;
        Field &l = pack.fields.emplace_back(Field{"Address Resolution Protocol (" + std::string(ntohs(arpHeader.opcode) == 1 ? "request" : ntohs(arpHeader.opcode) == 2 ? "reply" : "other") + ")",
                                                  static_cast<uint32_t>(o), static_cast<uint32_t>(sizeof(network::ARPHeader)), {}});
        l.add("Hardware type: " + std::to_string(ntohs(arpHeader.hw_type)), o, 2);
        l.add("Protocol type: " + hexString(ntohs(arpHeader.protocol_type), 4), o + 2, 2);
        l.add("Hardware size: " + std::to_string(arpHeader.hw_addr_len), o + 4, 1);
        l.add("Protocol size: " + std::to_string(arpHeader.protocol_addr_len), o + 5, 1);
        l.add("Opcode: " + std::to_string(ntohs(arpHeader.opcode)), o + 6, 2);
        l.add("Sender MAC address: " + network::getMACAddressString(arpHeader.sender_hw_addr), o + 8, 6);
        l.add("Sender IP address: " + ip4(arpHeader.sender_protocol_addr), o + 14, 4);
        l.add("Target MAC address: " + network::getMACAddressString(arpHeader.target_hw_addr), o + 18, 6);
        l.add("Target IP address: " + ip4(arpHeader.target_protocol_addr), o + 24, 4);
    } else {
        // Unsupported EtherType: show the frame at least by its MAC addresses.
        pack.protocol = haveEthernet ? "Ethernet" : "Unknown";
        if (haveEthernet) {
            pack.source = network::getMACAddressString(ethHeader.src_mac);
            pack.destination = network::getMACAddressString(ethHeader.dest_mac);
        }
        std::ostringstream oss;
        oss << "EtherType 0x" << std::hex << std::setw(4) << std::setfill('0') << etherType;
        pack.info = oss.str();
        if (len > l3Offset) {
            pack.fields.emplace_back(Field{"Data (" + std::to_string(len - l3Offset) + " bytes)", static_cast<uint32_t>(l3Offset),
                                           static_cast<uint32_t>(len - l3Offset), {}});
        }
    }
    packet = pack;
}
