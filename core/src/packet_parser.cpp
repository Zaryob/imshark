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

// `length` is the number of bytes actually available at pack_data (captured, clamped to the IP payload).
void packet::PacketParser::parseProtocolPacket(const char *pack_data, size_t length, uint8_t protocol) {
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
            pack.info = std::to_string(src_port) + " -> " + std::to_string(dest_port) + " [" + flags + "] " +
                        (seq >= 0 ? (" Seq=" + std::to_string(seq)) : "") +
                        (ack >= 0 ? (" Ack=" + std::to_string(ack)) : "") +
                        (window > 0 ? (" Win=" + std::to_string(window)) : "") +
                        describeTCPOptions(pack_data + sizeof(network::TCPHeader), headerLen - sizeof(network::TCPHeader));

            if (src_port == 23 || dest_port == 23) {
                pack.protocol = "Telnet";
                parseTelnet(payload, payloadLen);
            } else if (src_port == 25 || dest_port == 25) {
                pack.protocol = "SMTP";
                parseSMTP(payload, payloadLen);
            } else if (src_port == 179 || dest_port == 179) {
                pack.protocol = "BGP";
                parseBGP(payload, payloadLen);
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

            if (srcPort == 53 || dstPort == 53) {
                pack.protocol = "DNS";
                parseDNSPacket(payload, payloadLen);
            } else if (srcPort == 67 || srcPort == 68 || dstPort == 67 || dstPort == 68) { // DHCP over UDP
                pack.protocol = "DHCP";
                network::DHCPHeader dhcpHeader;
                if (readStruct(payload, payloadLen, 0, dhcpHeader)) {
                    pack.l7_header = dhcpHeader;
                    parseDHCP(&dhcpHeader);
                } else {
                    markMalformed("DHCP message too short");
                }
            } else if (srcPort == 161 || dstPort == 161 || srcPort == 162 || dstPort == 162) { // SNMP
                pack.protocol = "SNMP";
                parseSNMP(payload, payloadLen);
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
    const char *base = packetData.data();
    const size_t len = packetData.size();
    pack.length = static_cast<uint32_t>(len);

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

        // Skip extension headers (hop-by-hop, routing, fragment, destination options, AH)
        while (nextHeader == 0 || nextHeader == 43 || nextHeader == 44 || nextHeader == 51 || nextHeader == 60) {
            if (avail < 8) { markMalformed("IPv6 extension header truncated"); packet = pack; return; }
            const uint8_t following = static_cast<uint8_t>(base[l4Offset]);
            const size_t extLen = nextHeader == 44 ? 8
                                  : nextHeader == 51 ? (static_cast<size_t>(static_cast<uint8_t>(base[l4Offset + 1])) + 2) * 4
                                  : (static_cast<size_t>(static_cast<uint8_t>(base[l4Offset + 1])) + 1) * 8;
            if (extLen > avail) { markMalformed("IPv6 extension header truncated"); packet = pack; return; }
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
    }
    packet = pack;
}
