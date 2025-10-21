#include "fields.h"

#include <algorithm>

#include <dissect/checksum.h>

namespace filter {
    namespace {
        using packet::PacketInfo;

        bool ipv4(const PacketInfo &p) { return p.ip_version == 4; }
        bool ipv6(const PacketInfo &p) { return p.ip_version == 6; }
        // a fragment that is not the last one carries no complete TCP/UDP header to speak of
        bool hasTcp(const PacketInfo &p) { return p.ip_version != 0 && p.ip_protocol == 6 && p.ip_frag != 1; }
        bool hasUdp(const PacketInfo &p) { return p.ip_version != 0 && p.ip_protocol == 17 && p.ip_frag != 1; }

        // protocol presence: one value (1) when present, none otherwise
        template<bool (*Present)(const PacketInfo &)>
        void proto(const PacketInfo &p, const Context &, Values &out) { if (Present(p)) out.addU(1); }

        bool isProtocol(const PacketInfo &p, const char *name) { return p.protocol == name; }

        // Wireshark's numbering of *.checksum.status: 0 = bad, 1 = good, 2 = unverified, 3 = not present
        uint32_t checksumStatusNumber(uint8_t state) { return state == dissect::kChecksumBad ? 0 : state == dissect::kChecksumGood ? 1 : state == dissect::kChecksumUnverified ? 2 : 3; }

        std::string_view httpMethodName(uint16_t code) {
            static const char *names[] = {"", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"};
            return code < sizeof(names) / sizeof(*names) ? names[code] : "";
        }

        template<uint8_t Bit>
        void tcpFlag(const PacketInfo &p, const Context &, Values &out) { if (hasTcp(p)) out.addU((p.tcp_flags & Bit) ? 1 : 0); }

        // TCP analysis flag (network::TcpAnalysisFlag bit): 0/1 for TCP packets, absent otherwise
        template<uint16_t Bit>
        void tcpAnalysis(const PacketInfo &p, const Context &, Values &out) { if (hasTcp(p)) out.addU((p.tcp_analysis & Bit) ? 1 : 0); }

        void addr(const PacketInfo &p, const Context &, Values &out, bool wantV6, bool src, bool dst) {
            if (p.ip_version != (wantV6 ? 6 : 4)) return;
            if (src) if (auto a = network::parseIpAddress(p.source)) out.addA(*a);
            if (dst) if (auto a = network::parseIpAddress(p.destination)) out.addA(*a);
        }

        std::vector<FieldDef> buildTable() {
            std::vector<FieldDef> t = {
                // ---- frame
                {"frame.number", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { o.addU(static_cast<uint64_t>(p.number)); }, "Packet number (1-based)"},
                {"frame.comment", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { o.addU(p.has_comment); }, "The capture file has a comment for this packet (pcapng)"},
                {"frame.len", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { o.addU(p.frame_length); }, "Length of the frame on the wire"},
                {"frame.cap_len", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { o.addU(p.captured_length); }, "Number of bytes captured"},
                {"frame.time_relative", FieldType::Float, [](const PacketInfo &p, const Context &, Values &o) { o.addD(p.time); }, "Seconds since the first packet"},
                {"frame.time_delta", FieldType::Float, [](const PacketInfo &p, const Context &c, Values &o) { o.addD(c.previous ? p.time - c.previous->time : 0.0); }, "Seconds since the previous captured packet"},
                {"frame.time_epoch", FieldType::Float, [](const PacketInfo &p, const Context &c, Values &o) { o.addD(c.captureStartEpoch + p.time); }, "Arrival time as UTC epoch seconds"},
                {"_ws.col.protocol", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { o.addS(p.protocol); }, "Protocol column"},
                {"protocol", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { o.addS(p.protocol); }, "Protocol column (alias of _ws.col.protocol)"},
                {"_ws.col.info", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { o.addS(p.info); }, "Info column"},
                {"info", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { o.addS(p.info); }, "Info column (alias of _ws.col.info)"},
                // ---- link layer
                {"eth", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.link_type == 1; }>, "Ethernet frame"},
                {"eth.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ether_type) o.addU(p.ether_type); }, "EtherType"},
                {"vlan", FieldType::Boolean, proto<[](const PacketInfo &p) { return !p.vlan_ids.empty(); }>, "802.1Q VLAN tagged"},
                {"vlan.id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { for (size_t i = 0; i < p.vlan_ids.size() && i < 2; ++i) o.addU(p.vlan_ids[i]); }, "VLAN ID (outermost two tags)"},
                // ---- network layer
                {"arp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "ARP") || isProtocol(p, "RARP")) o.addU(1); }, "ARP / RARP"},
                {"ip", FieldType::Boolean, proto<ipv4>, "IPv4"},
                {"ipv6", FieldType::Boolean, proto<ipv6>, "IPv6"},
                {"ip.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(4); }, "IPv4 version"},
                {"ip.ttl", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(p.ttl); }, "IPv4 time to live"},
                {"ip.id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(p.ip_id); }, "IPv4 identification"},
                {"ip.fragment", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(p.ip_frag != 0); }, "IPv4 fragment (part of a fragmented datagram)"},
                {"ip.reassembled", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(p.ip_frag == 2); }, "Last IPv4 fragment: the datagram was reassembled here"},
                {"ipv6.fragment", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p)) o.addU(p.ip_frag != 0); }, "IPv6 fragment (part of a fragmented datagram)"},
                {"ipv6.fragment.id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p) && p.ip_frag != 0) o.addU(p.ip_id); }, "IPv6 Fragment Header identification"},
                {"ipv6.reassembled", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p)) o.addU(p.ip_frag == 2); }, "Last IPv6 fragment: the datagram was reassembled here"},
                {"ip.proto", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(p.ip_protocol); }, "IPv4 protocol number"},
                {"ip.src", FieldType::Ipv4, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, false, true, false); }, "IPv4 source address"},
                {"ip.dst", FieldType::Ipv4, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, false, false, true); }, "IPv4 destination address"},
                {"ip.addr", FieldType::Ipv4, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, false, true, true); }, "IPv4 source or destination address"},
                {"ipv6.hlim", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p)) o.addU(p.ttl); }, "IPv6 hop limit"},
                {"ipv6.nxt", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p)) o.addU(p.ip_protocol); }, "IPv6 next header (after extension headers)"},
                {"ipv6.src", FieldType::Ipv6, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, true, true, false); }, "IPv6 source address"},
                {"ipv6.dst", FieldType::Ipv6, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, true, false, true); }, "IPv6 destination address"},
                {"ipv6.addr", FieldType::Ipv6, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, true, true, true); }, "IPv6 source or destination address"},
                // ---- transport layer
                {"tcp", FieldType::Boolean, proto<hasTcp>, "TCP"},
                {"udp", FieldType::Boolean, proto<hasUdp>, "UDP"},
                {"icmp", FieldType::Boolean, proto<[](const PacketInfo &p) { return ipv4(p) && p.ip_protocol == 1; }>, "ICMP"},
                {"icmpv6", FieldType::Boolean, proto<[](const PacketInfo &p) { return ipv6(p) && p.ip_protocol == 58; }>, "ICMPv6"},
                {"tcp.srcport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.src_port); }, "TCP source port"},
                {"tcp.dstport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.dst_port); }, "TCP destination port"},
                {"tcp.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) { o.addU(p.src_port); o.addU(p.dst_port); } }, "TCP source or destination port"},
                {"tcp.flags", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.tcp_flags); }, "TCP flag byte"},
                {"tcp.flags.fin", FieldType::Boolean, tcpFlag<0x01>, "TCP FIN flag"},
                {"tcp.flags.syn", FieldType::Boolean, tcpFlag<0x02>, "TCP SYN flag"},
                {"tcp.flags.rst", FieldType::Boolean, tcpFlag<0x04>, "TCP RST flag"},
                {"tcp.flags.push", FieldType::Boolean, tcpFlag<0x08>, "TCP PSH flag"},
                {"tcp.flags.ack", FieldType::Boolean, tcpFlag<0x10>, "TCP ACK flag"},
                {"tcp.flags.urg", FieldType::Boolean, tcpFlag<0x20>, "TCP URG flag"},
                {"tcp.flags.ece", FieldType::Boolean, tcpFlag<0x40>, "TCP ECE flag"},
                {"tcp.flags.cwr", FieldType::Boolean, tcpFlag<0x80>, "TCP CWR flag"},
                {"tcp.len", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.tcp_len); }, "TCP payload length"},
                {"tcp.seq", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p) && p.tcp_relative_seq >= 0) o.addU(static_cast<uint64_t>(p.tcp_relative_seq)); }, "TCP relative sequence number"},
                {"tcp.ack", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p) && p.tcp_relative_ack >= 0) o.addU(static_cast<uint64_t>(p.tcp_relative_ack)); }, "TCP relative acknowledgment number"},
                {"tcp.analysis.flags", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.tcp_analysis != 0); }, "Any TCP analysis note (retransmission, dup ACK, ...)"},
                {"tcp.analysis.retransmission", FieldType::Boolean, tcpAnalysis<1>, "TCP segment repeats data that was already seen"},
                {"tcp.analysis.out_of_order", FieldType::Boolean, tcpAnalysis<2>, "TCP segment arrived out of order"},
                {"tcp.analysis.lost_segment", FieldType::Boolean, tcpAnalysis<4>, "A previous TCP segment was not captured"},
                {"tcp.analysis.duplicate_ack", FieldType::Boolean, tcpAnalysis<8>, "Duplicate acknowledgment"},
                {"tcp.analysis.duplicate_ack_num", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p) && (p.tcp_analysis & 8)) o.addU(p.tcp_dup_ack); }, "Number of the duplicate ACK (#n)"},
                {"tcp.analysis.zero_window", FieldType::Boolean, tcpAnalysis<16>, "Zero receive window advertised"},
                {"tcp.analysis.keep_alive", FieldType::Boolean, tcpAnalysis<32>, "TCP keep-alive"},
                {"tcp.analysis.window_update", FieldType::Boolean, tcpAnalysis<64>, "TCP window update"},
                {"ip.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_version == 4) o.addU(checksumStatusNumber(dissect::ipChecksumState(p))); }, "IPv4 header checksum: 0 = bad, 1 = good, 2 = unverified (offload or truncated), 3 = not present"},
                {"tcp.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 6 && p.src_port != 0) o.addU(checksumStatusNumber(dissect::transportChecksumState(p))); }, "TCP checksum: 0 = bad, 1 = good, 2 = unverified (offload or truncated)"},
                {"udp.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 17 && p.src_port != 0) o.addU(checksumStatusNumber(dissect::transportChecksumState(p))); }, "UDP checksum: 0 = bad, 1 = good, 2 = unverified, 3 = not present (zero over IPv4)"},
                {"icmp.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 1 && p.ip_frag != 1) o.addU(checksumStatusNumber(dissect::transportChecksumState(p))); }, "ICMP checksum: 0 = bad, 1 = good, 2 = unverified"},
                {"icmpv6.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 58 && p.ip_frag != 1) o.addU(checksumStatusNumber(dissect::transportChecksumState(p))); }, "ICMPv6 checksum: 0 = bad, 1 = good, 2 = unverified"},
                {"tcp.segment", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.tcp_pdu_state == 1 || p.tcp_pdu_state == 4); }, "Segment of a TCP message that is reassembled in a later packet"},
                {"tcp.reassembled", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.tcp_pdu_state == 2); }, "Packet that completes a reassembled TCP message"},
                {"tcp.reassembled_in", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p) && (p.tcp_pdu_state == 1 || p.tcp_pdu_state == 4) && p.tcp_reassembled_in) o.addU(p.tcp_reassembled_in); }, "Number of the packet that completes the message this segment belongs to"},
                {"tcp.reassembled.length", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p) && p.tcp_pdu_state == 2) o.addU(p.tcp_pdu_len); }, "Length of the reassembled TCP message"},
                {"udp.srcport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasUdp(p)) o.addU(p.src_port); }, "UDP source port"},
                {"udp.dstport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasUdp(p)) o.addU(p.dst_port); }, "UDP destination port"},
                {"udp.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasUdp(p)) { o.addU(p.src_port); o.addU(p.dst_port); } }, "UDP source or destination port"},
                // ---- application protocols (by the protocol column)
                {"http", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP")) o.addU(1); }, "HTTP/1.x"},
                {"http.request", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP")) o.addU(p.app_flags == 0); }, "HTTP request"},
                {"http.response", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP")) o.addU(p.app_flags == 1); }, "HTTP response"},
                {"http.request.method", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP") && p.app_flags == 0) o.addS(httpMethodName(p.app_type)); }, "HTTP request method (GET, POST ...)"},
                {"http.request.uri", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP") && p.app_flags == 0) o.addS(p.app_text2); }, "HTTP request URI"},
                {"http.host", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP") && !p.app_text.empty()) o.addS(p.app_text); }, "HTTP Host header"},
                {"http.response.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP") && p.app_flags == 1) o.addU(p.app_code); }, "HTTP response status code"},
                {"http.content_type", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP") && p.app_flags == 1 && !p.app_text2.empty()) o.addS(p.app_text2); }, "HTTP response Content-Type"},
                {"http2", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2")) o.addU(1); }, "HTTP/2"},
                {"http2.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2")) o.addU(p.app_type); }, "HTTP/2 frame type (0 = DATA, 1 = HEADERS, 4 = SETTINGS ...)"},
                {"http2.streamid", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2")) o.addU(p.app_stream); }, "HTTP/2 stream identifier"},
                {"http2.flags", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2")) o.addU(p.app_flags); }, "HTTP/2 frame flags"},
                {"http2.headers.method", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2") && !p.app_text.empty()) o.addS(p.app_text); }, "HTTP/2 request method"},
                {"http2.headers.path", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2") && !p.app_text2.empty()) o.addS(p.app_text2); }, "HTTP/2 request path"},
                {"http2.headers.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "HTTP2") && p.app_code != 0) o.addU(p.app_code); }, "HTTP/2 response status code"},
                {"tls", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS")) o.addU(1); }, "TLS / SSL"},
                {"tls.record.content_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS")) o.addU(p.app_code); }, "Content type of the first TLS record (22 = handshake, 23 = application data)"},
                {"tls.record.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS")) o.addU(p.app_flags); }, "Version of the first TLS record (0x0303 = TLS 1.2)"},
                {"tls.handshake.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS") && p.app_type != 0) o.addU(p.app_type); }, "First handshake message type (1 = ClientHello, 2 = ServerHello ...)"},
                {"tls.handshake.certificate_subject", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS") && !p.app_text2.empty()) o.addS(p.app_text2); }, "Common name of the first certificate in a Certificate message"},
                {"tls.handshake.extensions_server_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS") && !p.app_text.empty()) o.addS(p.app_text); }, "Server name indication (SNI) of a ClientHello"},
                {"icmp.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p) && p.ip_protocol == 1 && p.protocol == "ICMP") o.addU(p.app_type); }, "ICMP message type"},
                {"icmp.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p) && p.ip_protocol == 1 && p.protocol == "ICMP") o.addU(p.app_code); }, "ICMP message code"},
                {"icmpv6.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p) && p.protocol == "ICMPv6") o.addU(p.app_type); }, "ICMPv6 message type"},
                {"icmpv6.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p) && p.protocol == "ICMPv6") o.addU(p.app_code); }, "ICMPv6 message code"},
                {"dhcp.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DHCP") && p.app_type != 0) o.addU(p.app_type); }, "DHCP message type (1 = Discover, 2 = Offer, 3 = Request, 5 = ACK ...)"},
                {"dhcp.option.hostname", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DHCP") && !p.app_text.empty()) o.addS(p.app_text); }, "DHCP host name option"},
                {"ntp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(1); }, "NTP"},
                {"ntp.mode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(p.app_type); }, "NTP mode (3 = client, 4 = server)"},
                {"ntp.stratum", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP") && p.app_type >= 1 && p.app_type <= 5) o.addU(p.app_code); }, "NTP stratum"},
                {"ntp.ctrl.opcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP") && p.app_type == 6) o.addU(p.app_code); }, "Opcode of an NTP control message (2 = read variables)"},
                {"ntp.priv.reqcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP") && p.app_type == 7) o.addU(p.app_code); }, "Request code of an NTP private (mode 7) message"},
                {"ntp.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(p.app_flags); }, "NTP version"},
                {"dns.qry.name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "DNS") || isProtocol(p, "MDNS")) && !p.app_text.empty()) o.addS(p.app_text); }, "Name of the first DNS question"},
                {"dns.qry.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "DNS") || isProtocol(p, "MDNS")) && !p.app_text.empty()) o.addU(p.app_type); }, "Type of the first DNS question (1 = A, 28 = AAAA, 15 = MX ...)"},
                {"dns.flags.response", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS") || isProtocol(p, "MDNS")) o.addU((p.app_flags & 0x8000) != 0); }, "DNS message is a response"},
                {"dns.flags.rcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS") || isProtocol(p, "MDNS")) o.addU(p.app_code); }, "DNS reply code (0 = no error, 3 = NXDOMAIN ...)"},
                {"dns.flags.truncated", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS") || isProtocol(p, "MDNS")) o.addU((p.app_flags & 0x0200) != 0); }, "DNS message is truncated"},
                {"mdns", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "MDNS")) o.addU(1); }, "Multicast DNS"},
                {"dns", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS")) o.addU(1); }, "DNS"},
                {"dhcp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DHCP")) o.addU(1); }, "DHCP"},
                {"snmp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(1); }, "SNMP"},
                {"snmp.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.app_flags); }, "SNMP version (0 = v1, 1 = v2c, 3 = v3)"},
                {"snmp.community", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP") && !p.app_text.empty()) o.addS(p.app_text); }, "SNMP community string or v3 user name"},
                {"snmp.pdu_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.app_type); }, "SNMP PDU type (0 = GetRequest, 1 = GetNextRequest, 2 = Response ...)"},
                {"snmp.request_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.tcp_pdu_start); }, "SNMP request ID"},
                {"snmp.error_status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP")) o.addU(p.app_code); }, "SNMP error-status code"},
                {"snmp.oid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SNMP") && !p.app_text2.empty()) o.addS(p.app_text2); }, "SNMP first variable binding OID"},
                {"telnet", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet")) o.addU(1); }, "Telnet"},
                {"telnet.cmd", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet") && p.app_type != 0) o.addU(p.app_type); }, "Telnet command (251 = WILL, 252 = WONT, 253 = DO, 254 = DONT, 250 = SB...)"},
                {"telnet.subcmd", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet") && p.app_code != 0) o.addU(p.app_code); }, "Telnet option code (1 = Echo, 3 = Suppress Go Ahead, 24 = Terminal Type, 31 = NAWS...)"},
                {"telnet.data", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet") && !p.app_text.empty()) o.addS(p.app_text); }, "Telnet text data or command summary"},
                {"smtp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP")) o.addU(1); }, "SMTP"},
                {"smtp.req", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 1) o.addU(1); }, "SMTP command/request"},
                {"smtp.rsp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 2) o.addU(1); }, "SMTP server response"},
                {"smtp.response.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 2 && p.app_code != 0) o.addU(p.app_code); }, "SMTP response code (e.g. 220, 250, 354, 550)"},
                {"smtp.command", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 1 && !p.app_text.empty()) o.addS(p.app_text); }, "SMTP command name (e.g. EHLO, MAIL FROM, RCPT TO, DATA)"},
                {"smtp.param", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && !p.app_text2.empty()) o.addS(p.app_text2); }, "SMTP command or response parameter"},
                {"ftp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP")) o.addU(1); }, "FTP"},
                {"ftp.req", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 1) o.addU(1); }, "FTP command/request"},
                {"ftp.rsp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 2) o.addU(1); }, "FTP server response"},
                {"ftp.response.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 2 && p.app_code != 0) o.addU(p.app_code); }, "FTP response code (e.g. 200, 220, 227, 230, 550)"},
                {"ftp.command", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 1 && !p.app_text.empty()) o.addS(p.app_text); }, "FTP command name (e.g. USER, PASS, PORT, PASV, RETR)"},
                {"ftp.arg", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && !p.app_text2.empty()) o.addS(p.app_text2); }, "FTP command or response argument"},
                {"ftp_data", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP-DATA")) o.addU(1); }, "FTP-DATA"},
                {"tftp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP")) o.addU(1); }, "TFTP"},
                {"tftp.opcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && p.app_type != 0) o.addU(p.app_type); }, "TFTP opcode (1 = RRQ, 2 = WRQ, 3 = DATA, 4 = ACK, 5 = ERROR, 6 = OACK)"},
                {"tftp.block", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && (p.app_type == 3 || p.app_type == 4)) o.addU(p.app_code); }, "TFTP block number"},
                {"tftp.error.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && p.app_type == 5) o.addU(p.app_code); }, "TFTP error code"},
                {"tftp.source_file", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && (p.app_type == 1 || p.app_type == 2) && !p.app_text.empty()) o.addS(p.app_text); }, "TFTP filename"},
                {"tftp.mode", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && (p.app_type == 1 || p.app_type == 2) && !p.app_text2.empty()) o.addS(p.app_text2); }, "TFTP transfer mode (e.g. netascii, octet)"},
                {"bgp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP")) o.addU(1); }, "BGP"},
                {"bgp.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP")) o.addU(p.app_type); }, "BGP message type (1 = OPEN, 2 = UPDATE, 3 = NOTIFICATION, 4 = KEEPALIVE, 5 = ROUTE-REFRESH)"},
                {"bgp.as", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP")) o.addU(p.tcp_pdu_start); }, "BGP Autonomous System number"},
                {"bgp.nlri", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP") && !p.app_text.empty()) o.addS(p.app_text); }, "BGP Network Layer Reachability Information prefix"},
                {"bgp.notification.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP") && p.app_type == 3) o.addU(p.app_code); }, "BGP notification error code"},
                {"ssh", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH")) o.addU(1); }, "SSH"},
                {"ssh.protocol", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 0 && !p.app_text.empty()) o.addS(p.app_text); }, "SSH protocol version banner"},
                {"ssh.message_code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type != 0 && p.app_type != 255) o.addU(p.app_type); }, "SSH packet message code (e.g. 20 = KEXINIT, 21 = NEWKEYS)"},
                {"ssh.kex_algorithm", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 20 && !p.app_text.empty()) o.addS(p.app_text); }, "SSH key exchange algorithm"},
                {"ssh.encryption_algorithm", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 20 && !p.app_text2.empty()) o.addS(p.app_text2); }, "SSH client-to-server encryption algorithm"},
                {"ssh.encrypted", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 255) o.addU(1); }, "SSH encrypted packet payload"},
                {"wlan", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.link_type == 105 || p.link_type == 127 || p.link_type == 192 || isProtocol(p, "802.11") || isProtocol(p, "WLAN") || p.wlan_fc != 0) o.addU(1); }, "IEEE 802.11 wireless frame"},
                {"wlan.fc.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc >> 2) & 0x03); }, "802.11 Frame Control type (0 = Management, 1 = Control, 2 = Data, 3 = Extension)"},
                {"wlan.fc.subtype", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc >> 4) & 0x0F); }, "802.11 Frame Control subtype"},
                {"wlan.fc.protected", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x4000) ? 1 : 0); }, "802.11 Frame Control protected (encrypted) bit"},
                {"wlan.fc.retry", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0800) ? 1 : 0); }, "802.11 Frame Control retry bit"},
                {"wlan.fc.tods", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0100) ? 1 : 0); }, "802.11 Frame Control To DS bit"},
                {"wlan.fc.fromds", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0200) ? 1 : 0); }, "802.11 Frame Control From DS bit"},
                {"wlan.seq", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU(p.wlan_seq); }, "802.11 sequence number"},
                {"wlan.sa", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.source.empty()) o.addS(p.source); }, "802.11 Source MAC address"},
                {"wlan.da", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.destination.empty()) o.addS(p.destination); }, "802.11 Destination MAC address"},
                {"wlan.ra", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.destination.empty()) o.addS(p.destination); }, "802.11 Receiver MAC address"},
                {"wlan.ta", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.source.empty()) o.addS(p.source); }, "802.11 Transmitter MAC address"},
                {"wlan.bssid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.app_text2.empty()) o.addS(p.app_text2); }, "802.11 BSSID MAC address"},
                {"wlan.ssid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.app_text.empty()) o.addS(p.app_text); }, "802.11 SSID"},
                {"radiotap.channel.freq", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_freq != 0) o.addU(p.radiotap_freq); }, "Radiotap/PPI channel frequency in MHz"},
                {"radiotap.dbm_antsignal", FieldType::Float, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_signal != 0) o.addD(static_cast<double>(p.radiotap_signal)); }, "Radiotap/PPI antenna signal in dBm"},
                {"radiotap.datarate", FieldType::Float, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_rate != 0) o.addD(p.radiotap_rate * 0.5); }, "Radiotap/PPI data rate in Mb/s"},
                {"ppi.dlt", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ppi_dlt != 0) o.addU(p.ppi_dlt); }, "PPI encapsulated Data Link Type"},
                {"eapol", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") || isProtocol(p, "EAP") || p.ether_type == 0x888E) o.addU(1); }, "IEEE 802.1X / EAPOL packet"},
                {"eapol.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") || isProtocol(p, "EAP") || p.ether_type == 0x888E) o.addU(p.app_type); }, "802.1X packet type (0 = EAP, 1 = Start, 2 = Logoff, 3 = Key)"},
                {"eapol.keydes.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") && p.app_type == 3) o.addU(p.app_code); }, "EAPOL-Key descriptor type (1 = RC4, 2 = RSN, 254 = WPA)"},
                {"eapol.keydes.msgnr", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") && p.app_type == 3 && p.app_flags != 0) o.addU(p.app_flags); }, "WPA 4-way handshake message number (1, 2, 3, 4)"},
                {"eap", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") || (isProtocol(p, "EAPOL") && p.app_type == 0)) o.addU(1); }, "Extensible Authentication Protocol"},
                {"eap.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_code != 0) o.addU(p.app_code); }, "EAP code (1 = Request, 2 = Response, 3 = Success, 4 = Failure)"},
                {"eap.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_flags != 0) o.addU(p.app_flags); }, "EAP type (1 = Identity, 13 = TLS, 25 = PEAP, 43 = FAST)"},
                {"eap.identity", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_flags == 1 && !p.app_text.empty()) o.addS(p.app_text); }, "EAP Identity username/string"},
                {"malformed", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Malformed") || p.info.find("[Malformed Packet") != std::string::npos) o.addU(1); }, "Packet that could not be fully decoded"},
            };
            std::sort(t.begin(), t.end(), [](const FieldDef &a, const FieldDef &b) { return std::string_view(a.name) < b.name; });
            return t;
        }
    } // namespace

    const std::vector<FieldDef> &allFields() {
        static const std::vector<FieldDef> table = buildTable();
        return table;
    }

    const FieldDef *findField(std::string_view lowerName) {
        const auto &t = allFields();
        const auto it = std::lower_bound(t.begin(), t.end(), lowerName,
                                         [](const FieldDef &f, std::string_view n) { return std::string_view(f.name) < n; });
        return (it != t.end() && std::string_view(it->name) == lowerName) ? &*it : nullptr;
    }
} // namespace filter
