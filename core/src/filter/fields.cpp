#include "fields.h"

#include <algorithm>

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
                {"tcp.len", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.length); }, "TCP payload length"},
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
                {"tls", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS")) o.addU(1); }, "TLS / SSL"},
                {"tls.record.content_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS")) o.addU(p.app_code); }, "Content type of the first TLS record (22 = handshake, 23 = application data)"},
                {"tls.record.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS")) o.addU(p.app_flags); }, "Version of the first TLS record (0x0303 = TLS 1.2)"},
                {"tls.handshake.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS") && p.app_type != 0) o.addU(p.app_type); }, "First handshake message type (1 = ClientHello, 2 = ServerHello ...)"},
                {"tls.handshake.extensions_server_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TLS") && !p.app_text.empty()) o.addS(p.app_text); }, "Server name indication (SNI) of a ClientHello"},
                {"icmp.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p) && p.ip_protocol == 1 && p.protocol == "ICMP") o.addU(p.app_type); }, "ICMP message type"},
                {"icmp.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p) && p.ip_protocol == 1 && p.protocol == "ICMP") o.addU(p.app_code); }, "ICMP message code"},
                {"icmpv6.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p) && p.protocol == "ICMPv6") o.addU(p.app_type); }, "ICMPv6 message type"},
                {"icmpv6.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p) && p.protocol == "ICMPv6") o.addU(p.app_code); }, "ICMPv6 message code"},
                {"dhcp.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DHCP") && p.app_type != 0) o.addU(p.app_type); }, "DHCP message type (1 = Discover, 2 = Offer, 3 = Request, 5 = ACK ...)"},
                {"dhcp.option.hostname", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DHCP") && !p.app_text.empty()) o.addS(p.app_text); }, "DHCP host name option"},
                {"ntp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(1); }, "NTP"},
                {"ntp.mode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(p.app_type); }, "NTP mode (3 = client, 4 = server)"},
                {"ntp.stratum", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(p.app_code); }, "NTP stratum"},
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
                {"telnet", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet")) o.addU(1); }, "Telnet"},
                {"smtp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP")) o.addU(1); }, "SMTP"},
                {"bgp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP")) o.addU(1); }, "BGP"},
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
