#include "statistics.h"

#include <algorithm>
#include <unordered_map>

#include <dissect/tls_summary.h>
#include <filter/filter.h>

namespace stats {
    namespace {
        bool applies(const packet::PacketInfo &p, AddressKind kind) {
            switch (kind) {
                case AddressKind::Ipv4: return p.ip_version == 4;
                case AddressKind::Ipv6: return p.ip_version == 6;
                case AddressKind::Tcp: return p.ip_version != 0 && p.ip_protocol == 6;
                case AddressKind::Udp: return p.ip_version != 0 && p.ip_protocol == 17;
                case AddressKind::Sctp: return p.ip_protocol == 132 || p.protocol == "SCTP";
                case AddressKind::Ethernet: return p.link_type == 1 && !p.source.empty() && !p.destination.empty();
                case AddressKind::Wlan: return (p.link_type == 105 || p.link_type == 127 || p.link_type == 192 ||
                                               p.protocol == "802.11" || p.protocol == "WLAN") &&
                                               (!p.source.empty() || !p.destination.empty());
                case AddressKind::Bluetooth: return (p.link_type == 187 || p.link_type == 254 ||
                                                    p.protocol == "HCI" || p.protocol == "BT Mon" ||
                                                    p.protocol == "L2CAP" || p.protocol == "ATT") &&
                                                    (!p.source.empty() || !p.destination.empty());
                case AddressKind::Usb: return (p.link_type == 189 || p.link_type == 220 || p.link_type == 249 ||
                                              p.protocol == "USB") &&
                                              (!p.source.empty() || !p.destination.empty());
            }
            return false;
        }

        template<typename F>
        void forEachPacket(const std::vector<packet::PacketInfo> &packets, Subset subset, F &&f) {
            if (subset) {
                for (uint32_t i: *subset) if (i < packets.size()) f(packets[i]);
            } else {
                for (const auto &p: packets) f(p);
            }
        }

        std::string endpointKey(const std::string &address, uint16_t port) { return address + "#" + std::to_string(port); }
    } // namespace

    bool hasPort(AddressKind kind) {
        return kind == AddressKind::Tcp || kind == AddressKind::Udp || kind == AddressKind::Sctp;
    }

    const char *kindName(AddressKind kind) {
        switch (kind) {
            case AddressKind::Ipv4: return "IPv4";
            case AddressKind::Ipv6: return "IPv6";
            case AddressKind::Tcp: return "TCP";
            case AddressKind::Udp: return "UDP";
            case AddressKind::Sctp: return "SCTP";
            case AddressKind::Ethernet: return "Ethernet";
            case AddressKind::Wlan: return "WLAN";
            case AddressKind::Bluetooth: return "Bluetooth";
            case AddressKind::Usb: return "USB";
        }
        return "";
    }

    std::vector<Endpoint> endpoints(const std::vector<packet::PacketInfo> &packets, Subset subset, AddressKind kind) {
        std::unordered_map<std::string, size_t> index;
        std::vector<Endpoint> out;
        const bool ports = hasPort(kind);

        auto touch = [&](const std::string &address, uint16_t port) -> Endpoint & {
            const auto key = endpointKey(address, ports ? port : 0);
            auto it = index.find(key);
            if (it == index.end()) {
                it = index.emplace(key, out.size()).first;
                Endpoint e;
                e.address = address;
                e.port = ports ? port : 0;
                out.push_back(std::move(e));
            }
            return out[it->second];
        };

        forEachPacket(packets, subset, [&](const packet::PacketInfo &p) {
            if (!applies(p, kind)) return;
            Endpoint &src = touch(p.source, p.src_port);
            src.packets++; src.bytes += p.frame_length; src.txPackets++; src.txBytes += p.frame_length;
            Endpoint &dst = touch(p.destination, p.dst_port); // `touch` may reallocate: take dst after src is updated
            dst.packets++; dst.bytes += p.frame_length; dst.rxPackets++; dst.rxBytes += p.frame_length;
        });

        std::stable_sort(out.begin(), out.end(), [](const Endpoint &a, const Endpoint &b) { return a.bytes > b.bytes; });
        return out;
    }

    std::vector<Conversation> conversations(const std::vector<packet::PacketInfo> &packets, Subset subset, AddressKind kind) {
        std::unordered_map<std::string, size_t> index;
        std::vector<Conversation> out;
        std::vector<double> last;
        const bool ports = hasPort(kind);

        forEachPacket(packets, subset, [&](const packet::PacketInfo &p) {
            if (!applies(p, kind)) return;
            const uint16_t sp = ports ? p.src_port : 0, dp = ports ? p.dst_port : 0;
            // direction independent key: the smaller endpoint first
            const std::string a = endpointKey(p.source, sp), b = endpointKey(p.destination, dp);
            const std::string key = a < b ? a + "|" + b : b + "|" + a;

            auto it = index.find(key);
            if (it == index.end()) {
                it = index.emplace(key, out.size()).first;
                Conversation c;
                c.addressA = p.source; c.portA = sp;
                c.addressB = p.destination; c.portB = dp;
                c.start = p.time;
                c.firstPacket = p.number;
                out.push_back(std::move(c));
                last.push_back(p.time);
            }
            Conversation &c = out[it->second];
            c.packets++;
            c.bytes += p.frame_length;
            if (p.source == c.addressA && sp == c.portA) { c.packetsAtoB++; c.bytesAtoB += p.frame_length; }
            else { c.packetsBtoA++; c.bytesBtoA += p.frame_length; }
            c.start = std::min(c.start, p.time);
            last[it->second] = std::max(last[it->second], p.time);
            c.duration = last[it->second] - c.start;
        });

        std::stable_sort(out.begin(), out.end(), [](const Conversation &a, const Conversation &b) { return a.bytes > b.bytes; });
        return out;
    }

    namespace {
        std::string addrTest(const std::string &address, AddressKind kind) {
            switch (kind) {
                case AddressKind::Ipv4:
                    return "ip.addr == " + address;
                case AddressKind::Ipv6:
                    return "ipv6.addr == " + address;
                case AddressKind::Tcp:
                case AddressKind::Udp:
                case AddressKind::Sctp: {
                    const bool v6 = address.find(':') != std::string::npos;
                    return std::string(v6 ? "ipv6.addr == " : "ip.addr == ") + address;
                }
                case AddressKind::Ethernet:
                    return "eth.addr == \"" + address + "\"";
                case AddressKind::Wlan:
                    return "wlan.sa == \"" + address + "\" || wlan.da == \"" + address + "\"";
                case AddressKind::Bluetooth:
                    return "bt.handle == \"" + address + "\"";
                case AddressKind::Usb:
                    return "usb.device == \"" + address + "\"";
            }
            return "ip.addr == " + address;
        }
    } // namespace

    std::string conversationFilter(const Conversation &c, AddressKind kind) {
        if (kind == AddressKind::Usb) {
            return "usb";
        }
        if (kind == AddressKind::Bluetooth) {
            return "bt.handle == \"" + c.addressA + "\"";
        }
        if (kind == AddressKind::Wlan) {
            return "(wlan.sa == \"" + c.addressA + "\" && wlan.da == \"" + c.addressB + "\") || "
                   "(wlan.sa == \"" + c.addressB + "\" && wlan.da == \"" + c.addressA + "\")";
        }
        std::string f = addrTest(c.addressA, kind) + " && " + addrTest(c.addressB, kind);
        if (kind == AddressKind::Tcp) {
            f += " && tcp.port == " + std::to_string(c.portA) + " && tcp.port == " + std::to_string(c.portB);
        } else if (kind == AddressKind::Udp) {
            f += " && udp.port == " + std::to_string(c.portA) + " && udp.port == " + std::to_string(c.portB);
        } else if (kind == AddressKind::Sctp) {
            f += " && sctp.port == " + std::to_string(c.portA) + " && sctp.port == " + std::to_string(c.portB);
        }
        return f;
    }

    std::string endpointFilter(const Endpoint &e, AddressKind kind) {
        if (kind == AddressKind::Usb) {
            return "usb";
        }
        if (kind == AddressKind::Bluetooth) {
            return "bt.handle == \"" + e.address + "\"";
        }
        std::string f = addrTest(e.address, kind);
        if (kind == AddressKind::Tcp) f += " && tcp.port == " + std::to_string(e.port);
        else if (kind == AddressKind::Udp) f += " && udp.port == " + std::to_string(e.port);
        else if (kind == AddressKind::Sctp) f += " && sctp.port == " + std::to_string(e.port);
        return f;
    }

    const char *severityName(Severity s) {
        switch (s) {
            case Severity::Chat: return "Chat";
            case Severity::Note: return "Note";
            case Severity::Warn: return "Warning";
            case Severity::Error: return "Error";
        }
        return "";
    }

    std::vector<ExpertItem> expertInfo(const std::vector<packet::PacketInfo> &packets, Subset subset, double captureStartEpoch) {
        struct Def { Severity severity; const char *summary; const char *filter; };
        static const Def defs[] = {
            {Severity::Error, "Malformed packet", "malformed"},
            {Severity::Error, "IPv4: bad header checksum", "ip.checksum.status == 0"},
            {Severity::Error, "TCP: bad checksum", "tcp.checksum.status == 0"},
            {Severity::Error, "UDP: bad checksum", "udp.checksum.status == 0"},
            {Severity::Error, "ICMP: bad checksum", "icmp.checksum.status == 0 || icmpv6.checksum.status == 0"},
            {Severity::Warn, "TCP: previous segment not captured", "tcp.analysis.lost_segment"},
            {Severity::Warn, "TCP: retransmission", "tcp.analysis.retransmission"},
            {Severity::Warn, "TCP: out-of-order segment", "tcp.analysis.out_of_order"},
            {Severity::Warn, "TCP: zero window", "tcp.analysis.zero_window"},
            {Severity::Warn, "TCP: connection reset (RST)", "tcp.flags.rst"},
            {Severity::Warn, "TLS: wrong key (the authentication tag of a record does not match)", "tls.decryption_status == \"tag_failure\""},
            {Severity::Warn, "TLS: records not decrypted because TCP data is missing before them", "tls.decryption_status == \"capture_gap\""},
            {Severity::Warn, "TLS: malformed protected record", "tls.decryption_status == \"malformed\""},
            {Severity::Warn, "TLS: decryption state lost (too many TLS records for the session table)", "tls.decryption_status == \"state_lost\""},
            {Severity::Note, "TLS: no key material for the connection", "tls.decryption_status == \"no_key\""},
            {Severity::Note, "TLS: unsupported cipher suite or version", "tls.decryption_status == \"unsupported_suite\""},
            {Severity::Note, "TLS: ServerHello not captured (cipher suite unknown)", "tls.decryption_status == \"no_handshake\""},
            {Severity::Note, "TLS: 1.3 early data (0-RTT) is not decrypted", "tls.decryption_status == \"early_data\""},
            {Severity::Note, "TLS: decryption is not available in this build (no OpenSSL)", "tls.decryption_status == \"unavailable\""},
            {Severity::Warn, "DTLS: wrong key (the authentication tag of a record does not match)", "dtls.decryption_status == \"tag_failure\""},
            {Severity::Warn, "DTLS: malformed protected record", "dtls.decryption_status == \"malformed\""},
            {Severity::Warn, "DTLS: decryption state lost (too many DTLS fragments or records for the session table)", "dtls.decryption_status == \"state_lost\""},
            {Severity::Note, "DTLS: no key material for the connection", "dtls.decryption_status == \"no_key\""},
            {Severity::Note, "DTLS: unsupported cipher suite or version (only DTLS 1.2 AES-GCM is decrypted)", "dtls.decryption_status == \"unsupported_suite\""},
            {Severity::Note, "DTLS: ServerHello not captured (cipher suite unknown)", "dtls.decryption_status == \"no_handshake\""},
            {Severity::Note, "DTLS: decryption is not available in this build (no OpenSSL)", "dtls.decryption_status == \"unavailable\""},
            {Severity::Note, "TCP: duplicate ACK", "tcp.analysis.duplicate_ack"},
            {Severity::Note, "TCP: keep-alive", "tcp.analysis.keep_alive"},
            {Severity::Note, "TCP: window update", "tcp.analysis.window_update"},
            {Severity::Chat, "Checksum not verified (capture cut short, or checksum offload)",
             "ip.checksum.status == 2 || tcp.checksum.status == 2 || udp.checksum.status == 2 || icmp.checksum.status == 2 || icmpv6.checksum.status == 2"},
            {Severity::Chat, "TLS: records decrypted with the key log", "tls.decryption_status == \"decrypted\""},
            {Severity::Chat, "DTLS: records decrypted with the key log", "dtls.decryption_status == \"decrypted\""},
            {Severity::Chat, "TCP: connection request (SYN)", "tcp.flags.syn && !tcp.flags.ack"},
            {Severity::Chat, "TCP: connection finished (FIN)", "tcp.flags.fin"},
        };
        std::vector<ExpertItem> out;
        for (const auto &d: defs) {
            auto compiled = filter::Filter::compile(d.filter);
            if (!compiled.ok) continue;
            ExpertItem item{d.severity, d.summary, d.filter, 0};
            filter::Context context;
            context.captureStartEpoch = captureStartEpoch;
            auto visit = [&](size_t i) {
                context.previous = i ? &packets[i - 1] : nullptr;
                if (compiled.filter.matches(packets[i], context)) ++item.count;
            };
            if (subset) { for (uint32_t i: *subset) if (i < packets.size()) visit(i); }
            else { for (size_t i = 0; i < packets.size(); ++i) visit(i); }
            if (item.count > 0) out.push_back(std::move(item));
        }
        std::stable_sort(out.begin(), out.end(), [](const ExpertItem &a, const ExpertItem &b) { return a.severity > b.severity; });
        return out;
    }

    namespace {
        std::string linkName(uint32_t t) {
            switch (t) {
                case 1: return "Ethernet";
                case 0:
                case 108: return "Loopback";
                case 113:
                case 276: return "Linux cooked capture";
                case 105: return "IEEE 802.11 wireless LAN";
                case 127: return "Radiotap";
                case 192: return "PPI";
                default: return "";   // raw IP: no link layer to show
            }
        }

        std::string applicationName(const std::string &protocol) {
            if (protocol == "DNS") return "Domain Name System";
            if (protocol == "DHCP") return "Dynamic Host Configuration Protocol";
            if (protocol == "SNMP") return "Simple Network Management Protocol";
            if (protocol == "Telnet") return "Telnet";
            if (protocol == "SMTP") return "Simple Mail Transfer Protocol";
            if (protocol == "BGP") return "Border Gateway Protocol";
            if (protocol == "HTTP") return "Hypertext Transfer Protocol";
            if (protocol == "HTTP2") return "Hypertext Transfer Protocol 2";
            if (protocol == "TLS") return "Transport Layer Security";
            if (protocol == "DTLS") return "Datagram Transport Layer Security";
            if (protocol == "NTP") return "Network Time Protocol";
            if (protocol == "MDNS") return "Multicast Domain Name System";
            if (protocol == "FTP") return "File Transfer Protocol";
            if (protocol == "FTP-DATA") return "File Transfer Protocol (data)";
            if (protocol == "TFTP") return "Trivial File Transfer Protocol";
            if (protocol == "SSH") return "Secure Shell";
            return "";
        }

        // LLDP/LACP/MAC-Control/PPPoE/MPLS arrive as EtherTypes; LLC/STP/SNAP behind an 802.3 length field.
        std::string ethernetSubprotocol(const packet::PacketInfo &p) {
            if (p.ether_type == 0x8863) return "PPPoE Discovery";
            if (p.ether_type == 0x8864) return "PPPoE Session";
            if (p.ether_type == 0x888E) return "802.1X Authentication";
            if (p.ether_type == 0x8847 || p.ether_type == 0x8848) return "MultiProtocol Label Switching";
            if (p.ether_type == 0x88CC) return "Link Layer Discovery Protocol";
            if (p.ether_type == 0x8809) return "Slow Protocols";
            if (p.ether_type == 0x8808) return "Ethernet MAC Control";
            if (p.has_llc) {
                if (p.protocol == "STP" || p.protocol == "RSTP" || p.protocol == "MSTP") return "Spanning Tree Protocol";
                if (p.protocol == "SNAP") return "Subnetwork Access Protocol";
                return "Logical Link Control";
            }
            return "";
        }

        // Summaries carry no field tree, so the encapsulation chain is rebuilt from the state each dissector left.
        std::vector<std::string> chain(const packet::PacketInfo &p) {
            std::vector<std::string> c;
            if (auto l = linkName(p.link_type); !l.empty()) c.push_back(l);
            if (!p.vlan_ids.empty()) c.push_back("802.1Q Virtual LAN");
            const auto sub = ethernetSubprotocol(p);
            if (!sub.empty()) c.push_back(sub);

            if (p.ip_version == 4) c.push_back("Internet Protocol Version 4");
            else if (p.ip_version == 6) c.push_back("Internet Protocol Version 6");
            else if (p.protocol == "ARP") c.push_back("Address Resolution Protocol");
            else if (p.protocol == "RARP") c.push_back("Reverse Address Resolution Protocol");
            else if (p.protocol == "Malformed" || p.protocol == "Unknown") c.push_back("Malformed / undecoded");
            else if (sub.empty()) c.push_back("Data");

            if (p.ip_version != 0 && p.ip_frag == 1) {
                c.push_back("Fragmented IP data");
                return c;
            }
            if (p.has_ipip) c.push_back("IP-in-IP");
            if (p.has_gre) c.push_back(p.protocol.rfind("ERSPAN", 0) == 0 ? "ERSPAN" : "GRE");

            if (p.ip_protocol == 6) c.push_back("Transmission Control Protocol");
            else if (p.ip_protocol == 17) c.push_back("User Datagram Protocol");
            else if (p.ip_protocol == 1) c.push_back("Internet Control Message Protocol");
            else if (p.ip_protocol == 58) c.push_back("Internet Control Message Protocol v6");
            else if (p.ip_version != 0 && p.ip_protocol != 4 && p.ip_protocol != 41 && p.ip_protocol != 47 && !p.has_gre && !p.has_ipip) c.push_back("Other IP protocol");
            // HTTP that was decrypted from TLS sits below the TLS layer
            if (p.ip_protocol == 6 && p.protocol != "TLS" && dissect::tlsSummaryState(p) == dissect::TlsRecordState::Decrypted) c.push_back(applicationName("TLS"));
            if (auto a = applicationName(p.protocol); !a.empty()) c.push_back(a);
            return c;
        }

        void sortNode(HierarchyNode &n) {
            std::stable_sort(n.children.begin(), n.children.end(), [](const HierarchyNode &a, const HierarchyNode &b) { return a.bytes > b.bytes; });
            for (auto &c: n.children) sortNode(c);
        }
    } // namespace

    HierarchyNode protocolHierarchy(const std::vector<packet::PacketInfo> &packets, Subset subset) {
        HierarchyNode root;
        root.name = "Frame";
        forEachPacket(packets, subset, [&](const packet::PacketInfo &p) {
            HierarchyNode *node = &root;
            node->packets++;
            node->bytes += p.frame_length;
            for (const auto &name: chain(p)) {
                auto it = std::find_if(node->children.begin(), node->children.end(), [&](const HierarchyNode &c) { return c.name == name; });
                if (it == node->children.end()) {
                    node->children.push_back(HierarchyNode{name, 0, 0, {}});
                    it = node->children.end() - 1;
                }
                it->packets++;
                it->bytes += p.frame_length;
                node = &*it;
            }
        });
        sortNode(root);
        return root;
    }
} // namespace stats
