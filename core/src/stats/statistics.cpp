#include "statistics.h"

#include <algorithm>
#include <unordered_map>

namespace stats {
    namespace {
        bool applies(const packet::PacketInfo &p, AddressKind kind) {
            switch (kind) {
                case AddressKind::Ipv4: return p.ip_version == 4;
                case AddressKind::Ipv6: return p.ip_version == 6;
                case AddressKind::Tcp: return p.ip_version != 0 && p.ip_protocol == 6;
                case AddressKind::Udp: return p.ip_version != 0 && p.ip_protocol == 17;
            }
            return false;
        }

        bool hasPort(AddressKind kind) { return kind == AddressKind::Tcp || kind == AddressKind::Udp; }

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

    const char *kindName(AddressKind kind) {
        switch (kind) {
            case AddressKind::Ipv4: return "IPv4";
            case AddressKind::Ipv6: return "IPv6";
            case AddressKind::Tcp: return "TCP";
            case AddressKind::Udp: return "UDP";
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
        // `ip.addr == a` for IPv4 kinds, `ipv6.addr == a` for IPv6; TCP/UDP kinds decide by the address text
        std::string addrTest(const std::string &address, AddressKind kind) {
            const bool v6 = kind == AddressKind::Ipv6 || address.find(':') != std::string::npos;
            return std::string(v6 ? "ipv6.addr == " : "ip.addr == ") + address;
        }
    } // namespace

    std::string conversationFilter(const Conversation &c, AddressKind kind) {
        std::string f = addrTest(c.addressA, kind) + " && " + addrTest(c.addressB, kind);
        if (kind == AddressKind::Tcp) {
            f += " && tcp.port == " + std::to_string(c.portA) + " && tcp.port == " + std::to_string(c.portB);
        } else if (kind == AddressKind::Udp) {
            f += " && udp.port == " + std::to_string(c.portA) + " && udp.port == " + std::to_string(c.portB);
        }
        return f;
    }

    std::string endpointFilter(const Endpoint &e, AddressKind kind) {
        std::string f = addrTest(e.address, kind);
        if (kind == AddressKind::Tcp) f += " && tcp.port == " + std::to_string(e.port);
        else if (kind == AddressKind::Udp) f += " && udp.port == " + std::to_string(e.port);
        return f;
    }

    namespace {
        std::string linkName(uint32_t t) {
            switch (t) {
                case 1: return "Ethernet";
                case 0:
                case 108: return "Loopback";
                case 113:
                case 276: return "Linux cooked capture";
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
            if (protocol == "TLS") return "Transport Layer Security";
            if (protocol == "NTP") return "Network Time Protocol";
            if (protocol == "mDNS") return "Multicast DNS";
            return "";
        }

        std::vector<std::string> chain(const packet::PacketInfo &p) {
            std::vector<std::string> c;
            if (auto l = linkName(p.link_type); !l.empty()) c.push_back(l);
            if (!p.vlan_ids.empty()) c.push_back("802.1Q Virtual LAN");
            if (p.ip_version == 4) c.push_back("Internet Protocol Version 4");
            else if (p.ip_version == 6) c.push_back("Internet Protocol Version 6");
            else if (p.protocol == "ARP") c.push_back("Address Resolution Protocol");
            else if (p.protocol == "RARP") c.push_back("Reverse Address Resolution Protocol");
            else if (p.protocol == "Malformed" || p.protocol == "Unknown") c.push_back("Malformed / undecoded");
            else c.push_back("Data");

            if (p.ip_version != 0) {
                switch (p.ip_protocol) {
                    case 6: c.push_back("Transmission Control Protocol"); break;
                    case 17: c.push_back("User Datagram Protocol"); break;
                    case 1: c.push_back("Internet Control Message Protocol"); break;
                    case 58: c.push_back("Internet Control Message Protocol v6"); break;
                    case 0: break;
                    default: c.push_back("Other IP protocol"); break;
                }
                if (auto a = applicationName(p.protocol); !a.empty()) c.push_back(a);
            }
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
