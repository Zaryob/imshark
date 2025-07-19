// ICMP (RFC 792) and ICMPv6 (RFC 4443 / 4861): message names, codes and the interesting contents.
#include "protocols.h"

#include "util.h"

#include <network/l3_network/ip_header.h>
#include <network/l4_transport/icmp_header.h>
#include <network/utils.h>

using packet::Field;

namespace {
    using namespace dissect;

    std::string typeName(unsigned type, bool v6) {
        if (!v6) {
            switch (type) {
                case 0: return "Echo (ping) reply";
                case 3: return "Destination unreachable";
                case 4: return "Source quench";
                case 5: return "Redirect";
                case 8: return "Echo (ping) request";
                case 9: return "Router advertisement";
                case 10: return "Router solicitation";
                case 11: return "Time-to-live exceeded";
                case 12: return "Parameter problem";
                case 13: return "Timestamp request";
                case 14: return "Timestamp reply";
                case 17: return "Address mask request";
                case 18: return "Address mask reply";
                default: return "Type " + std::to_string(type);
            }
        }
        switch (type) {
            case 1: return "Destination unreachable";
            case 2: return "Packet too big";
            case 3: return "Time exceeded";
            case 4: return "Parameter problem";
            case 128: return "Echo (ping) request";
            case 129: return "Echo (ping) reply";
            case 130: return "Multicast listener query";
            case 131: return "Multicast listener report";
            case 132: return "Multicast listener done";
            case 133: return "Router solicitation";
            case 134: return "Router advertisement";
            case 135: return "Neighbor solicitation";
            case 136: return "Neighbor advertisement";
            case 137: return "Redirect";
            case 143: return "Multicast listener report v2";
            default: return "Type " + std::to_string(type);
        }
    }

    std::string codeName(unsigned type, unsigned code, bool v6) {
        if (!v6 && type == 3) {
            switch (code) {
                case 0: return "Network unreachable";
                case 1: return "Host unreachable";
                case 2: return "Protocol unreachable";
                case 3: return "Port unreachable";
                case 4: return "Fragmentation needed and DF set";
                case 5: return "Source route failed";
                case 13: return "Communication administratively filtered";
                default: return "";
            }
        }
        if (!v6 && type == 11) return code == 0 ? "TTL expired in transit" : code == 1 ? "Fragment reassembly time exceeded" : "";
        if (!v6 && type == 5) return code == 0 ? "Redirect for network" : code == 1 ? "Redirect for host" : "";
        if (v6 && type == 1) {
            switch (code) {
                case 0: return "No route to destination";
                case 1: return "Administratively prohibited";
                case 3: return "Address unreachable";
                case 4: return "Port unreachable";
                default: return "";
            }
        }
        if (v6 && type == 3) return code == 0 ? "Hop limit exceeded in transit" : code == 1 ? "Fragment reassembly time exceeded" : "";
        return "";
    }

    std::string protocolName(unsigned p) {
        switch (p) {
            case 1: return "ICMP";
            case 6: return "TCP";
            case 17: return "UDP";
            case 58: return "ICMPv6";
            default: return "protocol " + std::to_string(p);
        }
    }

    // Error messages carry the start of the packet that caused them: "orig 10.0.0.1 -> 10.0.0.2 UDP port 53"
    std::string quotedPacket(const char *d, size_t n, bool v6) {
        if (v6 || n < sizeof(network::IPHeader)) return "";
        network::IPHeader ip;
        std::memcpy(&ip, d, sizeof(ip));
        if (ip.version != 4) return "";
        const size_t hl = static_cast<size_t>(ip.ihl) * 4;
        std::string out = ip4(ip.src_addr) + " -> " + ip4(ip.dst_addr) + " " + protocolName(ip.protocol);
        if ((ip.protocol == 6 || ip.protocol == 17) && n >= hl + 4) out += " ports " + std::to_string(be16(d + hl)) + " -> " + std::to_string(be16(d + hl + 2));
        return out;
    }
} // namespace

void dissect::dissectIcmp(Context &ctx, const char *data, size_t length, bool v6) {
    auto &pack = ctx.pack;
    network::ICMPHeader icmp;
    if (!readStruct(data, length, 0, icmp)) {
        ctx.markMalformed("ICMP message too short");
        return;
    }
    pack.protocol = v6 ? "ICMPv6" : "ICMP";
    pack.app_type = icmp.type;
    pack.app_code = icmp.code;

    const unsigned type = icmp.type, code = icmp.code;
    const bool echo = v6 ? (type == 128 || type == 129) : (type == 0 || type == 8);
    const std::string codeText = codeName(type, code, v6);
    const char *body = data + sizeof(icmp);
    const size_t bodyLen = length - sizeof(icmp);

    std::string info = typeName(type, v6);
    std::string quoted;
    std::string target;
    if (echo) {
        char id[16];
        std::snprintf(id, sizeof id, "0x%04x", network::ntoh16(icmp.identifier));
        info += std::string("  id=") + id + ", seq=" + std::to_string(network::ntoh16(icmp.sequence)) + ", ttl=" + std::to_string(pack.ttl);
    } else {
        if (!codeText.empty()) info += " (" + codeText + ")";
        if (!v6 && (type == 3 || type == 11 || type == 12)) quoted = quotedPacket(body, bodyLen, v6); // the quoted IP header follows the 8-byte ICMP header
        if (v6 && (type == 135 || type == 136) && bodyLen >= 16) target = network::formatIPv6(body); // the 4 reserved/flag bytes are part of the header
        if (!quoted.empty()) info += " [orig: " + quoted + "]";
        if (!target.empty()) info += " target " + target;
    }
    pack.info = info;

    if (!ctx.wantFields()) return;
    const size_t o = ctx.offsetOf(data);
    Field &l = ctx.addLayer(v6 ? "Internet Control Message Protocol v6" : "Internet Control Message Protocol", o, length);
    l.add("Type: " + std::to_string(type) + " (" + typeName(type, v6) + ")", o, 1);
    l.add("Code: " + std::to_string(code) + (codeText.empty() ? "" : " (" + codeText + ")"), o + 1, 1);
    l.add("Checksum: " + hexString(network::ntoh16(icmp.checksum), 4), o + 2, 2);
    if (echo) {
        l.add("Identifier: " + hexString(network::ntoh16(icmp.identifier), 4) + " (" + std::to_string(network::ntoh16(icmp.identifier)) + ")", o + 4, 2);
        l.add("Sequence Number: " + std::to_string(network::ntoh16(icmp.sequence)), o + 6, 2);
        if (bodyLen > 0) l.add("Data (" + std::to_string(bodyLen) + " bytes)", o + sizeof(icmp), bodyLen);
    } else {
        l.add("Unused / message specific (4 bytes)", o + 4, 4);
        if (!quoted.empty()) l.add("Original packet: " + quoted, o + 8, bodyLen);
        if (!target.empty()) l.add("Target Address: " + target, o + 8, 16);
    }
}
