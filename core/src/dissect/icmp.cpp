// ICMP (RFC 792) and ICMPv6 (RFC 4443 / 4861): message names, codes and the interesting contents.
#include "protocols.h"

#include "util.h"

#include <string>
#include <vector>

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
        if (v6) {   // IPv6 header: next header at 6, addresses at 8 and 24; the transport header follows when no extension headers are quoted
            if (n < 40 || (static_cast<uint8_t>(d[0]) >> 4) != 6) return "";
            const unsigned next = static_cast<uint8_t>(d[6]);
            std::string out = network::formatIPv6(d + 8) + " -> " + network::formatIPv6(d + 24) + " " + protocolName(next);
            if ((next == 6 || next == 17) && n >= 44) out += " ports " + std::to_string(be16(d + 40)) + " -> " + std::to_string(be16(d + 42));
            return out;
        }
        if (n < sizeof(network::IPHeader)) return "";
        network::IPHeader ip;
        std::memcpy(&ip, d, sizeof(ip));
        if (ip.version != 4) return "";
        const size_t hl = static_cast<size_t>(ip.ihl) * 4;
        std::string out = ip4(ip.src_addr) + " -> " + ip4(ip.dst_addr) + " " + protocolName(ip.protocol);
        if ((ip.protocol == 6 || ip.protocol == 17) && n >= hl + 4) out += " ports " + std::to_string(be16(d + hl)) + " -> " + std::to_string(be16(d + hl + 2));
        return out;
    }

    std::string macText(const char *p) {
        char b[24];
        std::snprintf(b, sizeof b, "%02x:%02x:%02x:%02x:%02x:%02x", static_cast<uint8_t>(p[0]), static_cast<uint8_t>(p[1]), static_cast<uint8_t>(p[2]),
                      static_cast<uint8_t>(p[3]), static_cast<uint8_t>(p[4]), static_cast<uint8_t>(p[5]));
        return b;
    }

    // ICMPv4 messages other than echo: the four bytes after the checksum and what follows
    void addV4Body(Field &l, size_t o, const char *d, size_t n, unsigned type, unsigned code, const std::string &quoted) {
        auto quote = [&](size_t at) {
            if (!quoted.empty() && n > at) l.add("Original packet: " + quoted, o + at, n - at);
            else if (n > at) l.add("Data (" + std::to_string(n - at) + " bytes)", o + at, n - at);
        };
        switch (type) {
            case 3:
                l.add("Unused", o + 4, 2);
                if (code == 4) l.add("MTU of next hop: " + std::to_string(be16(d + 6)), o + 6, 2);
                else l.add("Unused", o + 6, 2);
                quote(8);
                break;
            case 4: case 11:
                l.add("Unused", o + 4, 4);
                quote(8);
                break;
            case 5:
                l.add("Gateway address: " + ip4(d + 4), o + 4, 4);
                quote(8);
                break;
            case 12:
                l.add("Pointer: " + std::to_string(static_cast<uint8_t>(d[4])), o + 4, 1);
                l.add("Unused", o + 5, 3);
                quote(8);
                break;
            case 13: case 14:
                l.add("Identifier: " + hexString(be16(d + 4), 4), o + 4, 2);
                l.add("Sequence Number: " + std::to_string(be16(d + 6)), o + 6, 2);
                if (n >= 20) {
                    l.add("Originate timestamp: " + std::to_string(be32(d + 8)) + " ms since midnight UTC", o + 8, 4);
                    l.add("Receive timestamp: " + std::to_string(be32(d + 12)) + " ms since midnight UTC", o + 12, 4);
                    l.add("Transmit timestamp: " + std::to_string(be32(d + 16)) + " ms since midnight UTC", o + 16, 4);
                }
                break;
            case 17: case 18:
                l.add("Identifier: " + hexString(be16(d + 4), 4), o + 4, 2);
                l.add("Sequence Number: " + std::to_string(be16(d + 6)), o + 6, 2);
                if (n >= 12) l.add("Address mask: " + ip4(d + 8), o + 8, 4);
                break;
            case 9: { // router advertisement: count, entry size (words), lifetime, then {address, preference}
                const unsigned count = static_cast<uint8_t>(d[4]), words = static_cast<uint8_t>(d[5]);
                l.add("Number of addresses: " + std::to_string(count), o + 4, 1);
                l.add("Address entry size: " + std::to_string(words) + " words", o + 5, 1);
                l.add("Lifetime: " + std::to_string(be16(d + 6)) + " seconds", o + 6, 2);
                for (unsigned k = 0; k < count && words >= 2 && 8 + (k + 1) * words * 4 <= n; ++k) {
                    const size_t at = 8 + k * words * 4;
                    l.add("Router address: " + ip4(d + at) + ", preference " + std::to_string(static_cast<int32_t>(be32(d + at + 4))), o + at, words * 4);
                }
                break;
            }
            default:
                l.add("Unused / message specific (4 bytes)", o + 4, 4);
                if (n > 8) l.add("Data (" + std::to_string(n - 8) + " bytes)", o + 8, n - 8);
        }
    }

    // Neighbor Discovery options (RFC 4861/8106) in d[from, n)
    void addNdpOptions(Field &l, size_t o, const char *d, size_t n, size_t from) {
        size_t i = from;
        int count = 0;
        while (n - std::min(n, i) >= 2 && count++ < 32) {
            const unsigned t = static_cast<uint8_t>(d[i]), units = static_cast<uint8_t>(d[i + 1]);
            const size_t len = units * 8u;
            if (units == 0) { l.add("[Malformed option: length 0]", o + i, 2); return; }
            const size_t take = std::min(len, n - i);
            std::string name, text;
            std::vector<std::string> kids;
            switch (t) {
                case 1: case 2:
                    name = t == 1 ? "Source link-layer address" : "Target link-layer address";
                    if (len >= 8 && take >= 8) text = macText(d + i + 2);
                    break;
                case 3:
                    name = "Prefix information";
                    if (len == 32 && take >= 32) {
                        const unsigned flags = static_cast<uint8_t>(d[i + 3]);
                        text = network::formatIPv6(d + i + 16) + "/" + std::to_string(static_cast<uint8_t>(d[i + 2]));
                        kids = {"Prefix length: " + std::to_string(static_cast<uint8_t>(d[i + 2])),
                                std::string("Flags: ") + ((flags & 0x80) ? "L (on-link) " : "") + ((flags & 0x40) ? "A (autonomous) " : "") + hexString(flags, 2),
                                "Valid lifetime: " + std::to_string(be32(d + i + 4)) + " seconds", "Preferred lifetime: " + std::to_string(be32(d + i + 8)) + " seconds",
                                "Prefix: " + network::formatIPv6(d + i + 16)};
                    }
                    break;
                case 4: name = "Redirected header"; break;
                case 5:
                    name = "MTU";
                    if (len >= 8 && take >= 8) text = std::to_string(be32(d + i + 4));
                    break;
                case 24: name = "Route information"; break;
                case 25:
                    name = "Recursive DNS server";
                    if (len >= 24 && take >= len) {
                        kids.push_back("Lifetime: " + std::to_string(be32(d + i + 4)) + " seconds");
                        for (size_t k = i + 8; k + 16 <= i + len; k += 16) { kids.push_back("Server: " + network::formatIPv6(d + k)); text += (text.empty() ? "" : ", ") + network::formatIPv6(d + k); }
                    }
                    break;
                case 31: name = "DNS search list"; break;
                default: name = "Option " + std::to_string(t);
            }
            Field &f = l.add("ICMPv6 Option (" + std::to_string(t) + ") " + name + (text.empty() ? "" : ": " + text), o + i, take);
            f.add("Type: " + std::to_string(t), o + i, 1);
            f.add("Length: " + std::to_string(units) + " (" + std::to_string(len) + " bytes)", o + i + 1, 1);
            for (const auto &k: kids) f.add(k, o + i + 2, take - 2);
            if (len > n - i) { l.add("[Option continues past the end of the message]", o + i, take); return; }
            i += len;
        }
    }

    void addV6Body(Field &l, size_t o, const char *d, size_t n, unsigned type, const std::string &quoted) {
        auto quote = [&](size_t at) {
            if (!quoted.empty() && n > at) l.add("Original packet: " + quoted, o + at, n - at);
            else if (n > at) l.add("Data (" + std::to_string(n - at) + " bytes)", o + at, n - at);
        };
        switch (type) {
            case 1: case 3:
                l.add("Unused", o + 4, 4);
                quote(8);
                break;
            case 2:
                l.add("MTU: " + std::to_string(be32(d + 4)), o + 4, 4);
                quote(8);
                break;
            case 4:
                l.add("Pointer: " + std::to_string(be32(d + 4)), o + 4, 4);
                quote(8);
                break;
            case 130: { // multicast listener query: v1 is 24 bytes, v2 is 28 or more
                l.add("Maximum response delay: " + std::to_string(be16(d + 4)) + " ms", o + 4, 2);
                l.add("Reserved", o + 6, 2);
                if (n >= 24) l.add("Multicast address: " + network::formatIPv6(d + 8), o + 8, 16);
                if (n >= 28) {
                    const unsigned sq = static_cast<uint8_t>(d[24]), count = be16(d + 26);
                    l.add(std::string("Flags: S=") + ((sq & 8) ? "1" : "0") + ", QRV=" + std::to_string(sq & 7), o + 24, 1);
                    l.add("QQIC: " + std::to_string(static_cast<uint8_t>(d[25])), o + 25, 1);
                    l.add("Number of sources: " + std::to_string(count), o + 26, 2);
                    for (unsigned k = 0; k < count && 28 + (k + 1) * 16 <= n; ++k) l.add("Source address: " + network::formatIPv6(d + 28 + k * 16), o + 28 + k * 16, 16);
                }
                break;
            }
            case 131: case 132:
                l.add("Maximum response delay: " + std::to_string(be16(d + 4)) + " ms", o + 4, 2);
                l.add("Reserved", o + 6, 2);
                if (n >= 24) l.add("Multicast address: " + network::formatIPv6(d + 8), o + 8, 16);
                break;
            case 143: { // MLDv2 report: records of {type, aux len, sources, address, sources, aux data}
                const unsigned records = be16(d + 6);
                l.add("Reserved", o + 4, 2);
                l.add("Number of multicast address records: " + std::to_string(records), o + 6, 2);
                size_t at = 8;
                static const char *recordTypes[] = {"", "MODE_IS_INCLUDE", "MODE_IS_EXCLUDE", "CHANGE_TO_INCLUDE_MODE", "CHANGE_TO_EXCLUDE_MODE", "ALLOW_NEW_SOURCES", "BLOCK_OLD_SOURCES"};
                for (unsigned k = 0; k < records && at + 20 <= n; ++k) {
                    const unsigned rt = static_cast<uint8_t>(d[at]), aux = static_cast<uint8_t>(d[at + 1]), sources = be16(d + at + 2);
                    const size_t size = 20 + sources * 16u + aux * 4u;
                    Field &r = l.add("Multicast Address Record: " + std::string(rt >= 1 && rt <= 6 ? recordTypes[rt] : "type " + std::to_string(rt)) + " " + network::formatIPv6(d + at + 4), o + at, std::min(size, n - at));
                    r.add("Record type: " + std::to_string(rt), o + at, 1);
                    r.add("Number of sources: " + std::to_string(sources), o + at + 2, 2);
                    r.add("Multicast address: " + network::formatIPv6(d + at + 4), o + at + 4, 16);
                    for (unsigned q = 0; q < sources && at + 20 + (q + 1) * 16 <= n; ++q) r.add("Source address: " + network::formatIPv6(d + at + 20 + q * 16), o + at + 20 + q * 16, 16);
                    at += size;
                }
                break;
            }
            case 133:
                l.add("Reserved", o + 4, 4);
                addNdpOptions(l, o, d, n, 8);
                break;
            case 134: {
                const unsigned flags = static_cast<uint8_t>(d[5]);
                l.add("Cur hop limit: " + std::to_string(static_cast<uint8_t>(d[4])), o + 4, 1);
                Field &f = l.add(std::string("Flags: ") + hexString(flags, 2) + ((flags & 0x80) ? ", Managed address configuration" : "") + ((flags & 0x40) ? ", Other configuration" : "") +
                                 ((flags & 0x20) ? ", Home agent" : "") + ", Preference " + (((flags >> 3) & 3) == 1 ? "high" : ((flags >> 3) & 3) == 3 ? "low" : ((flags >> 3) & 3) == 0 ? "medium" : "reserved"),
                                 o + 5, 1);
                (void) f;
                l.add("Router lifetime: " + std::to_string(be16(d + 6)) + " seconds", o + 6, 2);
                if (n >= 16) {
                    l.add("Reachable time: " + std::to_string(be32(d + 8)) + " ms", o + 8, 4);
                    l.add("Retrans timer: " + std::to_string(be32(d + 12)) + " ms", o + 12, 4);
                    addNdpOptions(l, o, d, n, 16);
                }
                break;
            }
            case 135:
                l.add("Reserved", o + 4, 4);
                if (n >= 24) { l.add("Target Address: " + network::formatIPv6(d + 8), o + 8, 16); addNdpOptions(l, o, d, n, 24); }
                break;
            case 136: {
                const unsigned flags = static_cast<uint8_t>(d[4]);
                l.add(std::string("Flags: ") + hexString(flags, 2) + ((flags & 0x80) ? ", Router" : "") + ((flags & 0x40) ? ", Solicited" : "") + ((flags & 0x20) ? ", Override" : ""), o + 4, 1);
                l.add("Reserved", o + 5, 3);
                if (n >= 24) { l.add("Target Address: " + network::formatIPv6(d + 8), o + 8, 16); addNdpOptions(l, o, d, n, 24); }
                break;
            }
            case 137:
                l.add("Reserved", o + 4, 4);
                if (n >= 40) {
                    l.add("Target Address: " + network::formatIPv6(d + 8), o + 8, 16);
                    l.add("Destination Address: " + network::formatIPv6(d + 24), o + 24, 16);
                    addNdpOptions(l, o, d, n, 40);
                }
                break;
            default:
                l.add("Unused / message specific (4 bytes)", o + 4, 4);
                if (n > 8) l.add("Data (" + std::to_string(n - 8) + " bytes)", o + 8, n - 8);
        }
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
        if (!v6 && (type == 3 || type == 4 || type == 5 || type == 11 || type == 12)) quoted = quotedPacket(body, bodyLen, v6); // the quoted IP header follows the 8-byte ICMP header
        if (v6 && (type == 1 || type == 2 || type == 3 || type == 4)) quoted = quotedPacket(body, bodyLen, v6);
        if (v6 && (type == 135 || type == 136) && bodyLen >= 16) target = network::formatIPv6(body); // the 4 reserved/flag bytes are part of the header
        if (!quoted.empty()) info += " [orig: " + quoted + "]";
        if (!target.empty()) info += " target " + target;
    }
    if (v6 && type == 2) info += " mtu " + std::to_string(be32(data + 4));
    if (!v6 && type == 3 && code == 4 && length >= 8) info += " next-hop mtu " + std::to_string(be16(data + 6));
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
    } else if (v6) {
        addV6Body(l, o, data, length, type, quoted);
    } else {
        addV4Body(l, o, data, length, type, code, quoted);
    }
}
