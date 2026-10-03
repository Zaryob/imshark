// DHCP / BOOTP: the fixed header and the options after the magic cookie.
#include "protocols.h"

#include "util.h"

#include <algorithm>
#include <vector>

#include <network/l7_application/dhcp_header.h>
#include <network/utils.h>

using packet::Field;

namespace {
    using namespace dissect;

    const char *messageTypeName(unsigned t) {
        switch (t) {
            case 1: return "Discover";
            case 2: return "Offer";
            case 3: return "Request";
            case 4: return "Decline";
            case 5: return "ACK";
            case 6: return "NAK";
            case 7: return "Release";
            case 8: return "Inform";
            default: return nullptr;
        }
    }

    const char *optionName(unsigned code) {
        switch (code) {
            case 1: return "Subnet Mask";
            case 3: return "Router";
            case 6: return "Domain Name Server";
            case 12: return "Host Name";
            case 15: return "Domain Name";
            case 2: return "Time Offset";
            case 4: return "Time Server";
            case 7: return "Log Server";
            case 26: return "Interface MTU";
            case 28: return "Broadcast Address";
            case 33: return "Static Route";
            case 43: return "Vendor-Specific Information";
            case 44: return "NetBIOS over TCP/IP Name Server";
            case 42: return "NTP Servers";
            case 50: return "Requested IP Address";
            case 51: return "IP Address Lease Time";
            case 53: return "DHCP Message Type";
            case 52: return "Option Overload";
            case 54: return "DHCP Server Identifier";
            case 55: return "Parameter Request List";
            case 56: return "Message";
            case 58: return "Renewal Time Value";
            case 59: return "Rebinding Time Value";
            case 60: return "Vendor class identifier";
            case 57: return "Maximum DHCP Message Size";
            case 61: return "Client identifier";
            case 66: return "TFTP Server Name";
            case 67: return "Bootfile name";
            case 119: return "Domain Search";
            case 121: return "Classless Static Route";
            case 252: return "Web Proxy Auto-Discovery";
            case 82: return "Relay Agent Information";
            case 255: return "End";
            default: return nullptr;
        }
    }

    std::string ipList(const char *d, size_t n) {
        std::string out;
        for (size_t i = 0; i + 4 <= n; i += 4) out += (out.empty() ? "" : ", ") + ip4(d + i);
        return out;
    }

    std::string decodeOption(unsigned code, const char *d, size_t n) {
        switch (code) {
            case 1: case 28: case 50: case 54:
                return n == 4 ? ip4(d) : "";
            case 3: case 6: case 42:
                return ipList(d, n);
            case 12: case 15: case 56: case 60: case 66: case 67: case 252:
                return std::string(d, n);
            case 26: case 57:
                return n == 2 ? std::to_string(be16(d)) : "";
            case 52: {
                if (n != 1) return "";
                const unsigned v = static_cast<uint8_t>(d[0]);
                return std::string(v == 1 ? "the file field holds options" : v == 2 ? "the sname field holds options" : v == 3 ? "the file and sname fields hold options" : "invalid") +
                       " (" + std::to_string(v) + ")";
            }
            case 51: case 58: case 59:
                return n == 4 ? std::to_string(be32(d)) + " seconds" : "";
            case 53: {
                if (n != 1) return "";
                const char *name = messageTypeName(static_cast<uint8_t>(d[0]));
                return std::string(name ? name : "?") + " (" + std::to_string(static_cast<uint8_t>(d[0])) + ")";
            }
            case 55: {
                std::string out;
                for (size_t i = 0; i < n; ++i) out += (out.empty() ? "" : ", ") + std::to_string(static_cast<uint8_t>(d[i]));
                return out;
            }
            case 61: {
                if (n < 2) return "";
                std::string mac;
                for (size_t i = 1; i < n; ++i) {
                    char b[4];
                    std::snprintf(b, sizeof b, "%02x", static_cast<uint8_t>(d[i]));
                    mac += (mac.empty() ? "" : ":") + std::string(b);
                }
                return "type " + std::to_string(static_cast<uint8_t>(d[0])) + ", " + mac;
            }
            default:
                return std::to_string(n) + " bytes";
        }
    }
} // namespace

void dissect::dissectDhcp(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "DHCP";

    network::DHCPHeader dhcp;
    if (!readStruct(data, length, 0, dhcp)) {
        ctx.markMalformed("DHCP message too short");
        return;
    }

    // options follow the 4-byte magic cookie 63 82 53 63
    const size_t optionsStart = sizeof(network::DHCPHeader) + 4;
    const bool haveOptions = length >= optionsStart && be32(data + sizeof(network::DHCPHeader)) == 0x63825363;

    constexpr size_t kSnameOffset = 44, kFileOffset = 108, kEndOfFixed = 236;
    struct Opt { unsigned code; size_t offset, length; int area; };   // area: 0 = options field, 1 = file, 2 = sname
    std::vector<Opt> options;
    unsigned msgType = 0, overload = 0;
    std::string hostname;
    bool areaEnded[3] = {false, false, false};

    // Reads options in data[from, to) into `options`; stops at End or at damage.
    auto parseArea = [&](size_t from, size_t to, int area) {
        size_t i = from;
        while (i < to && options.size() < 256) {
            const unsigned code = static_cast<uint8_t>(data[i]);
            if (code == 0) { ++i; continue; }                 // pad
            if (code == 255) { options.push_back({255, i, 1, area}); areaEnded[area] = true; break; }
            if (i + 1 >= to) break;
            const size_t n = static_cast<uint8_t>(data[i + 1]);
            if (i + 2 + n > to) break;
            options.push_back({code, i, 2 + n, area});
            if (code == 53 && n == 1) msgType = static_cast<uint8_t>(data[i + 2]);
            if (code == 12) hostname.assign(data + i + 2, n);
            if (code == 52 && n == 1 && area == 0) overload = static_cast<uint8_t>(data[i + 2]);
            i += 2 + n;
        }
    };
    if (haveOptions) {
        parseArea(optionsStart, length, 0);
        // option overload (RFC 2132 9.3): the file and/or sname fields continue the options, file first
        if ((overload & 1) && length >= kEndOfFixed) parseArea(kFileOffset, kEndOfFixed, 1);
        if ((overload & 2) && length >= kEndOfFixed) parseArea(kSnameOffset, kFileOffset, 2);
    }

    pack.app_type = static_cast<uint16_t>(msgType);
    pack.app_text = hostname;
    const char *typeName = messageTypeName(msgType);
    std::ostringstream info;
    info << "DHCP " << (typeName ? typeName : (dhcp.op == 1 ? "Boot Request" : dhcp.op == 2 ? "Boot Reply" : "message"))
         << " - Transaction ID 0x" << std::hex << network::ntoh32(dhcp.xid);
    pack.info = info.str();

    if (!ctx.wantFields()) return;
    const size_t p = ctx.offsetOf(data);
    Field &l = ctx.addLayer("Dynamic Host Configuration Protocol (" + std::string(typeName ? typeName : "message") + ")", p, length);
    l.add("Message type: " + std::string(dhcp.op == 1 ? "Boot Request (1)" : dhcp.op == 2 ? "Boot Reply (2)" : std::to_string(dhcp.op)), p, 1);
    l.add("Hardware type: " + hexString(dhcp.hw_type, 2), p + 1, 1);
    l.add("Hardware address length: " + std::to_string(dhcp.hw_len), p + 2, 1);
    l.add("Hops: " + std::to_string(dhcp.hops), p + 3, 1);
    l.add("Transaction ID: " + hexString(network::ntoh32(dhcp.xid), 8), p + 4, 4);
    l.add("Seconds elapsed: " + std::to_string(network::ntoh16(dhcp.secs)), p + 8, 2);
    l.add("Flags: " + hexString(network::ntoh16(dhcp.flags), 4) + (network::ntoh16(dhcp.flags) & 0x8000 ? " (Broadcast)" : " (Unicast)"), p + 10, 2);
    l.add("Client IP address: " + ip4(dhcp.cip_addr), p + 12, 4);
    l.add("Your (client) IP address: " + ip4(dhcp.yip_addr), p + 16, 4);
    l.add("Next server IP address: " + ip4(dhcp.sip_addr), p + 20, 4);
    l.add("Relay agent IP address: " + ip4(dhcp.gip_addr), p + 24, 4);
    l.add("Client MAC address: " + network::getMACAddressString(dhcp.ch_addr), p + 28, 6);
    if (haveOptions) {
        l.add("Magic cookie: DHCP", p + sizeof(network::DHCPHeader), 4);
    }
    // the two text fields of the fixed header, unless they carry options instead
    auto cString = [&](size_t at, size_t max) {
        size_t n = 0;
        while (n < max && data[at + n] != 0) ++n;
        return std::string(data + at, n);
    };
    if (!(overload & 2)) {
        const std::string name = cString(kSnameOffset, 64);
        l.add(name.empty() ? "Server host name not given" : "Server host name: " + name, p + kSnameOffset, 64);
    } else {
        l.add("Server host name: options (option overload)", p + kSnameOffset, 64);
    }
    if (!(overload & 1)) {
        const std::string file = cString(kFileOffset, 128);
        l.add(file.empty() ? "Boot file name not given" : "Boot file name: " + file, p + kFileOffset, 128);
    } else {
        l.add("Boot file name: options (option overload)", p + kFileOffset, 128);
    }
    if (haveOptions) {
        static const char *areaNames[] = {nullptr, "Options in the file field (option overload)", "Options in the sname field (option overload)"};
        for (const auto &o: options) {
            if (o.area != 0 && (options.empty() || &o == &*std::find_if(options.begin(), options.end(), [&](const Opt &x) { return x.area == o.area; }))) {
                l.add(areaNames[o.area], p + (o.area == 1 ? kFileOffset : kSnameOffset), o.area == 1 ? 128 : 64);
            }
            const char *name = optionName(o.code);
            std::string text = "Option: (" + std::to_string(o.code) + ") " + (name ? name : "Unknown");
            if (o.code != 255) {
                const std::string value = decodeOption(o.code, data + o.offset + 2, o.length - 2);
                if (!value.empty()) text += ": " + value;
            }
            l.add(text, p + o.offset, o.length);
        }
    }
}
