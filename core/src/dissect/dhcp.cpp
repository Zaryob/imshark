#include "protocols.h"

#include "util.h"

#include <network/l7_application/dhcp_header.h>
#include <network/utils.h>

using packet::Field;

void dissect::dissectDhcp(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "DHCP";

    network::DHCPHeader dhcp;
    if (!readStruct(data, length, 0, dhcp)) {
        ctx.markMalformed("DHCP message too short");
        return;
    }
    pack.l7_header = dhcp;

    std::ostringstream oss;
    oss << "DHCP ";
    if (dhcp.op == 1) oss << "Request";
    else if (dhcp.op == 2) oss << "Reply";

    oss << ", XID: 0x" << std::hex << network::ntoh32(dhcp.xid) << std::dec;
    oss << ", Client IP: " << ip4(dhcp.cip_addr);
    oss << ", Your IP: " << ip4(dhcp.yip_addr);
    oss << ", Server IP: " << ip4(dhcp.sip_addr);
    oss << ", Gateway IP: " << ip4(dhcp.gip_addr);
    oss << ", Client MAC: ";
    for (int i = 0; i < 6; ++i) {
        oss << std::hex << std::setw(2) << std::setfill('0') << (int) dhcp.ch_addr[i];
        if (i != 5) oss << ":";
    }
    pack.info = oss.str();

    const size_t p = ctx.offsetOf(data);
    Field &l = ctx.addLayer("Dynamic Host Configuration Protocol", p, length);
    l.add("Message type: " + std::string(dhcp.op == 1 ? "Boot Request (1)" : dhcp.op == 2 ? "Boot Reply (2)" : std::to_string(dhcp.op)), p, 1);
    l.add("Hardware type: " + hexString(dhcp.hw_type, 2), p + 1, 1);
    l.add("Hardware address length: " + std::to_string(dhcp.hw_len), p + 2, 1);
    l.add("Hops: " + std::to_string(dhcp.hops), p + 3, 1);
    l.add("Transaction ID: " + hexString(network::ntoh32(dhcp.xid), 8), p + 4, 4);
    l.add("Seconds elapsed: " + std::to_string(network::ntoh16(dhcp.secs)), p + 8, 2);
    l.add("Flags: " + hexString(network::ntoh16(dhcp.flags), 4), p + 10, 2);
    l.add("Client IP address: " + ip4(dhcp.cip_addr), p + 12, 4);
    l.add("Your (client) IP address: " + ip4(dhcp.yip_addr), p + 16, 4);
    l.add("Next server IP address: " + ip4(dhcp.sip_addr), p + 20, 4);
    l.add("Relay agent IP address: " + ip4(dhcp.gip_addr), p + 24, 4);
    l.add("Client MAC address: " + network::getMACAddressString(dhcp.ch_addr), p + 28, 6);
}
