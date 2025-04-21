#include "protocols.h"

#include "registry.h"
#include "util.h"

#include <network/l4_transport/udp_header.h>

using packet::Field;

void dissect::dissectUdp(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    network::UDPHeader udpHeader;
    if (!readStruct(data, length, 0, udpHeader)) {
        ctx.markMalformed("UDP header truncated");
        pack.protocol = "UDP";
        return;
    }
    pack.l4_header = udpHeader;

    const uint16_t srcPort = ntohs(udpHeader.src_port);
    const uint16_t dstPort = ntohs(udpHeader.dest_port);
    const size_t udpLen = ntohs(udpHeader.len);
    pack.length = udpLen;
    if (udpLen < sizeof(network::UDPHeader)) {
        pack.protocol = "UDP";
        ctx.markMalformed("invalid UDP length");
        return;
    }

    const size_t o = ctx.offsetOf(data);
    const char *payload = data + sizeof(network::UDPHeader);
    const size_t payloadLen = std::min(udpLen, length) - sizeof(network::UDPHeader);

    Field &l = ctx.addLayer("User Datagram Protocol, Src Port: " + std::to_string(srcPort) + ", Dst Port: " + std::to_string(dstPort),
                            o, sizeof(network::UDPHeader) + payloadLen);
    l.add("Source Port: " + std::to_string(srcPort), o, 2);
    l.add("Destination Port: " + std::to_string(dstPort), o + 2, 2);
    l.add("Length: " + std::to_string(udpLen), o + 4, 2);
    l.add("Checksum: " + hexString(ntohs(udpHeader.checksum), 4), o + 6, 2);
    if (payloadLen > 0) l.add("UDP payload (" + std::to_string(payloadLen) + " bytes)", o + 8, payloadLen);

    if (const Dissector *app = ctx.registry.findUdpPort(srcPort, dstPort)) {
        (*app)(ctx, payload, payloadLen);
    } else {
        pack.protocol = "UDP";
        pack.info = std::to_string(srcPort) + " -> " + std::to_string(dstPort) +
                    " Len=" + std::to_string(udpLen - sizeof(network::UDPHeader));
    }
}
