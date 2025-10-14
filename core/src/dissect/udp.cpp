#include "protocols.h"

#include "registry.h"
#include "util.h"
#include "checksum.h"

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

    const uint16_t srcPort = network::ntoh16(udpHeader.src_port);
    const uint16_t dstPort = network::ntoh16(udpHeader.dest_port);
    pack.src_port = srcPort;
    pack.dst_port = dstPort;
    const size_t udpLen = network::ntoh16(udpHeader.len);
    pack.length = udpLen;
    if (udpLen < sizeof(network::UDPHeader)) {
        pack.protocol = "UDP";
        ctx.markMalformed("invalid UDP length");
        return;
    }

    const ChecksumResult sum = checkTransport(ctx, 17, data, length, udpLen, 6);
    setTransportChecksumState(pack, sum.state);
    const size_t o = ctx.offsetOf(data);
    const char *payload = data + sizeof(network::UDPHeader);
    const size_t payloadLen = std::min(udpLen, length) - sizeof(network::UDPHeader);
    if (payloadLen > 0) {
        pack.payload_offset = static_cast<uint32_t>(ctx.offsetOf(payload));
        pack.payload_length = static_cast<uint32_t>(payloadLen);
    }

    if (ctx.wantFields()) {
        Field &l = ctx.addLayer("User Datagram Protocol, Src Port: " + std::to_string(srcPort) + ", Dst Port: " + std::to_string(dstPort),
                                o, sizeof(network::UDPHeader) + payloadLen);
        l.add("Source Port: " + std::to_string(srcPort), o, 2);
        l.add("Destination Port: " + std::to_string(dstPort), o + 2, 2);
        l.add("Length: " + std::to_string(udpLen), o + 4, 2);
        Field &csum = l.add("Checksum: " + hexString(network::ntoh16(udpHeader.checksum), 4) + " [" + checksumStateText(sum.state) + "]", o + 6, 2);
        csum.add(std::string("[Checksum Status: ") + checksumStateText(sum.state) + "]", o + 6, 2);
        if (sum.state == kChecksumBad) csum.add("[Expected checksum: " + hexString(sum.expected, 4) + "]", o + 6, 2);
        if (sum.state == kChecksumNone) csum.add("[Zero checksum: not used (IPv4 allows this)]", o + 6, 2);
        if (payloadLen > 0) l.add("UDP payload (" + std::to_string(payloadLen) + " bytes)", o + 8, payloadLen);
    }

    if (pack.protocol == "TFTP") {
        dissectTftp(ctx, payload, payloadLen);
    } else if (const Dissector *app = ctx.registry.findUdpPort(srcPort, dstPort)) {
        (*app)(ctx, payload, payloadLen);
    } else if (payloadLen > 0 && [&] {
        if (ctx.sessions && ctx.sessions->matchOrUpdateTftpSession(srcPort, dstPort)) {
            dissectTftp(ctx, payload, payloadLen);
            return true;
        }
        for (const auto &heuristic: ctx.registry.udpHeuristics()) if (heuristic(ctx, payload, payloadLen)) return true;
        return false;
    }()) {
        // recognised by its content on a port nobody registered
    } else {
        pack.protocol = "UDP";
        pack.info = std::to_string(srcPort) + " -> " + std::to_string(dstPort) +
                    " Len=" + std::to_string(udpLen - sizeof(network::UDPHeader));
    }
}
