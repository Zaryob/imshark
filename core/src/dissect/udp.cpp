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

    auto rawUdp = [&] {
        pack.protocol = "UDP";
        pack.info = std::to_string(srcPort) + " -> " + std::to_string(dstPort) +
                    " Len=" + std::to_string(udpLen - sizeof(network::UDPHeader));
    };
    if (pack.protocol == "TFTP") {
        dissectTftp(ctx, payload, payloadLen);
    } else if (const Dissector *app = ctx.registry.findUdpPort(srcPort, dstPort)) {
        (*app)(ctx, payload, payloadLen);
        if (pack.protocol.empty()) rawUdp();   // the port's dissector declined: the content is not its protocol (DTLS ports)
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
        rawUdp();
    }
}

void dissect::dissectUdpLite(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    network::UDPHeader hdr;
    if (!readStruct(data, length, 0, hdr)) {
        ctx.markMalformed("UDP-Lite header truncated");
        pack.protocol = "UDP-Lite";
        return;
    }

    const uint16_t srcPort = network::ntoh16(hdr.src_port);
    const uint16_t dstPort = network::ntoh16(hdr.dest_port);
    pack.src_port = srcPort;
    pack.dst_port = dstPort;

    // In UDP-Lite (RFC 3828), the length field is replaced by Checksum Coverage (cov)
    // 0 = full packet covered (same as cov == length)
    // 1..7 = invalid (must be >= 8 or 0)
    const uint16_t cov = network::ntoh16(hdr.len);
    pack.length = static_cast<uint32_t>(length);

    if (cov > 0 && cov < 8) {
        pack.protocol = "UDP-Lite";
        ctx.markMalformed("illegal UDP-Lite checksum coverage");
        return;
    }

    const size_t neededCov = (cov == 0) ? length : std::min<size_t>(cov, length);
    const ChecksumResult sum = checkTransport(ctx, 136, data, length, neededCov, 6);
    setTransportChecksumState(pack, sum.state);

    const size_t o = ctx.offsetOf(data);
    const char *payload = data + sizeof(network::UDPHeader);
    const size_t payloadLen = length > sizeof(network::UDPHeader) ? length - sizeof(network::UDPHeader) : 0;
    if (payloadLen > 0) {
        pack.payload_offset = static_cast<uint32_t>(ctx.offsetOf(payload));
        pack.payload_length = static_cast<uint32_t>(payloadLen);
    }

    pack.protocol = "UDP-Lite";
    pack.info = std::to_string(srcPort) + " -> " + std::to_string(dstPort) +
                " Cov=" + (cov == 0 ? "all" : std::to_string(cov)) +
                " Len=" + std::to_string(payloadLen);

    if (ctx.wantFields()) {
        Field &l = ctx.addLayer("Lightweight User Datagram Protocol, Src Port: " + std::to_string(srcPort) + ", Dst Port: " + std::to_string(dstPort),
                                o, length);
        l.add("Source Port: " + std::to_string(srcPort), o, 2);
        l.add("Destination Port: " + std::to_string(dstPort), o + 2, 2);
        l.add("Checksum Coverage: " + (cov == 0 ? std::string("0 (covers all)") : std::to_string(cov)), o + 4, 2);
        Field &csum = l.add("Checksum: " + hexString(network::ntoh16(hdr.checksum), 4) + " [" + checksumStateText(sum.state) + "]", o + 6, 2);
        csum.add(std::string("[Checksum Status: ") + checksumStateText(sum.state) + "]", o + 6, 2);
        if (sum.state == kChecksumBad) csum.add("[Expected checksum: " + hexString(sum.expected, 4) + "]", o + 6, 2);
        if (payloadLen > 0) l.add("UDP-Lite payload (" + std::to_string(payloadLen) + " bytes)", o + 8, payloadLen);
    }

    // Try payload sub-dissectors if entire packet was captured
    if (const Dissector *app = ctx.registry.findUdpPort(srcPort, dstPort)) {
        (*app)(ctx, payload, payloadLen);
    }
}

