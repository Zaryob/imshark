#include "protocols.h"

#include "registry.h"
#include "util.h"

#include <network/l4_transport/tcp_header.h>

using packet::Field;

namespace {
    std::string tcpFlagNames(uint8_t flags) {
        static const std::pair<uint8_t, const char *> names[] = {
            {0x80, "CWR"}, {0x40, "ECE"}, {0x20, "URG"}, {0x10, "ACK"}, {0x08, "PSH"}, {0x04, "RST"}, {0x02, "SYN"}, {0x01, "FIN"}};
        std::string out;
        for (const auto &[bit, name]: names) {
            if (flags & bit) out += (out.empty() ? "" : ", ") + std::string(name);
        }
        return out;
    }

    // Renders TCP options (MSS, WS, SACK, TS, ...) as " MSS=1460 WS=7 ..."
    std::string describeTcpOptions(const char *p, size_t len) {
        using namespace dissect;
        std::string out;
        size_t i = 0;
        while (i < len) {
            const uint8_t kind = static_cast<uint8_t>(p[i]);
            if (kind == 0) break;                  // end of option list
            if (kind == 1) { ++i; continue; }      // NOP padding
            if (i + 1 >= len) break;
            const size_t optLen = static_cast<uint8_t>(p[i + 1]);
            if (optLen < 2 || optLen > len - i) break; // malformed option, stop decoding
            switch (kind) {
                case 2: if (optLen == 4) out += " MSS=" + std::to_string(be16(p + i + 2)); break;
                case 3: if (optLen == 3) out += " WS=" + std::to_string(static_cast<uint8_t>(p[i + 2])); break;
                case 4: out += " SACK_PERM"; break;
                case 5: out += " SACK"; break;
                case 8:
                    if (optLen == 10)
                        out += " TSval=" + std::to_string(be32(p + i + 2)) + " TSecr=" + std::to_string(be32(p + i + 6));
                    break;
                default: break;
            }
            i += optLen;
        }
        return out;
    }
} // namespace

void dissect::dissectTcp(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    network::TCPHeader tcpHeader;
    if (!readStruct(data, length, 0, tcpHeader)) {
        ctx.markMalformed("TCP header truncated");
        pack.protocol = "TCP";
        return;
    }
    const size_t headerLen = static_cast<size_t>((tcpHeader.data_offset >> 4) & 0x0F) * 4;
    pack.protocol = "TCP";
    // recorded before any validation, so that even packets with a broken header can be filtered by port
    pack.src_port = network::ntoh16(tcpHeader.src_port);
    pack.dst_port = network::ntoh16(tcpHeader.dest_port);
    pack.tcp_flags = tcpHeader.flags;
    if (headerLen < sizeof(network::TCPHeader) || headerLen > length) {
        ctx.markMalformed("invalid TCP data offset");
        return;
    }

    const size_t o = ctx.offsetOf(data);
    pack.length = pack.length >= headerLen ? pack.length - headerLen : 0;
    const char *payload = data + headerLen;
    const size_t payloadLen = std::min<size_t>(pack.length, length - headerLen);

    int64_t seq = -1, ack = -1;
    if (ctx.mode == ParseMode::Replay) {
        seq = pack.tcp_relative_seq; // the connection table only exists while the capture is loaded
        ack = pack.tcp_relative_ack;
    } else {
        const network::TcpAnalysis analysis = ctx.tcp.trackAndAnalyze(seq, ack, pack.source, pack.destination, tcpHeader,
                                                                      static_cast<uint32_t>(payloadLen));
        pack.tcp_relative_seq = seq;
        pack.tcp_relative_ack = ack;
        pack.tcp_analysis = analysis.flags;
        pack.tcp_dup_ack = analysis.duplicateAckCount;
    }

    const uint16_t window = network::ntoh16(tcpHeader.window);
    const uint16_t srcPort = network::ntoh16(tcpHeader.src_port);
    const uint16_t dstPort = network::ntoh16(tcpHeader.dest_port);

    const std::string flagNames = tcpFlagNames(tcpHeader.flags);
    const std::string options = describeTcpOptions(data + sizeof(network::TCPHeader), headerLen - sizeof(network::TCPHeader));
    // analysis notes go in front of the usual summary, like Wireshark's "[TCP Retransmission] ..."
    std::string notes;
    if (pack.tcp_analysis & network::kTcpLostSegment) notes += "[TCP Previous segment not captured] ";
    if (pack.tcp_analysis & network::kTcpRetransmission) notes += "[TCP Retransmission] ";
    if (pack.tcp_analysis & network::kTcpOutOfOrder) notes += "[TCP Out-Of-Order] ";
    if (pack.tcp_analysis & network::kTcpDuplicateAck) notes += "[TCP Dup ACK #" + std::to_string(pack.tcp_dup_ack) + "] ";
    if (pack.tcp_analysis & network::kTcpZeroWindow) notes += "[TCP ZeroWindow] ";
    if (pack.tcp_analysis & network::kTcpKeepAlive) notes += "[TCP Keep-Alive] ";
    if (pack.tcp_analysis & network::kTcpWindowUpdate) notes += "[TCP Window Update] ";

    pack.info = notes + std::to_string(srcPort) + " -> " + std::to_string(dstPort) + " [" + flagNames + "] " +
                (seq >= 0 ? (" Seq=" + std::to_string(seq)) : "") +
                (ack >= 0 ? (" Ack=" + std::to_string(ack)) : "") +
                (window > 0 ? (" Win=" + std::to_string(window)) : "") + options;

    if (ctx.wantFields()) {
        Field &l = ctx.addLayer("Transmission Control Protocol, Src Port: " + std::to_string(srcPort) + ", Dst Port: " +
                                    std::to_string(dstPort) + (seq >= 0 ? ", Seq: " + std::to_string(seq) : "") +
                                    ", Len: " + std::to_string(payloadLen),
                                o, headerLen + payloadLen);
        l.add("Source Port: " + std::to_string(srcPort), o, 2);
        l.add("Destination Port: " + std::to_string(dstPort), o + 2, 2);
        l.add("Sequence Number: " + (seq >= 0 ? std::to_string(seq) + " (relative), " : std::string()) +
                  std::to_string(network::ntoh32(tcpHeader.seq_num)) + " (raw)", o + 4, 4);
        l.add("Acknowledgment Number: " + (ack >= 0 ? std::to_string(ack) + " (relative), " : std::string()) +
                  std::to_string(network::ntoh32(tcpHeader.ack_num)) + " (raw)", o + 8, 4);
        l.add("Header Length: " + std::to_string(headerLen) + " bytes", o + 12, 1);
        Field &f = l.add("Flags: " + hexString(tcpHeader.flags, 3) + " (" + flagNames + ")", o + 13, 1);
        static const std::pair<uint8_t, const char *> bits[] = {
            {0x80, "Congestion Window Reduced"}, {0x40, "ECN-Echo"}, {0x20, "Urgent"}, {0x10, "Acknowledgment"},
            {0x08, "Push"}, {0x04, "Reset"}, {0x02, "Syn"}, {0x01, "Fin"}};
        for (const auto &[bit, name]: bits) {
            f.add(std::string(name) + ": " + ((tcpHeader.flags & bit) ? "Set" : "Not set"), o + 13, 1);
        }
        l.add("Window: " + std::to_string(window), o + 14, 2);
        l.add("Checksum: " + hexString(network::ntoh16(tcpHeader.checksum), 4), o + 16, 2);
        l.add("Urgent Pointer: " + std::to_string(network::ntoh16(tcpHeader.urgent_pointer)), o + 18, 2);
        if (headerLen > sizeof(network::TCPHeader)) {
            l.add("Options:" + (options.empty() ? std::string(" (no decoded options)") : options), o + 20,
                  headerLen - sizeof(network::TCPHeader));
        }
        if (pack.tcp_analysis != 0) {
            Field &a = l.add("[SEQ/ACK analysis]");
            auto note = [&](uint16_t flag, const char *text) { if (pack.tcp_analysis & flag) a.add(text); };
            note(network::kTcpLostSegment, "A segment before this one was not captured (sequence number jumped ahead)");
            note(network::kTcpRetransmission, "This frame is a (suspected) retransmission");
            note(network::kTcpOutOfOrder, "This frame is a (suspected) out-of-order segment");
            if (pack.tcp_analysis & network::kTcpDuplicateAck) a.add("This is a TCP duplicate ack (#" + std::to_string(pack.tcp_dup_ack) + ")");
            note(network::kTcpZeroWindow, "The receive window is 0: the sender cannot receive more data");
            note(network::kTcpKeepAlive, "This is a TCP keep-alive segment");
            note(network::kTcpWindowUpdate, "This is a TCP window update");
        }
        if (payloadLen > 0) l.add("TCP payload (" + std::to_string(payloadLen) + " bytes)", o + headerLen, payloadLen);
    }

    if (const Dissector *app = ctx.registry.findTcpPort(srcPort, dstPort)) (*app)(ctx, payload, payloadLen);
}
