// Filter fields of TCP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerTcpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"tcp", FieldType::Boolean, proto<hasTcp>, "TCP"},
            {"tcp.srcport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.src_port); }, "TCP source port"},
            {"tcp.dstport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.dst_port); }, "TCP destination port"},
            {"tcp.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) { o.addU(p.src_port); o.addU(p.dst_port); } }, "TCP source or destination port"},
            {"tcp.flags", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.tcp_flags); }, "TCP flag byte"},
            {"tcp.flags.fin", FieldType::Boolean, tcpFlag<0x01>, "TCP FIN flag"},
            {"tcp.flags.syn", FieldType::Boolean, tcpFlag<0x02>, "TCP SYN flag"},
            {"tcp.flags.rst", FieldType::Boolean, tcpFlag<0x04>, "TCP RST flag"},
            {"tcp.flags.push", FieldType::Boolean, tcpFlag<0x08>, "TCP PSH flag"},
            {"tcp.flags.ack", FieldType::Boolean, tcpFlag<0x10>, "TCP ACK flag"},
            {"tcp.flags.urg", FieldType::Boolean, tcpFlag<0x20>, "TCP URG flag"},
            {"tcp.flags.ece", FieldType::Boolean, tcpFlag<0x40>, "TCP ECE flag"},
            {"tcp.flags.cwr", FieldType::Boolean, tcpFlag<0x80>, "TCP CWR flag"},
            {"tcp.len", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.tcp_len); }, "TCP payload length"},
            {"tcp.seq", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p) && p.tcp_relative_seq >= 0) o.addU(static_cast<uint64_t>(p.tcp_relative_seq)); }, "TCP relative sequence number"},
            {"tcp.ack", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p) && p.tcp_relative_ack >= 0) o.addU(static_cast<uint64_t>(p.tcp_relative_ack)); }, "TCP relative acknowledgment number"},
            {"tcp.analysis.flags", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.tcp_analysis != 0); }, "Any TCP analysis note (retransmission, dup ACK, ...)"},
            {"tcp.analysis.retransmission", FieldType::Boolean, tcpAnalysis<1>, "TCP segment repeats data that was already seen"},
            {"tcp.analysis.out_of_order", FieldType::Boolean, tcpAnalysis<2>, "TCP segment arrived out of order"},
            {"tcp.analysis.lost_segment", FieldType::Boolean, tcpAnalysis<4>, "A previous TCP segment was not captured"},
            {"tcp.analysis.duplicate_ack", FieldType::Boolean, tcpAnalysis<8>, "Duplicate acknowledgment"},
            {"tcp.analysis.duplicate_ack_num", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p) && (p.tcp_analysis & 8)) o.addU(p.tcp_dup_ack); }, "Number of the duplicate ACK (#n)"},
            {"tcp.analysis.zero_window", FieldType::Boolean, tcpAnalysis<16>, "Zero receive window advertised"},
            {"tcp.analysis.keep_alive", FieldType::Boolean, tcpAnalysis<32>, "TCP keep-alive"},
            {"tcp.analysis.window_update", FieldType::Boolean, tcpAnalysis<64>, "TCP window update"},
            {"tcp.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 6 && p.src_port != 0) o.addU(checksumStatusNumber(dissect::transportChecksumState(p))); }, "TCP checksum: 0 = bad, 1 = good, 2 = unverified (offload or truncated)"},
            {"tcp.segment", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.tcp_pdu_state == 1 || p.tcp_pdu_state == 4); }, "Segment of a TCP message that is reassembled in a later packet"},
            {"tcp.reassembled", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p)) o.addU(p.tcp_pdu_state == 2); }, "Packet that completes a reassembled TCP message"},
            {"tcp.reassembled_in", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p) && (p.tcp_pdu_state == 1 || p.tcp_pdu_state == 4) && p.tcp_reassembled_in) o.addU(p.tcp_reassembled_in); }, "Number of the packet that completes the message this segment belongs to"},
            {"tcp.reassembled.length", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasTcp(p) && p.tcp_pdu_state == 2) o.addU(p.tcp_pdu_len); }, "Length of the reassembled TCP message"},
        });
    }
} // namespace filter
