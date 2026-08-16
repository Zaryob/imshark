// Filter fields of SCTP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <cstdlib>

#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    namespace {
        bool isSctp(const packet::PacketInfo &p) { return p.ip_protocol == 132 || p.protocol == "SCTP"; }
        // app_flags of an SCTP packet (dissectSctp): 1 DATA/I-DATA chunk, 2 I-DATA, 4 fragment, 8 completes a message here,
        // 16 unordered, 32 retransmission; app_code stream, tcp_pdu_len TSN, app_stream PPID, app_text2 SSN / MID (decimal)
        template<uint16_t Bit>
        void dataFlag(const packet::PacketInfo &p, const Context &, Values &o) { if (isSctp(p) && (p.app_flags & 1)) o.addU((p.app_flags & Bit) ? 1 : 0); }
    } // namespace

    void registerSctpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"sctp", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.ip_protocol == 132 || p.protocol == "SCTP"; }>, "Stream Control Transmission Protocol"},
            {"sctp.srcport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 132 || p.protocol == "SCTP") o.addU(p.src_port); }, "SCTP source port"},
            {"sctp.dstport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 132 || p.protocol == "SCTP") o.addU(p.dst_port); }, "SCTP destination port"},
            {"sctp.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 132 || p.protocol == "SCTP") { o.addU(p.src_port); o.addU(p.dst_port); } }, "SCTP source or destination port"},
            {"sctp.vtag", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 132 || p.protocol == "SCTP") o.addU(p.tcp_pdu_start); }, "SCTP Verification Tag"},
            {"sctp.chunk_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if ((p.ip_protocol == 132 || p.protocol == "SCTP") && p.app_type != 0xFF) o.addU(p.app_type); }, "SCTP Chunk Type (of the first chunk)"},
            {"sctp.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isSctp(p)) o.addU(checksumStatusNumber(dissect::transportChecksumState(p))); }, "SCTP CRC-32C: 0 = bad, 1 = good, 2 = unverified, 3 = not present"},
            {"sctp.data", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isSctp(p) && (p.app_flags & 1)) o.addU(1); }, "SCTP packet with a DATA or I-DATA chunk"},
            {"sctp.data.tsn", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isSctp(p) && (p.app_flags & 1)) o.addU(p.tcp_pdu_len); }, "TSN of the first DATA / I-DATA chunk"},
            {"sctp.data.sid", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isSctp(p) && (p.app_flags & 1)) o.addU(p.app_code); }, "Stream identifier of the first DATA / I-DATA chunk"},
            {"sctp.data.ssn", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isSctp(p) && (p.app_flags & 1) && !p.app_text2.empty()) o.addU(std::strtoull(p.app_text2.c_str(), nullptr, 10)); }, "Stream sequence number (DATA) or message identifier (I-DATA) of the first DATA / I-DATA chunk"},
            {"sctp.data.ppid", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isSctp(p) && (p.app_flags & 1)) o.addU(p.app_stream); }, "Payload protocol identifier of the first DATA / I-DATA chunk (of the whole message when it was reassembled)"},
            {"sctp.data.idata", FieldType::Boolean, dataFlag<2>, "The first data chunk is an I-DATA chunk"},
            {"sctp.data.fragment", FieldType::Boolean, dataFlag<4>, "The first data chunk carries only part of a user message"},
            {"sctp.data.unordered", FieldType::Boolean, dataFlag<16>, "The first data chunk has the U (unordered) flag"},
            {"sctp.data.retransmission", FieldType::Boolean, dataFlag<32>, "The first data chunk is a fragment seen before"},
            {"sctp.reassembled", FieldType::Boolean, dataFlag<8>, "This packet's first data chunk completed a user message (reassembled SCTP message)"},
        });
    }
} // namespace filter
