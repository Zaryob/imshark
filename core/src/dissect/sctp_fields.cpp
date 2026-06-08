// Filter fields of SCTP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerSctpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"sctp", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.ip_protocol == 132 || p.protocol == "SCTP"; }>, "Stream Control Transmission Protocol"},
            {"sctp.srcport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 132 || p.protocol == "SCTP") o.addU(p.src_port); }, "SCTP source port"},
            {"sctp.dstport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 132 || p.protocol == "SCTP") o.addU(p.dst_port); }, "SCTP destination port"},
            {"sctp.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 132 || p.protocol == "SCTP") { o.addU(p.src_port); o.addU(p.dst_port); } }, "SCTP source or destination port"},
            {"sctp.vtag", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 132 || p.protocol == "SCTP") o.addU(p.tcp_pdu_start); }, "SCTP Verification Tag"},
            {"sctp.chunk_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if ((p.ip_protocol == 132 || p.protocol == "SCTP") && p.app_type != 0xFF) o.addU(p.app_type); }, "SCTP Chunk Type (of the first chunk)"},
        });
    }
} // namespace filter
