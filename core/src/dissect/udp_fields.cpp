// Filter fields of UDP and UDP-Lite (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerUdpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"udp", FieldType::Boolean, proto<hasUdp>, "UDP"},
            {"udplite", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.ip_protocol == 136 || p.protocol == "UDP-Lite"; }>, "Lightweight User Datagram Protocol"},
            {"udp.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 17 && p.src_port != 0) o.addU(checksumStatusNumber(dissect::transportChecksumState(p))); }, "UDP checksum: 0 = bad, 1 = good, 2 = unverified, 3 = not present (zero over IPv4)"},
            {"udp.srcport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasUdp(p)) o.addU(p.src_port); }, "UDP source port"},
            {"udp.dstport", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasUdp(p)) o.addU(p.dst_port); }, "UDP destination port"},
            {"udp.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasUdp(p)) { o.addU(p.src_port); o.addU(p.dst_port); } }, "UDP source or destination port"},
        });
    }
} // namespace filter
