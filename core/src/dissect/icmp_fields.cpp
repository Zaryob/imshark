// Filter fields of ICMP and ICMPv6 (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerIcmpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"icmp", FieldType::Boolean, proto<[](const PacketInfo &p) { return ipv4(p) && p.ip_protocol == 1; }>, "ICMP"},
            {"icmpv6", FieldType::Boolean, proto<[](const PacketInfo &p) { return ipv6(p) && p.ip_protocol == 58; }>, "ICMPv6"},
            {"icmp.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 1 && p.ip_frag != 1) o.addU(checksumStatusNumber(dissect::transportChecksumState(p))); }, "ICMP checksum: 0 = bad, 1 = good, 2 = unverified"},
            {"icmpv6.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_protocol == 58 && p.ip_frag != 1) o.addU(checksumStatusNumber(dissect::transportChecksumState(p))); }, "ICMPv6 checksum: 0 = bad, 1 = good, 2 = unverified"},
            {"icmp.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p) && p.ip_protocol == 1 && p.protocol == "ICMP") o.addU(p.app_type); }, "ICMP message type"},
            {"icmp.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p) && p.ip_protocol == 1 && p.protocol == "ICMP") o.addU(p.app_code); }, "ICMP message code"},
            {"icmpv6.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p) && p.protocol == "ICMPv6") o.addU(p.app_type); }, "ICMPv6 message type"},
            {"icmpv6.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p) && p.protocol == "ICMPv6") o.addU(p.app_code); }, "ICMPv6 message code"},
        });
    }
} // namespace filter
