// Filter fields of DNS and mDNS (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerDnsFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"dns.qry.name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "DNS") || isProtocol(p, "MDNS")) && !p.app_text.empty()) o.addS(p.app_text); }, "Name of the first DNS question"},
            {"dns.qry.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "DNS") || isProtocol(p, "MDNS")) && !p.app_text.empty()) o.addU(p.app_type); }, "Type of the first DNS question (1 = A, 28 = AAAA, 15 = MX ...)"},
            {"dns.flags.response", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS") || isProtocol(p, "MDNS")) o.addU((p.app_flags & 0x8000) != 0); }, "DNS message is a response"},
            {"dns.flags.rcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS") || isProtocol(p, "MDNS")) o.addU(p.app_code); }, "DNS reply code (0 = no error, 3 = NXDOMAIN ...)"},
            {"dns.flags.truncated", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS") || isProtocol(p, "MDNS")) o.addU((p.app_flags & 0x0200) != 0); }, "DNS message is truncated"},
            {"mdns", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "MDNS")) o.addU(1); }, "Multicast DNS"},
            {"dns", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DNS")) o.addU(1); }, "DNS"},
        });
    }
} // namespace filter
