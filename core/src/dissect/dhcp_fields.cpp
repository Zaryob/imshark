// Filter fields of DHCP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerDhcpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"dhcp.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DHCP") && p.app_type != 0) o.addU(p.app_type); }, "DHCP message type (1 = Discover, 2 = Offer, 3 = Request, 5 = ACK ...)"},
            {"dhcp.option.hostname", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DHCP") && !p.app_text.empty()) o.addS(p.app_text); }, "DHCP host name option"},
            {"dhcp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "DHCP")) o.addU(1); }, "DHCP"},
        });
    }
} // namespace filter
