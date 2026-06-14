// Filter fields of BGP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerBgpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"bgp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP")) o.addU(1); }, "BGP"},
            {"bgp.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP")) o.addU(p.app_type); }, "BGP message type (1 = OPEN, 2 = UPDATE, 3 = NOTIFICATION, 4 = KEEPALIVE, 5 = ROUTE-REFRESH)"},
            {"bgp.as", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP")) o.addU(p.tcp_pdu_start); }, "BGP Autonomous System number"},
            {"bgp.nlri", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP") && !p.app_text.empty()) o.addS(p.app_text); }, "BGP Network Layer Reachability Information prefix"},
            {"bgp.notification.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "BGP") && p.app_type == 3) o.addU(p.app_code); }, "BGP notification error code"},
        });
    }
} // namespace filter
