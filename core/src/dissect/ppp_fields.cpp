// Filter fields of PPP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerPppFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"ppp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isPpp(p)) o.addU(1); }, "Point-to-Point Protocol"},
            {"ppp.protocol", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (!isMpls(p) && p.ppp_protocol != 0) o.addU(p.ppp_protocol); }, "PPP Protocol ID (0x0021 = IPv4, 0x0057 = IPv6, 0xc021 = LCP, 0x8021 = IPCP)"},
            {"ppp.lcp.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (!isMpls(p) && (p.ppp_protocol == 0xc021 || isProtocol(p, "LCP"))) o.addU(p.app_type); }, "LCP Code (1 = Config-Req, 2 = Config-Ack, etc.)"},
            {"ppp.ipcp.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (!isMpls(p) && (p.ppp_protocol == 0x8021 || isProtocol(p, "IPCP"))) o.addU(p.app_type); }, "IPCP Code"},
        });
    }
} // namespace filter
