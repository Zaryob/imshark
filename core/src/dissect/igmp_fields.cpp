// Filter fields of IGMP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerIgmpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"igmp", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "IGMP" || p.ip_protocol == 2; }>, "Internet Group Management Protocol"},
            {"igmp.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "IGMP" && p.app_type != 0) o.addU(p.app_type); }, "IGMP Message Type (0x11 Query, 0x12 v1 Report, 0x16 v2 Report, 0x17 Leave, 0x22 v3 Report)"},
            {"igmp.group", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "IGMP" && !p.app_text.empty()) o.addS(p.app_text); }, "IGMP Multicast Group Address"},
        });
    }
} // namespace filter
