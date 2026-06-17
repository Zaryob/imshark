// Filter fields of LLDP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerLldpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"lldp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p)) o.addU(1); }, "Link Layer Discovery Protocol"},
            {"lldp.chassis_id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p) && !p.app_text.empty()) o.addS(p.app_text); }, "LLDP Chassis ID"},
            {"lldp.port_id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "LLDP Port ID"},
            {"lldp.ttl", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p)) o.addU(p.app_code); }, "LLDP Time To Live in seconds"},
            {"lldp.capabilities", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p)) o.addU(p.app_flags); }, "LLDP System Capabilities (enabled bits)"},
        });
    }
} // namespace filter
