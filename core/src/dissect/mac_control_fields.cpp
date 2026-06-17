// Filter fields of MAC Control, PAUSE and PFC (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerMacControlFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"mac_control", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p)) o.addU(1); }, "Ethernet MAC Control"},
            {"mac_control.opcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p)) o.addU(p.app_code); }, "MAC Control opcode (0x0001 PAUSE, 0x0101 PFC)"},
            {"pause", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0001) o.addU(1); }, "Ethernet PAUSE frame"},
            {"pause.time", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0001) o.addU(p.app_type); }, "PAUSE time (units of 512 bit times)"},
            {"pfc", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0101) o.addU(1); }, "Priority Flow Control frame"},
            {"pfc.class_enable", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0101) o.addU(p.app_type); }, "PFC Class Enable Vector"},
        });
    }
} // namespace filter
