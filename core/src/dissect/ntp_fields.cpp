// Filter fields of NTP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerNtpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"ntp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(1); }, "NTP"},
            {"ntp.mode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(p.app_type); }, "NTP mode (3 = client, 4 = server)"},
            {"ntp.stratum", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP") && p.app_type >= 1 && p.app_type <= 5) o.addU(p.app_code); }, "NTP stratum"},
            {"ntp.ctrl.opcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP") && p.app_type == 6) o.addU(p.app_code); }, "Opcode of an NTP control message (2 = read variables)"},
            {"ntp.priv.reqcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP") && p.app_type == 7) o.addU(p.app_code); }, "Request code of an NTP private (mode 7) message"},
            {"ntp.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "NTP")) o.addU(p.app_flags); }, "NTP version"},
        });
    }
} // namespace filter
