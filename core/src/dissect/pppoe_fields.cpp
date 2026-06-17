// Filter fields of PPPoE (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerPppoeFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"pppoe", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p)) o.addU(1); }, "PPP-over-Ethernet (Discovery or Session)"},
            {"pppoed", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.ether_type == 0x8863 || isProtocol(p, "PPPoED")) o.addU(1); }, "PPPoE Discovery Stage"},
            {"pppoes", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.ether_type == 0x8864 || isProtocol(p, "PPPoES") || (p.link_type == 1 && isPpp(p))) o.addU(1); }, "PPPoE Session Stage"},
            {"pppoe.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p)) o.addU(p.pppoe_code); }, "PPPoE Code (0x00 = Session, 0x09 = PADI, 0x07 = PADO, 0x19 = PADR, 0x65 = PADS, 0xa7 = PADT)"},
            {"pppoe.session_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p)) o.addU(p.pppoe_session_id); }, "PPPoE Session ID"},
            {"pppoe.service_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p) && !p.app_text.empty()) o.addS(p.app_text); }, "PPPoE Service-Name tag"},
            {"pppoe.ac_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "PPPoE Access Concentrator (AC) Name tag"},
        });
    }
} // namespace filter
