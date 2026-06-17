// Filter fields of LACP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerSlowProtocolsFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"lacp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(1); }, "Link Aggregation Control Protocol"},
            {"lacp.actor.system", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p) && !p.app_text.empty()) o.addS(p.app_text); }, "LACP Actor System ID (MAC)"},
            {"lacp.partner.system", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "LACP Partner System ID (MAC)"},
            {"lacp.actor.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(p.app_type); }, "LACP Actor Port number"},
            {"lacp.partner.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(p.app_code); }, "LACP Partner Port number"},
            {"lacp.actor.state", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(p.app_flags & 0xFF); }, "LACP Actor State byte"},
            {"lacp.partner.state", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags >> 8) & 0xFF); }, "LACP Partner State byte"},
            {"lacp.actor.state.activity", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x01) ? 1 : 0); }, "LACP Actor Activity bit"},
            {"lacp.actor.state.synchronization", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x08) ? 1 : 0); }, "LACP Actor Synchronization bit"},
            {"lacp.actor.state.collecting", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x10) ? 1 : 0); }, "LACP Actor Collecting bit"},
            {"lacp.actor.state.distributing", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x20) ? 1 : 0); }, "LACP Actor Distributing bit"},
        });
    }
} // namespace filter
