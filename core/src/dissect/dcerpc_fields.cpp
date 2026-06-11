// Filter fields of DCE/RPC (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerDcerpcFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"dcerpc", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "DCERPC"; }>, "DCE/RPC"},
            {"dcerpc.pkt_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DCERPC") o.addU(p.app_type); }, "DCE/RPC PDU type (0 Request, 2 Response, 3 Fault, 11 Bind, 12 Bind_ack)"},
            {"dcerpc.opnum", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DCERPC" && (p.app_flags & 1)) o.addU(p.app_code); }, "DCE/RPC operation number of a Request"},
            {"dcerpc.cn_call_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DCERPC") o.addU(p.app_stream); }, "DCE/RPC call id"},
            {"dcerpc.if_uuid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DCERPC" && !p.app_text.empty()) o.addS(p.app_text); }, "DCE/RPC interface UUID of the first presentation context of a Bind / Alter_context"},
        });
    }
} // namespace filter
