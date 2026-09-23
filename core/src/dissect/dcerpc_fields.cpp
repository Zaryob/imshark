// Filter fields of DCE/RPC (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo (dcerpc.h).
#include <dissect/dcerpc.h>
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    namespace {
        using dissect::kDceAuthMask;
        using dissect::kDceAuthShift;
        using dissect::kDceFlagConnectionless;
        using dissect::kDceFlagFragment;
        using dissect::kDceFlagOpnum;
        using dissect::kDceFlagReassembled;
        using dissect::kDceFlagSealed;

        bool isDce(const packet::PacketInfo &p) { return p.protocol == "DCERPC"; }
    } // namespace

    void registerDcerpcFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"dcerpc", FieldType::Boolean, proto<[](const PacketInfo &p) { return isDce(p); }>, "DCE/RPC"},
            {"dcerpc.pkt_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isDce(p)) o.addU(p.app_type); }, "DCE/RPC PDU type (0 Request, 2 Response, 3 Fault, 11 Bind, 12 Bind_ack)"},
            {"dcerpc.opnum", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isDce(p) && (p.app_flags & kDceFlagOpnum)) o.addU(p.app_code); }, "DCE/RPC operation number of a Request"},
            {"dcerpc.cn_call_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isDce(p) && !(p.app_flags & kDceFlagConnectionless)) o.addU(p.app_stream); }, "DCE/RPC call id of a connection-oriented PDU"},
            {"dcerpc.if_uuid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isDce(p) && !p.app_text.empty()) o.addS(p.app_text); }, "DCE/RPC interface UUID: of the first presentation context of a Bind / Alter_context, of the context a Request / Response used"},
            {"dcerpc.auth_level", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isDce(p) && (p.app_flags & kDceAuthMask)) o.addU((p.app_flags & kDceAuthMask) >> kDceAuthShift); }, "DCE/RPC authentication level of the PDU's verifier (1 none ... 5 packet integrity, 6 packet privacy)"},
            {"dcerpc.auth_service", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isDce(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "DCE/RPC authentication service of the PDU's verifier (NTLMSSP, Kerberos, SPNEGO, ...)"},
            {"dcerpc.sealed", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isDce(p)) o.addU((p.app_flags & kDceFlagSealed) != 0); }, "DCE/RPC stub data is sealed (packet privacy): labelled, not interpreted"},
            {"dcerpc.fragment", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isDce(p)) o.addU((p.app_flags & kDceFlagFragment) != 0); }, "DCE/RPC PDU is one fragment of a call split over several PDUs"},
            {"dcerpc.reassembled", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isDce(p)) o.addU((p.app_flags & kDceFlagReassembled) != 0); }, "DCE/RPC PDU completes a call that was split into fragments"},
        });
    }
} // namespace filter
