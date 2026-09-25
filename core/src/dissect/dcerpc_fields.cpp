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

        using dissect::kDcePipeOpnum;
        using dissect::kDcePipePdu;
        using dissect::kDcePipeTypeMask;
        using dissect::kDcePipeTypeShift;

        // a DCERPC packet (TCP, UDP), whose summary facts are in the kDce* bits of app_flags
        bool isDceProtocol(const packet::PacketInfo &p) { return p.protocol == "DCERPC"; }
        // an SMB2 packet whose first command carried a PDU in a named pipe: type, opnum and interface are kept in the free bits of app_flags
        bool isDcePipe(const packet::PacketInfo &p) { return p.protocol == "SMB2" && (p.app_flags & kDcePipePdu) != 0; }
        bool isDce(const packet::PacketInfo &p) { return isDceProtocol(p) || isDcePipe(p); }
        uint32_t pduType(const packet::PacketInfo &p) { return isDcePipe(p) ? (p.app_flags & kDcePipeTypeMask) >> kDcePipeTypeShift : p.app_type; }
    } // namespace

    void registerDcerpcFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"dcerpc", FieldType::Boolean, proto<[](const PacketInfo &p) { return isDce(p); }>, "DCE/RPC"},
            {"dcerpc.pkt_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isDce(p)) o.addU(pduType(p)); }, "DCE/RPC PDU type (0 Request, 2 Response, 3 Fault, 11 Bind, 12 Bind_ack); also of a PDU in the first SMB2 command of a packet (named pipe)"},
            {"dcerpc.opnum", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if ((isDceProtocol(p) && (p.app_flags & kDceFlagOpnum)) || (isDcePipe(p) && (p.app_flags & kDcePipeOpnum))) o.addU(p.app_code); }, "DCE/RPC operation number of a Request"},
            {"dcerpc.cn_call_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isDceProtocol(p) && !(p.app_flags & kDceFlagConnectionless)) o.addU(p.app_stream); }, "DCE/RPC call id of a connection-oriented PDU (not kept for a PDU inside an SMB2 packet)"},
            {"dcerpc.if_uuid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isDce(p) && !p.app_text.empty()) o.addS(p.app_text); }, "DCE/RPC interface UUID: of the first presentation context of a Bind / Alter_context, of the context a Request / Response used"},
            {"dcerpc.auth_level", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isDceProtocol(p) && (p.app_flags & kDceAuthMask)) o.addU((p.app_flags & kDceAuthMask) >> kDceAuthShift); }, "DCE/RPC authentication level of the PDU's verifier (1 none ... 5 packet integrity, 6 packet privacy)"},
            {"dcerpc.auth_service", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isDceProtocol(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "DCE/RPC authentication service of the PDU's verifier (NTLMSSP, Kerberos, SPNEGO, ...)"},
            {"dcerpc.sealed", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isDceProtocol(p)) o.addU((p.app_flags & kDceFlagSealed) != 0); }, "DCE/RPC stub data is sealed (packet privacy): labelled, not interpreted"},
            {"dcerpc.fragment", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isDceProtocol(p)) o.addU((p.app_flags & kDceFlagFragment) != 0); }, "DCE/RPC PDU is one fragment of a call split over several PDUs"},
            {"dcerpc.reassembled", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isDceProtocol(p)) o.addU((p.app_flags & kDceFlagReassembled) != 0); }, "DCE/RPC PDU completes a call that was split into fragments"},
        });
    }
} // namespace filter
