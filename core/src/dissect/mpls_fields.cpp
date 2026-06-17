// Filter fields of MPLS (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerMplsFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"mpls", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU(1); }, "MultiProtocol Label Switching"},
            {"mpls.label", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU((p.mplsLse(0) >> 12) & 0xFFFFF); }, "MPLS Label Value (outermost label)"},
            {"mpls.exp", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU((p.mplsLse(0) >> 9) & 0x07); }, "MPLS Experimental (TC) Bits"},
            {"mpls.ttl", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU(p.mplsLse(0) & 0xFF); }, "MPLS Time To Live"},
            {"mpls.bottom_of_stack", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU((p.mplsLse(0) >> 8) & 0x01); }, "MPLS Bottom of Stack flag (outermost label)"},
            {"mpls.label1", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p) && !((p.mplsLse(0) >> 8) & 0x01)) o.addU((p.mplsLse(1) >> 12) & 0xFFFFF); }, "MPLS Label Value (second label in the stack)"},
        });
    }
} // namespace filter
