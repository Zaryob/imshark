// Filter fields of GRE (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerGreFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"gre", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU(1); }, "Generic Routing Encapsulation"},
            {"gre.proto", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU(p.gre_proto); }, "GRE Protocol Type (0x0800 = IPv4, 0x86DD = IPv6, 0x6558 = Ethernet, 0x880B = PPP)"},
            {"gre.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU(p.gre_flags & 0x0007); }, "GRE Version (0 = RFC 2784, 1 = Enhanced GRE/RFC 2637)"},
            {"gre.flags.checksum", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x8000) ? 1 : 0); }, "GRE Checksum present flag"},
            {"gre.flags.routing", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x4000) ? 1 : 0); }, "GRE Routing present flag"},
            {"gre.flags.key", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x2000) ? 1 : 0); }, "GRE Key present flag"},
            {"gre.flags.sequence", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x1000) ? 1 : 0); }, "GRE Sequence Number present flag"},
            {"gre.key", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p) && (p.gre_flags & 0x2000)) o.addU(p.gre_key); }, "GRE Key (low 16 bits)"},
            {"gre.sequence_number", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p) && (p.gre_flags & 0x1000)) o.addU(p.gre_seq); }, "GRE Sequence Number (low 16 bits)"},
        });
    }
} // namespace filter
