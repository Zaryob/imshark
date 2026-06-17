// Filter fields of LLC and SNAP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerLlcFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"llc", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLlc(p)) o.addU(1); }, "IEEE 802.2 Logical-Link Control"},
            {"llc.dsap", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "LLC") || isProtocol(p, "SNAP")) o.addU(p.app_type); else if (isStp(p)) o.addU(0x42); }, "LLC Destination Service Access Point (DSAP)"},
            {"llc.ssap", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "LLC") || isProtocol(p, "SNAP")) o.addU(p.app_flags & 0xFF); else if (isStp(p)) o.addU(0x42); }, "LLC Source Service Access Point (SSAP)"},
            {"llc.control", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "LLC") || isProtocol(p, "SNAP")) o.addU(p.app_code); else if (isStp(p)) o.addU(0x03); }, "LLC Control Field"},
            {"snap", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isSnap(p)) o.addU(1); }, "Subnetwork Access Protocol (SNAP)"},
            {"snap.oui", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isSnap(p)) o.addU(p.tcp_pdu_start); }, "SNAP Organizationally Unique Identifier (OUI)"},
            {"snap.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isSnap(p) && p.ether_type != 0) o.addU(p.ether_type); }, "SNAP Protocol ID / EtherType"},
        });
    }
} // namespace filter
