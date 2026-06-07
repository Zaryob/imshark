// Filter fields of Ethernet and 802.1Q (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerEthernetFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"eth", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.link_type == 1; }>, "Ethernet frame"},
            {"eth.src", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (hasMacAddresses(p) && packet::isMacAddress(p.source)) o.addS(p.source); }, "Ethernet source address (frames the summary still holds MAC addresses for: not IP packets)"},
            {"eth.dst", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (hasMacAddresses(p) && packet::isMacAddress(p.destination)) o.addS(p.destination); }, "Ethernet destination address (frames the summary still holds MAC addresses for: not IP packets)"},
            {"eth.addr", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (hasMacAddresses(p)) { if (packet::isMacAddress(p.source)) o.addS(p.source); if (packet::isMacAddress(p.destination)) o.addS(p.destination); } }, "Ethernet source or destination address (frames the summary still holds MAC addresses for: not IP packets)"},
            {"eth.len", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.link_type == 1 && p.has_llc && p.eth_len != 0) o.addU(p.eth_len); }, "IEEE 802.3 length field"},
            {"eth.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (!p.has_llc && p.ether_type > 1500) o.addU(p.ether_type); }, "EtherType"},
            {"vlan", FieldType::Boolean, proto<[](const PacketInfo &p) { return !p.vlan_ids.empty(); }>, "802.1Q VLAN tagged"},
            {"vlan.id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { for (size_t i = 0; i < p.vlan_ids.size() && i < 2; ++i) o.addU(p.vlan_ids[i]); }, "VLAN ID (outermost two tags)"},
        });
    }
} // namespace filter
