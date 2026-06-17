// Filter fields of IEEE 802.11 (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerWlanFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"wlan", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.link_type == 105 || p.link_type == 127 || p.link_type == 192 || isProtocol(p, "802.11") || isProtocol(p, "WLAN") || p.wlan_fc != 0) o.addU(1); }, "IEEE 802.11 wireless frame"},
            {"wlan.fc.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc >> 2) & 0x03); }, "802.11 Frame Control type (0 = Management, 1 = Control, 2 = Data, 3 = Extension)"},
            {"wlan.fc.subtype", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc >> 4) & 0x0F); }, "802.11 Frame Control subtype"},
            {"wlan.fc.protected", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x4000) ? 1 : 0); }, "802.11 Frame Control protected (encrypted) bit"},
            {"wlan.fc.retry", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0800) ? 1 : 0); }, "802.11 Frame Control retry bit"},
            {"wlan.fc.tods", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0100) ? 1 : 0); }, "802.11 Frame Control To DS bit"},
            {"wlan.fc.fromds", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0200) ? 1 : 0); }, "802.11 Frame Control From DS bit"},
            {"wlan.seq", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU(p.wlan_seq); }, "802.11 sequence number"},
            {"wlan.sa", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.source.empty()) o.addS(p.source); }, "802.11 Source MAC address"},
            {"wlan.da", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.destination.empty()) o.addS(p.destination); }, "802.11 Destination MAC address"},
            {"wlan.ra", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.destination.empty()) o.addS(p.destination); }, "802.11 Receiver MAC address"},
            {"wlan.ta", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.source.empty()) o.addS(p.source); }, "802.11 Transmitter MAC address"},
            {"wlan.bssid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.app_text2.empty()) o.addS(p.app_text2); }, "802.11 BSSID MAC address"},
            {"wlan.ssid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.app_text.empty()) o.addS(p.app_text); }, "802.11 SSID"},
        });
    }
} // namespace filter
