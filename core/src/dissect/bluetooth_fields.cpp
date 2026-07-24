// Filter fields of Bluetooth (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerBluetoothFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"bt.handle", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) {
                 if (!isBluetooth(p) || !(p.app_code & 0x8000)) return;
                 static const char digits[] = "0123456789abcdef";
                 char *t = o.text[o.n];
                 t[0] = '0'; t[1] = 'x';
                 for (int i = 0; i < 4; ++i) t[2 + i] = digits[((p.app_code & 0x0FFF) >> (12 - 4 * i)) & 0xF];
                 o.v[o.n].s = std::string_view(t, 6);
                 ++o.n;
             }, "Bluetooth ACL connection handle (0x0040 form)"},
            {"bt.bd_addr", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (!isBluetooth(p)) return; for (const std::string *a: {&p.source, &p.destination}) if (packet::isMacAddress(*a)) o.addS(*a); }, "Bluetooth BD_ADDR of the remote device of an ACL link (aa:bb:cc:dd:ee:ff; only when an HCI connection event in the capture named the handle)"},
            {"bt.addr", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (!isBluetooth(p)) return; if (!p.source.empty()) o.addS(p.source); if (!p.destination.empty()) o.addS(p.destination); }, "Bluetooth source or destination: host, controller (hciN), a BD_ADDR, or a connection handle"},
        });
    }
} // namespace filter
