// Filter fields of Bluetooth (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerBluetoothFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"bt.handle", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (!isBluetooth(p)) return; for (const std::string *a: {&p.source, &p.destination}) if (a->rfind("0x", 0) == 0) o.addS(*a); }, "Bluetooth ACL connection handle (0x0040 form)"},
            {"bt.addr", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (!isBluetooth(p)) return; if (!p.source.empty()) o.addS(p.source); if (!p.destination.empty()) o.addS(p.destination); }, "Bluetooth source or destination: host, controller (hciN), or a connection handle"},
        });
    }
} // namespace filter
