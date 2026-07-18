// Filter fields of USB (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerUsbFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"usb", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isUsb(p)) o.addU(1); }, "USB packet"},
            {"usb.device", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (!isUsb(p)) return; for (const std::string *a: {&p.source, &p.destination}) if (!a->empty() && *a != "host") o.addS(*a); }, "USB device address (bus.device)"},
            {"usb.endpoint", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isUsb(p) && (p.app_flags & 0x100)) o.addU(p.app_flags & 0xFF); }, "USB endpoint address of the transfer (bit 7 set = IN, e.g. 0x81 is endpoint 1 IN)"},
        });
    }
} // namespace filter
