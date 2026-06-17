// Filter fields of IP-in-IP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerIpipFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"ipip", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isIpip(p)) o.addU(1); }, "IP-in-IP tunnel (protocol 4 or 41)"},
        });
    }
} // namespace filter
