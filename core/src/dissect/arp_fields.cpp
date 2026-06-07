// Filter fields of ARP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerArpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"arp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "ARP") || isProtocol(p, "RARP")) o.addU(1); }, "ARP / RARP"},
        });
    }
} // namespace filter
