// Filter fields of PPI (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerPpiFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"ppi.dlt", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ppi_dlt != 0) o.addU(p.ppi_dlt); }, "PPI encapsulated Data Link Type"},
        });
    }
} // namespace filter
