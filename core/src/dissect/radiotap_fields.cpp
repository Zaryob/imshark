// Filter fields of Radiotap (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerRadiotapFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"radiotap.channel.freq", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_freq != 0) o.addU(p.radiotap_freq); }, "Radiotap/PPI channel frequency in MHz"},
            {"radiotap.dbm_antsignal", FieldType::Float, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_signal != 0) o.addD(static_cast<double>(p.radiotap_signal)); }, "Radiotap/PPI antenna signal in dBm"},
            {"radiotap.datarate", FieldType::Float, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_rate != 0) o.addD(p.radiotap_rate * 0.5); }, "Radiotap/PPI data rate in Mb/s"},
        });
    }
} // namespace filter
