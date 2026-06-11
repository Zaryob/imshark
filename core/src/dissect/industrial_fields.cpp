// Filter fields of DNP3 (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerIndustrialFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"dnp3", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "DNP3"; }>, "Distributed Network Protocol 3.0"},
            {"dnp3.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DNP3") o.addU(checksumStatusNumber(dnp3CrcState(p, true, true))); }, "DNP3 CRC-16 of the link header and all data blocks: 0 = bad (any), 1 = good, 2 = unverified (block cut by the capture)"},
            {"dnp3.header.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DNP3") o.addU(checksumStatusNumber(dnp3CrcState(p, true, false))); }, "DNP3 link header CRC-16: 0 = bad, 1 = good"},
            {"dnp3.data.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "DNP3") o.addU(checksumStatusNumber(dnp3CrcState(p, false, true))); }, "DNP3 CRC-16 of all user data blocks: 0 = bad (any block), 1 = good, 2 = unverified, 3 = not present (no user data)"},
        });
    }
} // namespace filter
