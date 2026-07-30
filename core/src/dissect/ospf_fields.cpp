// Filter fields of OSPF (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerOspfFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"ospf", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "OSPF" || p.ip_protocol == 89; }>, "Open Shortest Path First"},
            {"ospf.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF") o.addU(p.app_code); }, "OSPF Version (2 or 3)"},
            {"ospf.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF") o.addU(p.app_type); }, "OSPF Packet Type (1=Hello, 2=DD, 3=LSR, 4=LSU, 5=LSAck)"},
            {"ospf.lsa.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF" && (p.app_flags & 3) != dissect::kChecksumNone) o.addU(checksumStatusNumber(static_cast<uint8_t>(p.app_flags & 3))); }, "OSPF LSA Fletcher checksum (RFC 2328 12.1.7, RFC 5340 A.4.2) of the LSAs in a DD, LSU or LSAck: 0 = bad (any), 1 = good, 2 = unverified (headers only, or cut off); absent without LSAs"},
            {"ospf.auth.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF" && p.app_code == 2) o.addU(p.app_stream & 0xffff); }, "OSPFv2 authentication type (0 none, 1 simple password, 2 cryptographic)"},
            {"ospf.instance_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF" && p.app_code == 3) o.addU(p.app_flags >> 8); }, "OSPFv3 Instance ID (RFC 5340 A.3.1)"},
            {"ospf.lsa.count", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF" && (p.app_type == 2 || p.app_type == 4 || p.app_type == 5)) o.addU(p.app_stream >> 16); }, "Number of LSAs found in an OSPF Database Description or Link State Acknowledgment (headers) or Link State Update"},
            {"ospf.router_id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF" && !p.app_text.empty()) o.addS(p.app_text); }, "OSPF Router ID"},
            {"ospf.area_id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "OSPF" && !p.app_text2.empty()) o.addS(p.app_text2); }, "OSPF Area ID"},
        });
    }
} // namespace filter
