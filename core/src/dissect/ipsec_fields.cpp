// Filter fields of IPsec AH/ESP and IKE (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerIpsecFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"ah", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "AH" || p.ip_protocol == 51; }>, "IPsec Authentication Header"},
            {"ah.spi", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "AH" || p.ip_protocol == 51) o.addU(p.tcp_pdu_start); }, "AH Security Parameters Index (SPI)"},
            {"ah.sequence", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "AH" || p.ip_protocol == 51) o.addU(p.app_code); }, "AH Sequence Number"},
            {"esp", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "ESP" || p.ip_protocol == 50; }>, "IPsec Encapsulating Security Payload"},
            {"esp.spi", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "ESP" || p.ip_protocol == 50) o.addU(p.tcp_pdu_start); }, "ESP Security Parameters Index (SPI)"},
            {"esp.sequence", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "ESP" || p.ip_protocol == 50) o.addU(p.app_code); }, "ESP Sequence Number"},
            {"ike", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "ISAKMP" || p.protocol == "IKEv2"; }>, "Internet Key Exchange / ISAKMP"},
            {"ike.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "ISAKMP" || p.protocol == "IKEv2") o.addU(p.app_code); }, "IKE Version (1 or 2)"},
            {"ike.exchange_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "ISAKMP" || p.protocol == "IKEv2") o.addU(p.app_type); }, "IKE Exchange Type"},
        });
    }
} // namespace filter
