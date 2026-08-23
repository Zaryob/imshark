// Filter fields of IPsec AH/ESP and IKE (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    namespace {
        // AH is a layer in front of the protocol it protects, so the SPI and sequence number come from the table the load pass filled
        // (packet::IpsecTable); a filter run without it (Context::ipsec) has no value for them
        const packet::IpsecTable::Entry *ahEntry(const packet::PacketInfo &p, const Context &c) {
            if (!p.has_ah || !c.ipsec) return nullptr;
            const auto *e = c.ipsec->find(static_cast<uint32_t>(p.number));
            return e && (e->flags & packet::IpsecTable::kAh) ? e : nullptr;
        }
        const packet::IpsecTable::Entry *espEntry(const packet::PacketInfo &p, const Context &c) {
            if (!p.has_esp || !c.ipsec) return nullptr;
            const auto *e = c.ipsec->find(static_cast<uint32_t>(p.number));
            return e && (e->flags & packet::IpsecTable::kEsp) ? e : nullptr;
        }
    } // namespace

    void registerIpsecFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"ah", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.has_ah || p.protocol == "AH"; }>, "IPsec Authentication Header (IPv4 or IPv6)"},
            {"ah.spi", FieldType::Unsigned, [](const PacketInfo &p, const Context &c, Values &o) { if (const auto *e = ahEntry(p, c)) o.addU(e->ahSpi); }, "AH Security Parameters Index (SPI)"},
            {"ah.sequence", FieldType::Unsigned, [](const PacketInfo &p, const Context &c, Values &o) { if (const auto *e = ahEntry(p, c)) o.addU(e->ahSequence); }, "AH Sequence Number"},
            {"esp", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.has_esp || p.protocol == "ESP"; }>, "IPsec Encapsulating Security Payload"},
            {"esp.spi", FieldType::Unsigned, [](const PacketInfo &p, const Context &c, Values &o) { if (const auto *e = espEntry(p, c)) o.addU(e->espSpi); }, "ESP Security Parameters Index (SPI)"},
            {"esp.sequence", FieldType::Unsigned, [](const PacketInfo &p, const Context &c, Values &o) { if (const auto *e = espEntry(p, c)) o.addU(e->espSequence); }, "ESP Sequence Number"},
            {"esp.null", FieldType::Boolean, [](const PacketInfo &p, const Context &c, Values &o) { if (const auto *e = espEntry(p, c)) o.addU((e->flags & packet::IpsecTable::kEspPlaintext) ? 1 : 0); }, "ESP payload judged unencrypted by the ESP-NULL heuristic (a setting, off by default)"},
            {"ike", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "ISAKMP" || p.protocol == "IKEv2"; }>, "Internet Key Exchange / ISAKMP"},
            {"ike.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "ISAKMP" || p.protocol == "IKEv2") o.addU(p.app_code); }, "IKE Version (1 or 2)"},
            {"ike.exchange_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "ISAKMP" || p.protocol == "IKEv2") o.addU(p.app_type); }, "IKE Exchange Type"},
        });
    }
} // namespace filter
