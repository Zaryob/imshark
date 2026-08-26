// Filter fields of IPsec AH/ESP and IKE (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <cstdlib>
#include <string_view>

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
        bool isIke(const packet::PacketInfo &p) { return p.protocol == "ISAKMP" || p.protocol == "IKEv2"; }

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
            {"ike.message_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "ISAKMP" || p.protocol == "IKEv2") o.addU(p.app_stream); }, "IKE Message ID"},
            {"ike.initiator_spi", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isIke(p) && p.app_text.size() == 37) o.addS(std::string_view(p.app_text).substr(0, 18)); }, "IKE Initiator SPI (0x, 16 hex digits)"},
            {"ike.responder_spi", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isIke(p) && p.app_text.size() == 37) o.addS(std::string_view(p.app_text).substr(19, 18)); }, "IKE Responder SPI (0x, 16 hex digits)"},
            {"ike.notify.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isIke(p) && p.app_flags != 0) o.addU(p.app_flags); }, "Message Type of the first unencrypted Notify payload (IKEv2 and IKEv1 registries differ)"},
            {"ike.fragment", FieldType::Boolean, proto<[](const PacketInfo &p) { return isIke(p) && !p.app_text2.empty(); }>, "IKEv2 encrypted fragment (SKF, RFC 7383)"},
            {"ike.fragment.number", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isIke(p) && !p.app_text2.empty()) o.addU(std::strtoul(p.app_text2.c_str(), nullptr, 10)); }, "IKEv2 fragment number (SKF)"},
            {"ike.fragment.total", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isIke(p)) if (const auto slash = p.app_text2.find('/'); slash != std::string::npos) o.addU(std::strtoul(p.app_text2.c_str() + slash + 1, nullptr, 10)); }, "IKEv2 total number of fragments (SKF)"},
        });
    }
} // namespace filter
