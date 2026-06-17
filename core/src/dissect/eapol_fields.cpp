// Filter fields of EAPOL and EAP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerEapolFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"eapol", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") || isProtocol(p, "EAP") || p.ether_type == 0x888E) o.addU(1); }, "IEEE 802.1X / EAPOL packet"},
            {"eapol.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") || isProtocol(p, "EAP") || p.ether_type == 0x888E) o.addU(p.app_type); }, "802.1X packet type (0 = EAP, 1 = Start, 2 = Logoff, 3 = Key)"},
            {"eapol.keydes.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") && p.app_type == 3) o.addU(p.app_code); }, "EAPOL-Key descriptor type (1 = RC4, 2 = RSN, 254 = WPA)"},
            {"eapol.keydes.msgnr", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") && p.app_type == 3 && p.app_flags != 0) o.addU(p.app_flags); }, "WPA 4-way handshake message number (1, 2, 3, 4)"},
            {"eap", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") || (isProtocol(p, "EAPOL") && p.app_type == 0)) o.addU(1); }, "Extensible Authentication Protocol"},
            {"eap.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_code != 0) o.addU(p.app_code); }, "EAP code (1 = Request, 2 = Response, 3 = Success, 4 = Failure)"},
            {"eap.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_flags != 0) o.addU(p.app_flags); }, "EAP type (1 = Identity, 13 = TLS, 25 = PEAP, 43 = FAST)"},
            {"eap.identity", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_flags == 1 && !p.app_text.empty()) o.addS(p.app_text); }, "EAP Identity username/string"},
        });
    }
} // namespace filter
