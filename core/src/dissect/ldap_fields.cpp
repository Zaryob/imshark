// Filter fields of LDAP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerLdapFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"ldap", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "LDAP"; }>, "Lightweight Directory Access Protocol"},
            {"ldap.message_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "LDAP") o.addU(p.app_stream); }, "LDAP Message ID"},
            {"ldap.protocol_op", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "LDAP" && p.app_type != 0xFF) o.addU(p.app_type); }, "LDAP Protocol Operation (Application tag)"},
            {"ldap.name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "LDAP" && !p.app_text.empty()) o.addS(p.app_text); }, "LDAP Distinguished Name / Target Object"},
            {"ldap.result_code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "LDAP" && (p.app_flags & 1)) o.addU(p.app_code); }, "LDAP result code of a response (0 success, 49 invalidCredentials, ...)"},
            {"ldap.extended_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "LDAP" && !p.app_text2.empty()) o.addS(p.app_text2); }, "LDAP extended operation OID (1.3.6.1.4.1.1466.20037 is StartTLS)"},
        });
    }
} // namespace filter
