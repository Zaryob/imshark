// Filter fields of Kerberos (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerKerberosFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"kerberos", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "Kerberos"; }>, "Kerberos"},
            {"kerberos.msg_type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Kerberos") o.addU(p.app_type); }, "Kerberos message type (10 AS-REQ, 11 AS-REP, 12 TGS-REQ, 13 TGS-REP, 14 AP-REQ, 15 AP-REP, 30 KRB-ERROR)"},
            {"kerberos.error_code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Kerberos" && p.app_type == 30) o.addU(p.app_code); }, "Kerberos KRB-ERROR error code (25 = KDC_ERR_PREAUTH_REQUIRED)"},
            {"kerberos.realm", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Kerberos" && !p.app_text.empty()) o.addS(p.app_text); }, "Kerberos realm"},
            {"kerberos.cname", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol != "Kerberos") return; const std::string_view v = p.app_text2; const auto c = v.substr(0, v.find('\n')); if (!c.empty()) o.addS(c); }, "Kerberos client principal name"},
            {"kerberos.sname", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol != "Kerberos") return; const std::string_view v = p.app_text2; const auto nl = v.find('\n'); if (nl == std::string_view::npos) return; const auto sv = v.substr(nl + 1); if (!sv.empty()) o.addS(sv); }, "Kerberos service principal name"},
        });
    }
} // namespace filter
