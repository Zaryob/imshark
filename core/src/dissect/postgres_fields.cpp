// Filter fields of PostgreSQL (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerPostgresFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"pgsql", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "PGSQL"; }>, "PostgreSQL frontend/backend protocol"},
            {"pgsql.type", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && p.app_type == 6 && p.app_flags > 31 && p.app_flags < 127) { static const std::string_view letters = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"; o.addS(letters.substr(p.app_flags - 32, 1)); } }, "PostgreSQL message type letter (Q SimpleQuery, P Parse, R Authentication, Z ReadyForQuery, ...)"},
            {"pgsql.query", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && !p.app_text.empty()) o.addS(p.app_text); }, "PostgreSQL SQL text of a SimpleQuery or Parse message"},
            {"pgsql.user", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && p.app_type == 1 && !p.app_text2.empty()) o.addS(p.app_text2); }, "PostgreSQL user of a StartupMessage"},
            {"pgsql.code", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && p.app_type == 6 && (p.app_flags == 'E' || p.app_flags == 'N') && !p.app_text2.empty()) o.addS(p.app_text2); }, "PostgreSQL SQLSTATE of an ErrorResponse / NoticeResponse"},
            {"pgsql.ssl_request", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL") o.addU(p.app_type == 2); }, "PostgreSQL SSLRequest"},
        });
    }
} // namespace filter
