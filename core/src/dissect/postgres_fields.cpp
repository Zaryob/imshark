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
            {"pgsql.query", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && !(p.app_code & 1) && !p.app_text.empty()) o.addS(p.app_text); }, "PostgreSQL SQL text of a SimpleQuery or Parse message, and the query a Bind / Describe / Execute / Close resolves to through the statement name"},
            {"pgsql.statement", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && p.app_type == 6 && !(p.app_code & 1) && (p.app_flags == 'P' || p.app_flags == 'B' || p.app_flags == 'D' || p.app_flags == 'C') && !p.app_text2.empty()) o.addS(p.app_text2); }, "PostgreSQL prepared statement name of a Parse, Bind, Describe or Close message (an unnamed statement has none)"},
            {"pgsql.value", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && p.app_type == 6 && (p.app_code & 1) && p.app_flags == 'D' && !p.app_text.empty()) o.addS(p.app_text); }, "PostgreSQL first values of a DataRow (up to 8, joined with \", \", typed by the RowDescription, NULL for null)"},
            {"pgsql.count", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && p.app_type == 6 && (p.app_flags == 'T' || p.app_flags == 'D' || p.app_flags == 'B' || p.app_flags == 't' || p.app_flags == 'G' || p.app_flags == 'H' || p.app_flags == 'W')) o.addU(p.app_stream); }, "PostgreSQL number of columns (RowDescription, DataRow, COPY responses) or parameters (Bind, ParameterDescription)"},
            {"pgsql.user", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && p.app_type == 1 && !p.app_text2.empty()) o.addS(p.app_text2); }, "PostgreSQL user of a StartupMessage"},
            {"pgsql.code", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL" && p.app_type == 6 && (p.app_flags == 'E' || p.app_flags == 'N') && !p.app_text2.empty()) o.addS(p.app_text2); }, "PostgreSQL SQLSTATE of an ErrorResponse / NoticeResponse"},
            {"pgsql.ssl_request", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "PGSQL") o.addU(p.app_type == 2); }, "PostgreSQL SSLRequest"},
        });
    }
} // namespace filter
