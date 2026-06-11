// Filter fields of MySQL (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerMysqlFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"mysql", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "MySQL"; }>, "MySQL client/server protocol"},
            {"mysql.command", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL" && (p.app_flags & 32)) o.addU(p.app_type); }, "MySQL command of a client packet (3 COM_QUERY, 2 COM_INIT_DB, 1 COM_QUIT, 22 COM_STMT_PREPARE, ...)"},
            {"mysql.query", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL" && !p.app_text.empty()) o.addS(p.app_text); }, "MySQL SQL text of COM_QUERY / COM_STMT_PREPARE (or the schema of COM_INIT_DB)"},
            {"mysql.error_code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL" && (p.app_flags & 2)) o.addU(p.app_code); }, "MySQL error code of an ERR packet"},
            {"mysql.version", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL" && (p.app_flags & 4) && !p.app_text2.empty()) o.addS(p.app_text2); }, "MySQL server version of the initial handshake"},
            {"mysql.user", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL" && (p.app_flags & 8) && !p.app_text2.empty()) o.addS(p.app_text2); }, "MySQL user name of the login request"},
            {"mysql.packet_number", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL") o.addU(p.app_stream); }, "MySQL packet (sequence) number"},
            {"mysql.from_server", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL") o.addU((p.app_flags & 1) != 0); }, "MySQL packet sent by the server"},
            {"mysql.ssl_request", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "MySQL") o.addU((p.app_flags & 16) != 0); }, "MySQL SSL request (TLS handshake follows)"},
        });
    }
} // namespace filter
