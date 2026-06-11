// Filter fields of TDS (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerTdsFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"tds", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "TDS"; }>, "Tabular Data Stream (SQL Server)"},
            {"tds.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS") o.addU(p.app_type); }, "TDS packet type (1 SQL Batch, 3 RPC, 4 Tabular Response, 16 Login7, 18 Pre-Login)"},
            {"tds.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS") o.addU(p.app_flags & 0xff); }, "TDS status byte (bit 0 = end of message)"},
            {"tds.spid", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS") o.addU(p.app_code); }, "TDS server process id of the packet header"},
            {"tds.query", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS" && !p.app_text.empty()) o.addS(p.app_text); }, "TDS SQL Batch text or RPC procedure name"},
            {"tds.user", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS" && (p.app_flags & 0x400) && !p.app_text2.empty()) o.addS(p.app_text2); }, "TDS Login7 user name"},
            {"tds.encryption", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS" && (p.app_flags & 0x200)) o.addU((p.app_flags >> 12) & 3); }, "TDS Pre-Login ENCRYPTION option (0 OFF, 1 ON, 2 NOT_SUP, 3 REQ)"},
            {"tds.error_number", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "TDS" && (p.app_flags & 0x100)) o.addU(p.app_stream); }, "TDS ERROR token number (18456 = login failed)"},
        });
    }
} // namespace filter
