// Filter fields of FTP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerFtpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"ftp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP")) o.addU(1); }, "FTP"},
            {"ftp.req", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 1) o.addU(1); }, "FTP command/request"},
            {"ftp.rsp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 2) o.addU(1); }, "FTP server response"},
            {"ftp.response.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 2 && p.app_code != 0) o.addU(p.app_code); }, "FTP response code (e.g. 200, 220, 227, 230, 550)"},
            {"ftp.command", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && p.app_type == 1 && !p.app_text.empty()) o.addS(p.app_text); }, "FTP command name (e.g. USER, PASS, PORT, PASV, RETR)"},
            {"ftp.arg", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP") && !p.app_text2.empty()) o.addS(p.app_text2); }, "FTP command or response argument"},
            {"ftp_data", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "FTP-DATA")) o.addU(1); }, "FTP-DATA"},
        });
    }
} // namespace filter
