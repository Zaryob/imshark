// Filter fields of SMTP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerSmtpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"smtp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP")) o.addU(1); }, "SMTP"},
            {"smtp.req", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 1) o.addU(1); }, "SMTP command/request"},
            {"smtp.rsp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 2) o.addU(1); }, "SMTP server response"},
            {"smtp.response.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 2 && p.app_code != 0) o.addU(p.app_code); }, "SMTP response code (e.g. 220, 250, 354, 550)"},
            {"smtp.command", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && p.app_type == 1 && !p.app_text.empty()) o.addS(p.app_text); }, "SMTP command name (e.g. EHLO, MAIL FROM, RCPT TO, DATA)"},
            {"smtp.param", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SMTP") && !p.app_text2.empty()) o.addS(p.app_text2); }, "SMTP command or response parameter"},
        });
    }
} // namespace filter
