// Filter fields of Telnet (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerTelnetFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"telnet", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet")) o.addU(1); }, "Telnet"},
            {"telnet.cmd", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet") && p.app_type != 0) o.addU(p.app_type); }, "Telnet command (251 = WILL, 252 = WONT, 253 = DO, 254 = DONT, 250 = SB...)"},
            {"telnet.subcmd", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet") && p.app_code != 0) o.addU(p.app_code); }, "Telnet option code (1 = Echo, 3 = Suppress Go Ahead, 24 = Terminal Type, 31 = NAWS...)"},
            {"telnet.data", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Telnet") && !p.app_text.empty()) o.addS(p.app_text); }, "Telnet text data or command summary"},
        });
    }
} // namespace filter
