// Filter fields of TFTP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerTftpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"tftp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP")) o.addU(1); }, "TFTP"},
            {"tftp.opcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && p.app_type != 0) o.addU(p.app_type); }, "TFTP opcode (1 = RRQ, 2 = WRQ, 3 = DATA, 4 = ACK, 5 = ERROR, 6 = OACK)"},
            {"tftp.block", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && (p.app_type == 3 || p.app_type == 4)) o.addU(p.app_code); }, "TFTP block number"},
            {"tftp.error.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && p.app_type == 5) o.addU(p.app_code); }, "TFTP error code"},
            {"tftp.source_file", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && (p.app_type == 1 || p.app_type == 2) && !p.app_text.empty()) o.addS(p.app_text); }, "TFTP filename"},
            {"tftp.mode", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "TFTP") && (p.app_type == 1 || p.app_type == 2) && !p.app_text2.empty()) o.addS(p.app_text2); }, "TFTP transfer mode (e.g. netascii, octet)"},
        });
    }
} // namespace filter
