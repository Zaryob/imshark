// Filter fields of SSH (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerSshFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"ssh", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH")) o.addU(1); }, "SSH"},
            {"ssh.protocol", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 0 && !p.app_text.empty()) o.addS(p.app_text); }, "SSH protocol version banner"},
            {"ssh.message_code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type != 0 && p.app_type != 255) o.addU(p.app_type); }, "SSH packet message code (e.g. 20 = KEXINIT, 21 = NEWKEYS)"},
            {"ssh.kex_algorithm", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 20 && !p.app_text.empty()) o.addS(p.app_text); }, "SSH key exchange algorithm"},
            {"ssh.encryption_algorithm", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 20 && !p.app_text2.empty()) o.addS(p.app_text2); }, "SSH client-to-server encryption algorithm"},
            {"ssh.encrypted", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "SSH") && p.app_type == 255) o.addU(1); }, "SSH encrypted packet payload"},
        });
    }
} // namespace filter
