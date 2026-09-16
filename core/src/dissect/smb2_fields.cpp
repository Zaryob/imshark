// Filter fields of SMB2 (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerSmb2Fields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"smb2", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "SMB2"; }>, "SMB2 / SMB3"},
            {"smb2.cmd", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && !(p.app_flags & 0xC)) o.addU(p.app_type); }, "SMB2 command of the first message in the packet (0 Negotiate, 1 Session Setup, 3 Tree Connect, 5 Create, 8 Read, 9 Write)"},
            {"smb2.flags.response", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && !(p.app_flags & 0xC)) o.addU((p.app_flags & 1) != 0); }, "SMB2 response flag of the first message"},
            {"smb2.flags.signed", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && !(p.app_flags & 0xC)) o.addU((p.app_flags & 2) != 0); }, "SMB2 signed flag of the first message"},
            {"smb2.encrypted", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2") o.addU((p.app_flags & 4) != 0); }, "SMB3 message in a Transform header (encrypted, content not shown)"},
            {"smb2.nt_status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && (p.app_flags & 1) && !(p.app_flags & 0xC)) o.addU(p.app_stream); }, "SMB2 NT status of a response (first message)"},
            {"smb2.dialect", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && (p.app_flags & 0x10)) o.addU(p.app_code); }, "SMB2 dialect revision chosen by a Negotiate response (0x0311 = SMB 3.1.1)"},
            {"smb2.tree", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && p.app_type == 3 && !(p.app_flags & 0xD) && !p.app_text.empty()) o.addS(p.app_text); }, "SMB2 share path of a Tree Connect request"},
            {"smb2.filename", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && p.app_type == 5 && !(p.app_flags & 0xD) && !p.app_text.empty()) o.addS(p.app_text); }, "SMB2 file name of a Create request"},
            {"smb2.file", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && !(p.app_flags & 0xC) && !p.app_text2.empty()) o.addS(p.app_text2); }, "SMB2 file the first command works on: the Create name, or the name behind its FileId / matched request (session table)"},
            {"smb2.pipe", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && !(p.app_flags & 0xC)) o.addU((p.app_flags & 0x80) != 0); }, "SMB2 first command works on a named pipe (a file of an IPC$ share, or the IPC$ tree itself)"},
            {"smb2.user", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "SMB2" && p.app_type == 1 && !(p.app_flags & 0xD) && !p.app_text.empty()) o.addS(p.app_text); }, "SMB2 user of an NTLMSSP authenticate message (domain\\user)"},
        });
    }
} // namespace filter
