// Filter fields of ONC RPC, NFS, Portmap and Mount (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo:
//   app_stream = xid, app_text = program number (a call, or a reply matched with its call), app_type = procedure, app_code = program
//   version of a call / accept or auth status of a reply, app_text2 = file name / path of a call (v3 name, Mount path) or the NFSv4
//   operation names, app_flags: bit 0 reply, 1 denied, 2 matched with its call, 3 retransmitted call / duplicate reply, 4 record joined
//   from fragments, 5 fragment of a longer record, 8..15 program version.
#include <cstdlib>

#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    namespace {
        using packet::PacketInfo;
        constexpr uint16_t kReply = 1, kDenied = 2, kMatched = 4, kRepeat = 8, kReassembled = 16, kFragment = 32, kResult = 64;
        inline bool isReply(const PacketInfo &p) { return (p.app_flags & kReply) != 0; }
        inline bool isNfs(const PacketInfo &p) { return p.protocol == "NFS" || p.protocol == "NFSv4"; }
        // a call, or a reply that was matched with its call: both carry the program, version and procedure
        inline bool hasProgram(const PacketInfo &p) { return fh::isRpc(p) && !p.app_text.empty(); }
        inline uint32_t version(const PacketInfo &p) { return isReply(p) ? (p.app_flags >> 8) : p.app_code; }
    } // namespace

    void registerNfsFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"rpc", FieldType::Boolean, proto<isRpc>, "ONC RPC (also NFS, Portmap and Mount)"},
            {"rpc.xid", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p)) o.addU(p.app_stream); }, "ONC RPC transaction id"},
            {"rpc.msgtyp", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p)) o.addU(p.app_flags & 1); }, "ONC RPC message type (0 call, 1 reply)"},
            {"rpc.program", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasProgram(p)) o.addU(std::strtoull(p.app_text.c_str(), nullptr, 10)); }, "ONC RPC program number of a call, or of the call a matched reply answers (100003 NFS, 100000 Portmap, 100005 Mount)"},
            {"rpc.programversion", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasProgram(p)) o.addU(version(p)); }, "ONC RPC program version of a call, or of the call a matched reply answers"},
            {"rpc.procedure", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (hasProgram(p)) o.addU(p.app_type); }, "ONC RPC procedure number of a call, or of the call a matched reply answers"},
            {"rpc.state_accept", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p) && isReply(p) && !(p.app_flags & kDenied)) o.addU((p.app_flags & kResult) ? 0 : p.app_code); }, "ONC RPC accept status of an accepted reply (0 SUCCESS, 1 PROG_UNAVAIL, 2 PROG_MISMATCH, 3 PROC_UNAVAIL ...)"},
            {"rpc.reply_denied", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p) && isReply(p)) o.addU((p.app_flags & kDenied) != 0); }, "ONC RPC reply that was denied (RPC_MISMATCH or AUTH_ERROR)"},
            {"rpc.matched", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p) && isReply(p)) o.addU((p.app_flags & kMatched) != 0); }, "ONC RPC reply whose call was seen earlier in the capture (xid, addresses and ports agree)"},
            {"rpc.retransmission", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (hasProgram(p) && !isReply(p)) o.addU((p.app_flags & kRepeat) != 0); }, "ONC RPC call seen again (same xid, program, version and procedure)"},
            {"rpc.duplicate_reply", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p) && isReply(p)) o.addU((p.app_flags & kRepeat) != 0); }, "ONC RPC second reply to the same call"},
            {"rpc.reassembled", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p)) o.addU((p.app_flags & kReassembled) != 0); }, "ONC RPC message joined from the several fragments of its TCP record (shown on the last fragment)"},
            {"rpc.fragment", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p)) o.addU((p.app_flags & kFragment) != 0); }, "ONC RPC record fragment that is not the last one of its record"},
            {"nfs", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "NFS" || p.protocol == "NFSv4"; }>, "Network File System call or matched reply"},
            {"nfs.proc", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isNfs(p)) o.addU(p.app_type); }, "NFS procedure of a call or matched reply (v3: 1 GETATTR, 3 LOOKUP, 6 READ, 7 WRITE; v4: 1 COMPOUND)"},
            {"nfs.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isNfs(p)) o.addU(version(p)); }, "NFS protocol version of a call or matched reply"},
            {"nfs.name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isNfs(p) && !isReply(p) && version(p) == 3 && !p.app_text2.empty()) o.addS(p.app_text2); }, "NFS file name of a LOOKUP / CREATE / MKDIR / REMOVE / RMDIR call"},
            {"nfs.operations", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "NFSv4" && !p.app_text2.empty()) o.addS(p.app_text2); }, "Operations of an NFSv4 COMPOUND call, or of the results of its matched reply, comma separated in order (PUTFH,LOOKUP,GETATTR; the first 16); test one with matches \"\\bLOOKUP\\b\""},
            {"nfs.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isNfs(p) && isReply(p) && (p.app_flags & kResult)) o.addU(p.app_code); }, "NFS status of a matched reply (v3 nfsstat3, v4 status of the COMPOUND: 0 OK, 2 NOENT, 13 ACCES, 70 STALE ...)"},
            {"portmap.proc", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Portmap") o.addU(p.app_type); }, "Portmap procedure of a call or matched reply (3 GETPORT)"},
            {"portmap.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Portmap" && isReply(p) && (p.app_flags & kResult) && (p.app_type == 3 || p.app_type == 9)) o.addU(p.app_code); }, "TCP / UDP port a Portmap GETPORT or rpcbind GETADDR / GETVERSADDR reply announced (0: the program is not registered)"},
            {"portmap.entries", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Portmap" && isReply(p) && (p.app_flags & kResult) && p.app_type == 4) o.addU(p.app_code); }, "Number of mappings a Portmap / rpcbind DUMP reply lists"},
            {"mount.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Mount" && isReply(p) && (p.app_flags & kResult) && p.app_type == 1) o.addU(p.app_code); }, "Mount status of a MNT reply (0 OK, 2 NOENT, 13 ACCES ...)"},
            {"mount.path", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Mount" && !isReply(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "Mount directory path of a MNT / UMNT call"},
        });
    }
} // namespace filter
