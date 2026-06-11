// Filter fields of ONC RPC, NFS, Portmap and Mount (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerNfsFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"rpc", FieldType::Boolean, proto<isRpc>, "ONC RPC (also NFS, Portmap and Mount)"},
            {"rpc.xid", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p)) o.addU(p.app_stream); }, "ONC RPC transaction id"},
            {"rpc.msgtyp", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpc(p)) o.addU(p.app_flags & 1); }, "ONC RPC message type (0 call, 1 reply)"},
            {"rpc.program", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpcCall(p)) o.addU(std::strtoull(p.app_text.c_str(), nullptr, 10)); }, "ONC RPC program number of a call (100003 NFS, 100000 Portmap, 100005 Mount)"},
            {"rpc.programversion", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpcCall(p)) o.addU(p.app_code); }, "ONC RPC program version of a call"},
            {"rpc.procedure", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isRpcCall(p)) o.addU(p.app_type); }, "ONC RPC procedure number of a call"},
            {"rpc.state_accept", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "RPC" && (p.app_flags & 1) && !(p.app_flags & 2)) o.addU(p.app_code); }, "ONC RPC accept status of an accepted reply (0 SUCCESS, 1 PROG_UNAVAIL, 2 PROG_MISMATCH, 3 PROC_UNAVAIL ...)"},
            {"rpc.reply_denied", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "RPC" && (p.app_flags & 1)) o.addU((p.app_flags & 2) != 0); }, "ONC RPC reply that was denied (RPC_MISMATCH or AUTH_ERROR)"},
            {"nfs", FieldType::Boolean, proto<[](const PacketInfo &p) { return p.protocol == "NFS" || p.protocol == "NFSv4"; }>, "Network File System call"},
            {"nfs.proc", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "NFS" || p.protocol == "NFSv4") o.addU(p.app_type); }, "NFS procedure of a call (v3: 1 GETATTR, 3 LOOKUP, 6 READ, 7 WRITE; v4: 1 COMPOUND)"},
            {"nfs.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "NFS" || p.protocol == "NFSv4") o.addU(p.app_code); }, "NFS protocol version of a call"},
            {"nfs.name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((p.protocol == "NFS" || p.protocol == "NFSv4") && !p.app_text2.empty()) o.addS(p.app_text2); }, "NFS file name of a LOOKUP / CREATE / MKDIR / REMOVE / RMDIR call"},
            {"portmap.proc", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Portmap") o.addU(p.app_type); }, "Portmap procedure of a call (3 GETPORT)"},
            {"mount.path", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (p.protocol == "Mount" && !p.app_text2.empty()) o.addS(p.app_text2); }, "Mount directory path of a MNT / UMNT call"},
        });
    }
} // namespace filter
