// Filter fields of STP/RSTP/MSTP (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerStpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"stp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p)) o.addU(1); }, "Spanning Tree Protocol (STP / RSTP / MSTP)"},
            {"stp.protocol", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p)) o.addU(0); }, "STP Protocol Identifier"},
            {"stp.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p)) o.addU(p.app_flags & 0xFF); }, "STP Protocol Version Identifier (0 = STP, 2 = RSTP, 3 = MSTP)"},
            {"stp.bpdu.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p)) o.addU(p.app_type); }, "STP BPDU Type (0x00 = Config, 0x02 = RST, 0x80 = TCN)"},
            {"stp.flags", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU((p.app_flags >> 8) & 0xFF); }, "STP BPDU Flags byte"},
            {"stp.flags.tc", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x01) ? 1 : 0); }, "STP Topology Change flag"},
            {"stp.flags.proposal", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x02) ? 1 : 0); }, "STP Proposal flag"},
            {"stp.flags.port_role", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) >> 2) & 0x03); }, "STP Port Role (1 = Alternate/Backup, 2 = Root, 3 = Designated)"},
            {"stp.flags.learning", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x10) ? 1 : 0); }, "STP Learning flag"},
            {"stp.flags.forwarding", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x20) ? 1 : 0); }, "STP Forwarding flag"},
            {"stp.flags.agreement", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x40) ? 1 : 0); }, "STP Agreement flag"},
            {"stp.flags.tc_ack", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(((p.app_flags >> 8) & 0x80) ? 1 : 0); }, "STP Topology Change Acknowledgment flag"},
            {"stp.root.cost", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(p.tcp_pdu_start); }, "STP Root Path Cost"},
            {"stp.root.id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && !p.app_text.empty()) o.addS(p.app_text); }, "STP Root Identifier"},
            {"stp.bridge.id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "STP Bridge Identifier"},
            {"stp.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isStp(p) && (p.app_type == 0 || p.app_type == 2)) o.addU(p.app_code); }, "STP Port Identifier"},
        });
    }
} // namespace filter
