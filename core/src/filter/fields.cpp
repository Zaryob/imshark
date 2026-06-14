#include "fields.h"

#include <algorithm>
#include <cstdlib>
#include <deque>
#include <mutex>

#include <cstdio>

#include "field_helpers.h"
#include "field_modules.h"

namespace filter {
    namespace {
        using namespace fh;
        using packet::PacketInfo;

        // The rows that are not in a field module yet (they move out protocol by protocol).
        std::vector<FieldDef> legacyRows() {
            std::vector<FieldDef> t = {
                // ---- frame
                // ---- link layer
                // ---- network layer
                // ---- transport layer
                // ---- application protocols (by the protocol column)
                {"wlan", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.link_type == 105 || p.link_type == 127 || p.link_type == 192 || isProtocol(p, "802.11") || isProtocol(p, "WLAN") || p.wlan_fc != 0) o.addU(1); }, "IEEE 802.11 wireless frame"},
                {"wlan.fc.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc >> 2) & 0x03); }, "802.11 Frame Control type (0 = Management, 1 = Control, 2 = Data, 3 = Extension)"},
                {"wlan.fc.subtype", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc >> 4) & 0x0F); }, "802.11 Frame Control subtype"},
                {"wlan.fc.protected", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x4000) ? 1 : 0); }, "802.11 Frame Control protected (encrypted) bit"},
                {"wlan.fc.retry", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0800) ? 1 : 0); }, "802.11 Frame Control retry bit"},
                {"wlan.fc.tods", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0100) ? 1 : 0); }, "802.11 Frame Control To DS bit"},
                {"wlan.fc.fromds", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU((p.wlan_fc & 0x0200) ? 1 : 0); }, "802.11 Frame Control From DS bit"},
                {"wlan.seq", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.wlan_fc != 0 || isProtocol(p, "802.11") || isProtocol(p, "WLAN")) o.addU(p.wlan_seq); }, "802.11 sequence number"},
                {"wlan.sa", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.source.empty()) o.addS(p.source); }, "802.11 Source MAC address"},
                {"wlan.da", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.destination.empty()) o.addS(p.destination); }, "802.11 Destination MAC address"},
                {"wlan.ra", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.destination.empty()) o.addS(p.destination); }, "802.11 Receiver MAC address"},
                {"wlan.ta", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.source.empty()) o.addS(p.source); }, "802.11 Transmitter MAC address"},
                {"wlan.bssid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.app_text2.empty()) o.addS(p.app_text2); }, "802.11 BSSID MAC address"},
                {"wlan.ssid", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if ((isProtocol(p, "802.11") || isProtocol(p, "WLAN")) && !p.app_text.empty()) o.addS(p.app_text); }, "802.11 SSID"},
                {"radiotap.channel.freq", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_freq != 0) o.addU(p.radiotap_freq); }, "Radiotap/PPI channel frequency in MHz"},
                {"radiotap.dbm_antsignal", FieldType::Float, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_signal != 0) o.addD(static_cast<double>(p.radiotap_signal)); }, "Radiotap/PPI antenna signal in dBm"},
                {"radiotap.datarate", FieldType::Float, [](const PacketInfo &p, const Context &, Values &o) { if (p.radiotap_rate != 0) o.addD(p.radiotap_rate * 0.5); }, "Radiotap/PPI data rate in Mb/s"},
                {"ppi.dlt", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ppi_dlt != 0) o.addU(p.ppi_dlt); }, "PPI encapsulated Data Link Type"},
                {"eapol", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") || isProtocol(p, "EAP") || p.ether_type == 0x888E) o.addU(1); }, "IEEE 802.1X / EAPOL packet"},
                {"eapol.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") || isProtocol(p, "EAP") || p.ether_type == 0x888E) o.addU(p.app_type); }, "802.1X packet type (0 = EAP, 1 = Start, 2 = Logoff, 3 = Key)"},
                {"eapol.keydes.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") && p.app_type == 3) o.addU(p.app_code); }, "EAPOL-Key descriptor type (1 = RC4, 2 = RSN, 254 = WPA)"},
                {"eapol.keydes.msgnr", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAPOL") && p.app_type == 3 && p.app_flags != 0) o.addU(p.app_flags); }, "WPA 4-way handshake message number (1, 2, 3, 4)"},
                {"eap", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") || (isProtocol(p, "EAPOL") && p.app_type == 0)) o.addU(1); }, "Extensible Authentication Protocol"},
                {"eap.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_code != 0) o.addU(p.app_code); }, "EAP code (1 = Request, 2 = Response, 3 = Success, 4 = Failure)"},
                {"eap.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_flags != 0) o.addU(p.app_flags); }, "EAP type (1 = Identity, 13 = TLS, 25 = PEAP, 43 = FAST)"},
                {"eap.identity", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "EAP") && p.app_flags == 1 && !p.app_text.empty()) o.addS(p.app_text); }, "EAP Identity username/string"},
                {"llc", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLlc(p)) o.addU(1); }, "IEEE 802.2 Logical-Link Control"},
                {"llc.dsap", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "LLC") || isProtocol(p, "SNAP")) o.addU(p.app_type); else if (isStp(p)) o.addU(0x42); }, "LLC Destination Service Access Point (DSAP)"},
                {"llc.ssap", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "LLC") || isProtocol(p, "SNAP")) o.addU(p.app_flags & 0xFF); else if (isStp(p)) o.addU(0x42); }, "LLC Source Service Access Point (SSAP)"},
                {"llc.control", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "LLC") || isProtocol(p, "SNAP")) o.addU(p.app_code); else if (isStp(p)) o.addU(0x03); }, "LLC Control Field"},
                {"snap", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isSnap(p)) o.addU(1); }, "Subnetwork Access Protocol (SNAP)"},
                {"snap.oui", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isSnap(p)) o.addU(p.tcp_pdu_start); }, "SNAP Organizationally Unique Identifier (OUI)"},
                {"snap.type", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isSnap(p) && p.ether_type != 0) o.addU(p.ether_type); }, "SNAP Protocol ID / EtherType"},
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
                {"ppp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isPpp(p)) o.addU(1); }, "Point-to-Point Protocol"},
                {"ppp.protocol", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (!isMpls(p) && p.ppp_protocol != 0) o.addU(p.ppp_protocol); }, "PPP Protocol ID (0x0021 = IPv4, 0x0057 = IPv6, 0xc021 = LCP, 0x8021 = IPCP)"},
                {"ppp.lcp.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (!isMpls(p) && (p.ppp_protocol == 0xc021 || isProtocol(p, "LCP"))) o.addU(p.app_type); }, "LCP Code (1 = Config-Req, 2 = Config-Ack, etc.)"},
                {"ppp.ipcp.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (!isMpls(p) && (p.ppp_protocol == 0x8021 || isProtocol(p, "IPCP"))) o.addU(p.app_type); }, "IPCP Code"},
                {"pppoe", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p)) o.addU(1); }, "PPP-over-Ethernet (Discovery or Session)"},
                {"pppoed", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.ether_type == 0x8863 || isProtocol(p, "PPPoED")) o.addU(1); }, "PPPoE Discovery Stage"},
                {"pppoes", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (p.ether_type == 0x8864 || isProtocol(p, "PPPoES") || (p.link_type == 1 && isPpp(p))) o.addU(1); }, "PPPoE Session Stage"},
                {"pppoe.code", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p)) o.addU(p.pppoe_code); }, "PPPoE Code (0x00 = Session, 0x09 = PADI, 0x07 = PADO, 0x19 = PADR, 0x65 = PADS, 0xa7 = PADT)"},
                {"pppoe.session_id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p)) o.addU(p.pppoe_session_id); }, "PPPoE Session ID"},
                {"pppoe.service_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p) && !p.app_text.empty()) o.addS(p.app_text); }, "PPPoE Service-Name tag"},
                {"pppoe.ac_name", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isPppoe(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "PPPoE Access Concentrator (AC) Name tag"},
                {"mpls", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU(1); }, "MultiProtocol Label Switching"},
                {"mpls.label", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU((p.mplsLse(0) >> 12) & 0xFFFFF); }, "MPLS Label Value (outermost label)"},
                {"mpls.exp", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU((p.mplsLse(0) >> 9) & 0x07); }, "MPLS Experimental (TC) Bits"},
                {"mpls.ttl", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU(p.mplsLse(0) & 0xFF); }, "MPLS Time To Live"},
                {"mpls.bottom_of_stack", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p)) o.addU((p.mplsLse(0) >> 8) & 0x01); }, "MPLS Bottom of Stack flag (outermost label)"},
                {"mpls.label1", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMpls(p) && !((p.mplsLse(0) >> 8) & 0x01)) o.addU((p.mplsLse(1) >> 12) & 0xFFFFF); }, "MPLS Label Value (second label in the stack)"},
                {"ipip", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isIpip(p)) o.addU(1); }, "IP-in-IP tunnel (protocol 4 or 41)"},
                {"gre", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU(1); }, "Generic Routing Encapsulation"},
                {"gre.proto", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU(p.gre_proto); }, "GRE Protocol Type (0x0800 = IPv4, 0x86DD = IPv6, 0x6558 = Ethernet, 0x880B = PPP)"},
                {"gre.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU(p.gre_flags & 0x0007); }, "GRE Version (0 = RFC 2784, 1 = Enhanced GRE/RFC 2637)"},
                {"gre.flags.checksum", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x8000) ? 1 : 0); }, "GRE Checksum present flag"},
                {"gre.flags.routing", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x4000) ? 1 : 0); }, "GRE Routing present flag"},
                {"gre.flags.key", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x2000) ? 1 : 0); }, "GRE Key present flag"},
                {"gre.flags.sequence", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p)) o.addU((p.gre_flags & 0x1000) ? 1 : 0); }, "GRE Sequence Number present flag"},
                {"gre.key", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p) && (p.gre_flags & 0x2000)) o.addU(p.gre_key); }, "GRE Key (low 16 bits)"},
                {"gre.sequence_number", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isGre(p) && (p.gre_flags & 0x1000)) o.addU(p.gre_seq); }, "GRE Sequence Number (low 16 bits)"},
                {"lldp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p)) o.addU(1); }, "Link Layer Discovery Protocol"},
                {"lldp.chassis_id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p) && !p.app_text.empty()) o.addS(p.app_text); }, "LLDP Chassis ID"},
                {"lldp.port_id", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "LLDP Port ID"},
                {"lldp.ttl", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p)) o.addU(p.app_code); }, "LLDP Time To Live in seconds"},
                {"lldp.capabilities", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLldp(p)) o.addU(p.app_flags); }, "LLDP System Capabilities (enabled bits)"},
                {"lacp", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(1); }, "Link Aggregation Control Protocol"},
                {"lacp.actor.system", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p) && !p.app_text.empty()) o.addS(p.app_text); }, "LACP Actor System ID (MAC)"},
                {"lacp.partner.system", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p) && !p.app_text2.empty()) o.addS(p.app_text2); }, "LACP Partner System ID (MAC)"},
                {"lacp.actor.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(p.app_type); }, "LACP Actor Port number"},
                {"lacp.partner.port", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(p.app_code); }, "LACP Partner Port number"},
                {"lacp.actor.state", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU(p.app_flags & 0xFF); }, "LACP Actor State byte"},
                {"lacp.partner.state", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags >> 8) & 0xFF); }, "LACP Partner State byte"},
                {"lacp.actor.state.activity", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x01) ? 1 : 0); }, "LACP Actor Activity bit"},
                {"lacp.actor.state.synchronization", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x08) ? 1 : 0); }, "LACP Actor Synchronization bit"},
                {"lacp.actor.state.collecting", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x10) ? 1 : 0); }, "LACP Actor Collecting bit"},
                {"lacp.actor.state.distributing", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isLacp(p)) o.addU((p.app_flags & 0x20) ? 1 : 0); }, "LACP Actor Distributing bit"},
                {"mac_control", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p)) o.addU(1); }, "Ethernet MAC Control"},
                {"mac_control.opcode", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p)) o.addU(p.app_code); }, "MAC Control opcode (0x0001 PAUSE, 0x0101 PFC)"},
                {"pause", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0001) o.addU(1); }, "Ethernet PAUSE frame"},
                {"pause.time", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0001) o.addU(p.app_type); }, "PAUSE time (units of 512 bit times)"},
                {"pfc", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0101) o.addU(1); }, "Priority Flow Control frame"},
                {"pfc.class_enable", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (isMacControl(p) && p.app_code == 0x0101) o.addU(p.app_type); }, "PFC Class Enable Vector"},
                {"bt.handle", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (!isBluetooth(p)) return; for (const std::string *a: {&p.source, &p.destination}) if (a->rfind("0x", 0) == 0) o.addS(*a); }, "Bluetooth ACL connection handle (0x0040 form)"},
                {"bt.addr", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (!isBluetooth(p)) return; if (!p.source.empty()) o.addS(p.source); if (!p.destination.empty()) o.addS(p.destination); }, "Bluetooth source or destination: host, controller (hciN), or a connection handle"},
                {"usb", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isUsb(p)) o.addU(1); }, "USB packet"},
                {"usb.device", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { if (!isUsb(p)) return; for (const std::string *a: {&p.source, &p.destination}) if (!a->empty() && *a != "host") o.addS(*a); }, "USB device address (bus.device)"},
            };
            return t;
        }

        // The built-in table: every field module, registered once. Built on first use (before any filter is compiled and
        // before any packet is dissected) and never changed afterwards, so findField() pointers into it stay valid for the
        // life of the process. registerField() is for fields added later (plugins, tests): it keeps them in a deque,
        // whose elements never move, behind a mutex, and never touches the built table.
        const std::vector<FieldDef> &baseTable() {
            static const std::vector<FieldDef> table = [] {
                FieldRegistry registry;
                registerBuiltinFields(registry);
                registry.addAll(legacyRows());
                if (!registry.problems().empty()) {
                    for (const auto &problem: registry.problems()) std::fprintf(stderr, "imshark: filter field table: %s\n", problem.c_str());
                    std::abort();
                }
                return registry.sorted();
            }();
            return table;
        }

        std::mutex &customMutex() {
            static std::mutex m;
            return m;
        }

        std::deque<FieldDef> &customFields() {
            static std::deque<FieldDef> list;
            return list;
        }

        const FieldDef *findBase(std::string_view lowerName) {
            const auto &t = baseTable();
            const auto it = std::lower_bound(t.begin(), t.end(), lowerName,
                                             [](const FieldDef &f, std::string_view n) { return std::string_view(f.name) < n; });
            return (it != t.end() && std::string_view(it->name) == lowerName) ? &*it : nullptr;
        }
    } // namespace

    bool FieldRegistry::add(const FieldDef &field) {
        if (field.name == nullptr || *field.name == '\0' || field.extract == nullptr) {
            problems_.push_back(std::string("incomplete field definition: ") + (field.name ? field.name : "(no name)"));
            return false;
        }
        for (const auto &f: fields_) {
            if (std::string_view(f.name) == field.name) {
                problems_.push_back(std::string("duplicate field name: ") + field.name);
                return false;
            }
        }
        fields_.push_back(field);
        return true;
    }

    std::vector<FieldDef> FieldRegistry::sorted() const {
        std::vector<FieldDef> out = fields_;
        std::sort(out.begin(), out.end(), [](const FieldDef &a, const FieldDef &b) { return std::string_view(a.name) < b.name; });
        return out;
    }

    void initFields() { baseTable(); }

    std::vector<FieldDef> allFields() {
        std::vector<FieldDef> all = baseTable();
        {
            std::lock_guard<std::mutex> lock(customMutex());
            all.insert(all.end(), customFields().begin(), customFields().end());
        }
        std::sort(all.begin(), all.end(), [](const FieldDef &a, const FieldDef &b) { return std::string_view(a.name) < b.name; });
        return all;
    }

    std::vector<FieldDef> builtinFields() { return baseTable(); }

    bool registerField(FieldDef field) {
        if (field.name == nullptr || *field.name == '\0' || field.extract == nullptr) return false;
        const std::string_view name = field.name;
        if (findBase(name) != nullptr) return false;
        std::lock_guard<std::mutex> lock(customMutex());
        for (const auto &f: customFields()) {
            if (std::string_view(f.name) == name) return false;
        }
        customFields().push_back(field);
        return true;
    }

    const FieldDef *findField(std::string_view lowerName) {
        if (const FieldDef *f = findBase(lowerName)) return f;
        std::lock_guard<std::mutex> lock(customMutex());
        for (const auto &f: customFields()) {
            if (std::string_view(f.name) == lowerName) return &f;
        }
        return nullptr;
    }
} // namespace filter
