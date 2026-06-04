#pragma once

// Building blocks shared by the per-protocol field modules (dissect/*_fields.cpp): protocol gates and the
// extractor templates that several protocols use. Everything here is stateless.

#include <string>
#include <string_view>

#include <dissect/checksum.h>
#include <dissect/tls_summary.h>
#include <filter/fields.h>
#include <network/address.h>

namespace filter::fh {
    // inside the helpers and the modules `PacketInfo` is short for packet::PacketInfo
    using packet::PacketInfo;

    inline bool ipv4(const PacketInfo &p) { return p.ip_version == 4; }
    // ONC RPC and the programs that name their own protocol (NFS, Portmap, Mount)
    inline bool isRpc(const PacketInfo &p) { return p.protocol == "RPC" || p.protocol == "NFS" || p.protocol == "NFSv4" || p.protocol == "Portmap" || p.protocol == "Mount"; }
    inline bool isRpcCall(const PacketInfo &p) { return isRpc(p) && (p.app_flags & 1) == 0 && !p.app_text.empty(); }
    inline bool ipv6(const PacketInfo &p) { return p.ip_version == 6; }
    // a fragment that is not the last one carries no complete TCP/UDP header to speak of
    inline bool hasTcp(const PacketInfo &p) { return p.ip_version != 0 && p.ip_protocol == 6 && p.ip_frag != 1; }
    inline bool hasUdp(const PacketInfo &p) { return p.ip_version != 0 && p.ip_protocol == 17 && p.ip_frag != 1; }

    // protocol presence: one value (1) when present, none otherwise
    template<bool (*Present)(const PacketInfo &)>
    void proto(const PacketInfo &p, const Context &, Values &out) { if (Present(p)) out.addU(1); }

    inline bool isProtocol(const PacketInfo &p, const char *name) { return p.protocol == name; }
    // Bluetooth and USB packets carry their own kind of address in source/destination (see dissect/bluetooth.cpp, usb.cpp)
    inline bool isBluetooth(const PacketInfo &p) {
        return p.link_type == 187 || p.link_type == 254 || p.protocol == "HCI" || p.protocol == "BT Mon" ||
               p.protocol == "L2CAP" || p.protocol == "ATT";
    }
    inline bool isUsb(const PacketInfo &p) { return p.link_type == 189 || p.link_type == 220 || p.link_type == 249 || isProtocol(p, "USB"); }
    // An IP dissector replaces source/destination with the IP addresses: only a frame that still holds MAC addresses has Ethernet ones
    inline bool hasMacAddresses(const PacketInfo &p) { return p.link_type == 1 && p.ip_version == 0; }
    inline bool isStp(const PacketInfo &p) { return isProtocol(p, "STP") || isProtocol(p, "RSTP") || isProtocol(p, "MSTP"); }
    inline bool isSnap(const PacketInfo &p) { return p.has_snap || isProtocol(p, "SNAP"); }
    inline bool isLlc(const PacketInfo &p) { return p.has_llc || isProtocol(p, "LLC") || isSnap(p) || isStp(p); }
    // mpls_lse* and gre_* share union storage with the PPP/PPPoE fields: those must be excluded first.
    inline bool isMpls(const PacketInfo &p) { return p.ether_type == 0x8847 || p.ether_type == 0x8848 || isProtocol(p, "MPLS"); }
    inline bool isGre(const PacketInfo &p) { return p.has_gre || isProtocol(p, "GRE") || p.protocol.rfind("ERSPAN", 0) == 0; }
    inline bool isIpip(const PacketInfo &p) { return p.has_ipip || isProtocol(p, "IP-in-IP"); }
    inline bool isLldp(const PacketInfo &p) { return p.ether_type == 0x88CC || isProtocol(p, "LLDP"); }
    inline bool isLacp(const PacketInfo &p) { return isProtocol(p, "LACP"); }
    inline bool isMacControl(const PacketInfo &p) { return p.ether_type == 0x8808 || isProtocol(p, "MAC Control"); }
    inline bool isPppoe(const PacketInfo &p) {
        if (isMpls(p) || isGre(p)) return false;
        return p.ether_type == 0x8863 || p.ether_type == 0x8864 ||
               isProtocol(p, "PPPoED") || isProtocol(p, "PPPoES") ||
               (p.link_type == 1 && (p.pppoe_session_id != 0 || p.pppoe_code != 0 || p.ppp_protocol != 0));
    }
    inline bool isPpp(const PacketInfo &p) {
        if (isMpls(p) || isGre(p)) return false;
        return p.link_type == 9 || p.ppp_protocol != 0 ||
               isProtocol(p, "PPP") || isProtocol(p, "LCP") || isProtocol(p, "IPCP") ||
               isProtocol(p, "IPv6CP") || isProtocol(p, "PAP") || isProtocol(p, "CHAP");
    }

    // Wireshark's numbering of *.checksum.status: 0 = bad, 1 = good, 2 = unverified, 3 = not present
    inline uint32_t checksumStatusNumber(uint8_t state) { return state == dissect::kChecksumBad ? 0 : state == dissect::kChecksumGood ? 1 : state == dissect::kChecksumUnverified ? 2 : 3; }

    // DNP3 keeps two 2-bit states in app_flags (dissectDnp3): bits 0-1 link header CRC, bits 2-3 all data block CRCs
    inline uint8_t dnp3CrcState(const PacketInfo &p, bool header, bool data) {
        const uint8_t h = header ? (p.app_flags & 3) : dissect::kChecksumNone, d = data ? ((p.app_flags >> 2) & 3) : dissect::kChecksumNone;
        if (h == dissect::kChecksumBad || d == dissect::kChecksumBad) return dissect::kChecksumBad;
        if (h == dissect::kChecksumUnverified || d == dissect::kChecksumUnverified) return dissect::kChecksumUnverified;
        return h == dissect::kChecksumGood || d == dissect::kChecksumGood ? dissect::kChecksumGood : dissect::kChecksumNone;
    }

    inline std::string_view httpMethodName(uint16_t code) {
        static const char *names[] = {"", "GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE"};
        return code < sizeof(names) / sizeof(*names) ? names[code] : "";
    }

    template<uint8_t Bit>
    void tcpFlag(const PacketInfo &p, const Context &, Values &out) { if (hasTcp(p)) out.addU((p.tcp_flags & Bit) ? 1 : 0); }

    // TCP analysis flag (network::TcpAnalysisFlag bit): 0/1 for TCP packets, absent otherwise
    template<uint16_t Bit>
    void tcpAnalysis(const PacketInfo &p, const Context &, Values &out) { if (hasTcp(p)) out.addU((p.tcp_analysis & Bit) ? 1 : 0); }

    inline void addr(const PacketInfo &p, const Context &, Values &out, bool wantV6, bool src, bool dst) {
        if (p.ip_version != (wantV6 ? 6 : 4)) return;
        if (src) if (auto a = network::parseIpAddress(p.source)) out.addA(*a);
        if (dst) if (auto a = network::parseIpAddress(p.destination)) out.addA(*a);
    }
} // namespace filter::fh
