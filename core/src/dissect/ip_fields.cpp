// Filter fields of IPv4 and IPv6 (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerIpFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"ip", FieldType::Boolean, proto<ipv4>, "IPv4"},
            {"ipv6", FieldType::Boolean, proto<ipv6>, "IPv6"},
            {"ip.version", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(4); }, "IPv4 version"},
            {"ip.ttl", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(p.ttl); }, "IPv4 time to live"},
            {"ip.id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(p.ip_id); }, "IPv4 identification"},
            {"ip.fragment", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(p.ip_frag != 0); }, "IPv4 fragment (part of a fragmented datagram)"},
            {"ip.reassembled", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(p.ip_frag == 2); }, "Last IPv4 fragment: the datagram was reassembled here"},
            {"ipv6.fragment", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p)) o.addU(p.ip_frag != 0); }, "IPv6 fragment (part of a fragmented datagram)"},
            {"ipv6.fragment.id", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p) && p.ip_frag != 0) o.addU(p.ip_id); }, "IPv6 Fragment Header identification"},
            {"ipv6.reassembled", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p)) o.addU(p.ip_frag == 2); }, "Last IPv6 fragment: the datagram was reassembled here"},
            {"ip.proto", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv4(p)) o.addU(p.ip_protocol); }, "IPv4 protocol number"},
            {"ip.src", FieldType::Ipv4, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, false, true, false); }, "IPv4 source address"},
            {"ip.dst", FieldType::Ipv4, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, false, false, true); }, "IPv4 destination address"},
            {"ip.addr", FieldType::Ipv4, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, false, true, true); }, "IPv4 source or destination address"},
            {"ipv6.hlim", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p)) o.addU(p.ttl); }, "IPv6 hop limit"},
            {"ipv6.nxt", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (ipv6(p)) o.addU(p.ip_protocol); }, "IPv6 next header (after extension headers)"},
            {"ipv6.src", FieldType::Ipv6, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, true, true, false); }, "IPv6 source address"},
            {"ipv6.dst", FieldType::Ipv6, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, true, false, true); }, "IPv6 destination address"},
            {"ipv6.addr", FieldType::Ipv6, [](const PacketInfo &p, const Context &c, Values &o) { addr(p, c, o, true, true, true); }, "IPv6 source or destination address"},
            {"ip.checksum.status", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { if (p.ip_version == 4) o.addU(checksumStatusNumber(dissect::ipChecksumState(p))); }, "IPv4 header checksum: 0 = bad, 1 = good, 2 = unverified (offload or truncated), 3 = not present"},
        });
    }
} // namespace filter
