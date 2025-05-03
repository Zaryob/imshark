//
// Created by Süleyman Poyraz on 12.10.2024.
//

#include <packet/packet_parser.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

#include <dissect/util.h>
#include <network/l2_data_link/ethernet_header.h>
#include <network/utils.h>

namespace {
    using packet::Field;
    using dissect::be16;
    using dissect::hexString;
    using dissect::readStruct;

    std::string etherTypeName(uint16_t type) {
        switch (type) {
            case 0x0800: return "IPv4";
            case 0x86DD: return "IPv6";
            case 0x0806: return "ARP";
            case 0x8035: return "RARP";
            case 0x8100: return "802.1Q VLAN";
            case 0x88A8: return "802.1ad VLAN";
            default: return "unknown";
        }
    }

    std::string linkTypeName(uint32_t type) {
        switch (type) {
            case 0: return "NULL";
            case 1: return "Ethernet";
            case 12:
            case 14:
            case 101: return "Raw IP";
            case 108: return "OpenBSD loopback";
            case 113: return "Linux cooked v1";
            case 276: return "Linux cooked v2";
            default: return "unsupported";
        }
    }


    constexpr uint32_t kLinkNull = 0, kLinkEthernet = 1, kLinkRawBsd = 12, kLinkRawOpenBsd = 14,
            kLinkRaw = 101, kLinkLoop = 108, kLinkLinuxSll = 113, kLinkLinuxSll2 = 276;
} // namespace

void packet::PacketParser::parsePacket(packet::PacketInfo &pack, const std::vector<char> &packetData,
                                       dissect::ParseMode mode) {
    pack.vlan_ids.clear();
    pack.fields.clear();
    pack.protocol.clear();
    pack.info.clear();
    pack.source.clear();
    pack.destination.clear();
    const char *base = packetData.data();
    const size_t len = packetData.size();
    pack.length = static_cast<uint32_t>(len);
    dissect::Context ctx{pack, base, len, connection, *registry_, mode};

    if (ctx.wantFields()) {
        Field &frame = ctx.addLayer("Frame " + std::to_string(pack.number) + ": " + std::to_string(len) + " bytes on wire", 0, len);
        frame.add("Frame Number: " + std::to_string(pack.number));
        frame.add("Frame Length: " + std::to_string(len) + " bytes", 0, len);
        frame.add("Link type: " + std::to_string(pack.link_type) + " (" + linkTypeName(pack.link_type) + ")");
    }

    // Link layer: find out where the network header starts and which protocol it carries.
    uint16_t etherType = 0;
    size_t l3Offset = 0;
    network::EthernetHeader ethHeader{};
    bool haveEthernet = false;

    switch (pack.link_type) {
        case kLinkEthernet: {
            if (!readStruct(base, len, 0, ethHeader)) {
                ctx.markMalformed("frame too short for Ethernet header");
                return;
            }
            haveEthernet = true;
            etherType = network::ntoh16(ethHeader.type);
            l3Offset = sizeof(network::EthernetHeader);
            const uint16_t outerType = etherType;
            // 802.1Q / 802.1ad (QinQ) tags: 2 bytes TCI + 2 bytes inner EtherType each
            while (etherType == 0x8100 || etherType == 0x88A8 || etherType == 0x9100) {
                if (len < l3Offset || len - l3Offset < 4) {
                    ctx.markMalformed("VLAN tag truncated");
                    pack.protocol = "VLAN";
                    pack.l2_size = static_cast<uint16_t>(std::min<size_t>(l3Offset, UINT16_MAX));
                    return;
                }
                pack.vlan_ids.push_back(be16(base + l3Offset) & 0x0FFF);
                etherType = be16(base + l3Offset + 2);
                l3Offset += 4;
            }

            if (ctx.wantFields()) {
                Field &eth = ctx.addLayer("Ethernet II, Src: " + network::getMACAddressString(ethHeader.src_mac) +
                                              ", Dst: " + network::getMACAddressString(ethHeader.dest_mac),
                                          0, l3Offset);
                eth.add("Destination: " + network::getMACAddressString(ethHeader.dest_mac), 0, 6);
                eth.add("Source: " + network::getMACAddressString(ethHeader.src_mac), 6, 6);
                eth.add("Type: " + etherTypeName(outerType) + " (" + hexString(outerType, 4) + ")", 12, 2);
                for (size_t i = 0; i < pack.vlan_ids.size(); ++i) {
                    eth.add("802.1Q Virtual LAN, ID: " + std::to_string(pack.vlan_ids[i]), 14 + 4 * i, 4);
                }
            }
        } break;
        case kLinkNull:
        case kLinkLoop: { // 4-byte address family; byte order of the capturing host (NULL) or network (LOOP)
            if (len < 4) { ctx.markMalformed("frame too short for loopback header"); return; }
            uint32_t af;
            std::memcpy(&af, base, sizeof(af));
            if (pack.link_type == kLinkLoop) af = network::ntoh32(af); // OpenBSD loop: always network order
            else if (af > 0xFFFF) af = network::bswap32(af); // NULL: written by a host of the other endianness
            etherType = af == 2 ? 0x0800 : (af == 10 || af == 24 || af == 28 || af == 30) ? 0x86DD : 0;
            l3Offset = 4;
        } break;
        case kLinkRaw:
        case kLinkRawBsd:
        case kLinkRawOpenBsd: { // no link header: the IP version nibble tells v4 from v6
            if (len < 1) { ctx.markMalformed("empty frame"); return; }
            const uint8_t version = static_cast<uint8_t>(base[0]) >> 4;
            etherType = version == 4 ? 0x0800 : version == 6 ? 0x86DD : 0;
            l3Offset = 0;
        } break;
        case kLinkLinuxSll: { // "cooked" capture v1: 16 bytes, protocol in the last 2
            if (len < 16) { ctx.markMalformed("frame too short for Linux cooked header"); return; }
            etherType = be16(base + 14);
            l3Offset = 16;
        } break;
        case kLinkLinuxSll2: { // "cooked" capture v2: 20 bytes, protocol first
            if (len < 20) { ctx.markMalformed("frame too short for Linux cooked v2 header"); return; }
            etherType = be16(base);
            l3Offset = 20;
        } break;
        default:
            pack.protocol = "Unknown";
            pack.info = "Unsupported link type " + std::to_string(pack.link_type);
            return;
    }
    pack.l2_size = static_cast<uint16_t>(l3Offset);
    if (ctx.wantFields() && !haveEthernet && l3Offset > 0) ctx.addLayer(linkTypeName(pack.link_type) + " link header", 0, l3Offset);

    if (const dissect::Dissector *network = registry_->findEtherType(etherType)) {
        (*network)(ctx, base + l3Offset, len - l3Offset);
        return;
    }

    // Unsupported EtherType: show the frame at least by its MAC addresses.
    pack.protocol = haveEthernet ? "Ethernet" : "Unknown";
    if (haveEthernet) {
        pack.source = network::getMACAddressString(ethHeader.src_mac);
        pack.destination = network::getMACAddressString(ethHeader.dest_mac);
    }
    std::ostringstream oss;
    oss << "EtherType 0x" << std::hex << std::setw(4) << std::setfill('0') << etherType;
    pack.info = oss.str();
    if (ctx.wantFields() && len > l3Offset) ctx.addLayer("Data (" + std::to_string(len - l3Offset) + " bytes)", l3Offset, len - l3Offset);
}
