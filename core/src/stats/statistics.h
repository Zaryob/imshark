#pragma once

// Capture statistics computed from packet summaries only (no file access): endpoints, conversations and
// the protocol hierarchy. Every function takes an optional `subset` (indices of the packets to include,
// e.g. the ones that pass the display filter); nullptr means all packets.

#include <cstdint>
#include <string>
#include <vector>

#include <packet/ethernet_table.h>
#include <packet/packet_info.h>

namespace stats {
    enum class AddressKind {
        Ipv4,       // IPv4 addresses
        Ipv6,       // IPv6 addresses
        Tcp,        // address + TCP port
        Udp,        // address + UDP port
        Sctp,       // address + SCTP port (ROADMAP B8)
        Ethernet,   // Ethernet MAC addresses
        Wlan,       // IEEE 802.11 MAC addresses (ROADMAP B8)
        Bluetooth,  // Bluetooth endpoints / Connection handles (ROADMAP B8)
        Usb,        // USB device / bus endpoints (ROADMAP B8)
    };

    constexpr size_t kAddressKindCount = 9;

    const char *kindName(AddressKind kind);
    bool hasPort(AddressKind kind);

    using Subset = const std::vector<uint32_t> *;

    struct Endpoint {
        std::string address;
        uint16_t port = 0;           // 0 for the IP kinds
        uint64_t packets = 0, bytes = 0;
        uint64_t txPackets = 0, txBytes = 0;   // sent by this endpoint
        uint64_t rxPackets = 0, rxBytes = 0;   // received by this endpoint
    };

    /// A conversation is the traffic between two endpoints. A is the sender of the first packet.
    struct Conversation {
        std::string addressA, addressB;
        uint16_t portA = 0, portB = 0;         // 0 for the IP kinds
        uint64_t packets = 0, bytes = 0;
        uint64_t packetsAtoB = 0, bytesAtoB = 0;
        uint64_t packetsBtoA = 0, bytesBtoA = 0;
        double start = 0;                      // time of the first packet (seconds since capture start)
        double duration = 0;                   // last - first
        int firstPacket = 0;                   // number of the first packet
    };

    /// Endpoints of `kind`, sorted by bytes (descending). `macs` (the capture's Ethernet address table, optional) adds the
    /// Ethernet frames whose summary holds IP addresses to the Ethernet kind; without it that kind lists only the frames the
    /// summary still holds MAC addresses for (not IP packets).
    std::vector<Endpoint> endpoints(const std::vector<packet::PacketInfo> &packets, Subset subset, AddressKind kind,
                                    const packet::EthernetAddressTable *macs = nullptr);

    /// Conversations of `kind`, sorted by bytes (descending).
    std::vector<Conversation> conversations(const std::vector<packet::PacketInfo> &packets, Subset subset, AddressKind kind,
                                            const packet::EthernetAddressTable *macs = nullptr);

    /// Display filter expression that selects exactly the packets of `conversation`.
    std::string conversationFilter(const Conversation &conversation, AddressKind kind);

    /// Display filter expression for one endpoint.
    std::string endpointFilter(const Endpoint &endpoint, AddressKind kind);

    enum class Severity { Chat, Note, Warn, Error };
    const char *severityName(Severity severity);

    /// One line of the expert summary: a class of finding, how many packets have it, and the display
    /// filter that selects them.
    struct ExpertItem {
        Severity severity;
        std::string summary;
        std::string filter;
        uint64_t count = 0;
    };

    /// Counts the well-known findings (malformed packets, TCP retransmissions, lost segments, resets, ...)
    /// over `subset`. Only items that occur are returned, most severe first.
    std::vector<ExpertItem> expertInfo(const std::vector<packet::PacketInfo> &packets, Subset subset, double captureStartEpoch = 0);

    struct HierarchyNode {
        std::string name;
        uint64_t packets = 0, bytes = 0;
        std::vector<HierarchyNode> children;   // sorted by bytes (descending)
    };

    /// "Frame" -> link layer -> network -> transport -> application, with packet and byte counts.
    HierarchyNode protocolHierarchy(const std::vector<packet::PacketInfo> &packets, Subset subset);
} // namespace stats
