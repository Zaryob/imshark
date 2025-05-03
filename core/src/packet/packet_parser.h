//
// Created by Süleyman Poyraz on 12.10.2024.
//

#pragma once

#include <vector>

#include <dissect/registry.h>
#include <network/tcp_connection.h>
#include <packet/packet_info.h>

namespace packet {
    /// Decodes one captured frame into a PacketInfo. The link layer is handled here; everything above it is
    /// delegated to the dissectors in `registry` (EtherType -> IP protocol -> port).
    class PacketParser {
    public:
        explicit PacketParser(const dissect::Registry &registry = dissect::Registry::builtin())
            : registry_(&registry) {}

        /// Fills `packet` (protocol, addresses, info and, unless `mode` is Summary, the field tree) from
        /// `packetData`. `packet.link_type` and `packet.number` must be set; nothing is read outside
        /// `packetData`. See dissect::ParseMode.
        void parsePacket(PacketInfo &packet, const std::vector<char> &packetData,
                         dissect::ParseMode mode = dissect::ParseMode::Full);

        /// Per-capture TCP state; use one parser per capture so connections do not leak between files.
        network::TCPConnection connection;

    private:
        const dissect::Registry *registry_;
    };
} // namespace packet
