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

        /// (fragment packet number, packet number that completed its datagram) pairs found since the last
        /// call. The file reader uses them to annotate the earlier fragments.
        std::vector<std::pair<uint32_t, uint32_t>> takeCompletedReassemblies() { return std::move(completed_); }

        /// For Replay mode of the last fragment of a datagram: the reassembled payload and the numbers of
        /// the packets it came from (the pointers must stay valid during parsePacket).
        void setReassembly(const std::vector<char> *payload, const std::vector<uint32_t> *fragmentNumbers, uint8_t protocol) {
            reassembledPayload_ = payload;
            fragmentNumbers_ = fragmentNumbers;
            reassembledProtocol_ = protocol;
        }

    private:
        const dissect::Registry *registry_;
        network::IpReassembler reassembler_;
        std::vector<std::pair<uint32_t, uint32_t>> completed_;
        const std::vector<char> *reassembledPayload_ = nullptr;
        const std::vector<uint32_t> *fragmentNumbers_ = nullptr;
        uint8_t reassembledProtocol_ = 0;
    };
} // namespace packet
