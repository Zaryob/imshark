#pragma once

// "Follow stream": the payload of one TCP or UDP conversation, reassembled in order.

#include <cstdint>
#include <string>
#include <vector>

#include <capture_reader.h>
#include <packet/packet_info.h>

namespace stream {
    enum class Direction { AtoB, BtoA };

    /// A run of payload bytes flowing in one direction. A is the sender of the first packet.
    struct Chunk {
        Direction direction = Direction::AtoB;
        std::string data;
        uint64_t missingBefore = 0;   // bytes that were never captured right before this chunk (TCP gaps)
        int firstPacket = 0;          // number of the packet that delivered the first byte
    };

    struct Stream {
        bool tcp = true;
        std::string addressA, addressB;
        uint16_t portA = 0, portB = 0;
        std::vector<Chunk> chunks;
        int packets = 0;              // packets of the conversation
        uint64_t bytesAtoB = 0, bytesBtoA = 0;
        uint64_t missingBytes = 0;    // total size of the TCP gaps
        bool truncated = false;       // stopped at the size limit
    };

    /// Indices (capture order) of all packets of the TCP/UDP conversation that `packets[index]` belongs to;
    /// empty if that packet is neither TCP nor UDP (or `index` is out of range).
    std::vector<uint32_t> conversationPackets(const std::vector<packet::PacketInfo> &packets, uint32_t index);

    /// Reads the payload of `indices` (ascending capture order) from `capturePath` and reassembles it:
    /// TCP segments are put in sequence order (out-of-order data is held back until the gap fills,
    /// retransmissions and overlaps are dropped, holes become `missingBefore`), UDP datagrams are taken as
    /// they come. Stops after `maxBytes` of output. Returns false if cancelled or the file cannot be read.
    bool reassemble(const std::string &capturePath, const std::vector<packet::PacketInfo> &packets,
                    const std::vector<uint32_t> &indices, Stream &out, core::ScanControl *control = nullptr,
                    uint64_t maxBytes = 256ull * 1024 * 1024);
} // namespace stream
