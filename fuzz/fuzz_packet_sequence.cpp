// Fuzzes the stateful half of the parser: TCP / IP / DTLS / datagram reassembly, the TCP connection table and every
// session table (TLS, DTLS, SCTP, DCE/RPC, ONC RPC, SMB2, database protocols, FTP-DATA, TFTP, Ethernet / IPsec
// address tables, USB / Bluetooth links) behave differently on packet 2 than on packet 1, which a single frame
// cannot reach.
//
// Input: byte 0 selects the link type (fuzz_common.h: kLinkTypes), byte 1 holds option bits (0x01 ESP-NULL heuristic),
// then records of  uint16 little endian length, frame bytes  (a last record may be cut short). The frames are fed
// through core::FileProcessor::appendLivePacket, the path every capture takes (summary parse, reassembly annotations
// of earlier packets, session tables), written to a temporary classic pcap at the offsets the processor is told,
// and every packet's details are then built with core::buildPacketDetails, which re-dissects it in Replay mode and
// reads fragments and TCP segments of reassembled messages back from the file.

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include <core.h>
#include <packet/packet_info.h>

#include "fuzz_common.h"

namespace {
    constexpr size_t kMaxInput = 256 * 1024;
    constexpr size_t kMaxPackets = 256;
    constexpr uint32_t kMaxFrame = 65535;

    void put32(std::vector<uint8_t> &out, uint32_t value) {
        for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(value >> (8 * i)));
    }
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > kMaxInput) return 0;
    const uint32_t linkType = fuzz::linkTypeFor(data[0]);
    const bool espNull = (data[1] & 0x01) != 0;

    // classic pcap in memory: the file the packets "come from"
    std::vector<uint8_t> file = {0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    put32(file, 65535);
    put32(file, linkType);

    core::FileProcessor processor;
    processor.sessions().setEspNullHeuristic(espNull);
    processor.beginLive(linkType, 65535);
    std::vector<packet::PacketInfo> packets;

    size_t pos = 2;
    while (pos + 2 <= size && packets.size() < kMaxPackets) {
        const uint32_t length = static_cast<uint32_t>(data[pos]) | (static_cast<uint32_t>(data[pos + 1]) << 8);
        pos += 2;
        const size_t available = size - pos;
        const size_t take = length < available ? length : available;
        if (take > kMaxFrame) break;
        const std::vector<char> frame(reinterpret_cast<const char *>(data) + pos, reinterpret_cast<const char *>(data) + pos + take);
        pos += take;

        put32(file, static_cast<uint32_t>(packets.size() / 1000 + 1700000000)); // seconds
        put32(file, static_cast<uint32_t>(packets.size() % 1000) * 1000);      // microseconds
        put32(file, static_cast<uint32_t>(take));
        put32(file, static_cast<uint32_t>(take));
        const uint64_t offset = file.size();
        file.insert(file.end(), data + (pos - take), data + pos);

        processor.appendLivePacket(packets, 1700000000 + packets.size() / 1000, static_cast<uint32_t>(packets.size() % 1000) * 1000,
                                   linkType, offset, static_cast<uint32_t>(take), frame);
    }
    if (packets.empty()) return 0;

    fuzz::TempFile capture("sequence.pcap");
    if (!capture.write(file.data(), file.size())) return 0;

    const dissect::Registry &registry = dissect::Registry::builtin();
    for (const auto &summary: packets) {
        packet::PacketInfo details;
        if (!core::buildPacketDetails(capture.path(), summary, details, &packets, &processor.captureInfo(), &registry,
                                      &processor.sessions())) {
            continue;
        }
        for (const auto &field: details.fields) FUZZ_CHECK(fuzz::fieldsInside(field, details.raw_data.size()) || summary.ip_frag == 2 || summary.tcp_pdu_state == 2);
    }
    return 0;
}
