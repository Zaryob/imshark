// Fuzzes the whole capture loading path the application uses for an untrusted file: gzip unpacking, format detection
// by magic number (pcap, pcapng, Microsoft Network Monitor, Sun snoop, Endace ERF, AIX iptrace), the format reader,
// the packet summaries with their session tables, the statistics and the display filter over the summaries, and the
// details of the first packets rebuilt from the file (Replay mode, reassembled fragments and TCP messages).
//
// Input: the bytes of a capture file. The format is chosen from its first bytes exactly as the application does, so
// the seed corpus holds one small file per format and the dictionaries (fuzz/dict) carry the magic numbers.

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include <core.h>
#include <filter/filter.h>
#include <gzip.h>
#include <load_control.h>
#include <packet/packet_info.h>
#include <stats/statistics.h>

#include "fuzz_common.h"

namespace {
    constexpr size_t kMaxInput = 4u << 20;          // bytes of the (compressed) input file
    constexpr uint64_t kMaxUnpacked = 16u << 20;    // a decompression bomb inside the input is cut off here
    constexpr size_t kMaxDetails = 64;              // packets whose details are rebuilt per input

    void analyse(const std::string &path, const core::FileProcessor &processor, const std::vector<packet::PacketInfo> &packets) {
        const core::CaptureInfo &info = processor.captureInfo();

        // statistics: the windows of the application compute these over the whole capture or the filtered subset
        const packet::EthernetAddressTable *macs = &processor.sessions().ethernetAddresses();
        for (size_t kind = 0; kind < stats::kAddressKindCount; ++kind) {
            const auto addressKind = static_cast<stats::AddressKind>(kind);
            (void) stats::endpoints(packets, nullptr, addressKind, macs);
            (void) stats::conversations(packets, nullptr, addressKind, macs);
        }
        (void) stats::expertInfo(packets, nullptr, processor.captureStartEpoch());
        (void) stats::protocolHierarchy(packets, nullptr);

        // the display filter over the summaries
        static const char *const kFilters[] = {
            "tcp.port in {80 443 8080} || udp || dns || tls || http || sctp",
            "frame.len > 100 && !(tcp.flags.syn == 1) && ip.addr == 10.0.0.0/8",
            "eth.addr == 00:11:22:33:44:55 || info contains \"GET\" || _ws.malformed",
        };
        for (const char *expression: kFilters) {
            const auto compiled = filter::Filter::compile(expression);
            if (!compiled.ok) continue;
            filter::Context context;
            context.captureStartEpoch = processor.captureStartEpoch();
            context.ethernet = macs;
            context.ipsec = &processor.sessions().ipsecHeaders();
            const packet::PacketInfo *previous = nullptr;
            for (const auto &pack: packets) {
                context.previous = previous;
                (void) compiled.filter.matches(pack, context);
                previous = &pack;
            }
        }

        // details: the packets are re-dissected from the file the way the details pane does it
        const size_t count = packets.size() < kMaxDetails ? packets.size() : kMaxDetails;
        for (size_t i = 0; i < count; ++i) {
            packet::PacketInfo details;
            if (!core::buildPacketDetails(path, packets[i], details, &packets, &info, nullptr, &processor.sessions())) continue;
            // a reassembled message is dissected from bytes that are not in this frame: only plain frames are checked
            if (packets[i].ip_frag == 2 || packets[i].tcp_pdu_state == 2) continue;
            for (const auto &field: details.fields) FUZZ_CHECK(fuzz::fieldsInside(field, details.raw_data.size()));
        }
    }
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size == 0 || size > kMaxInput) return 0;

    fuzz::TempFile input("capture.bin");
    if (!input.write(data, size)) return 0;

    // like the loader: a gzip wrapper is unpacked to a second file first (the packets keep file offsets into it)
    fuzz::TempFile unpacked("capture.unpacked");
    std::string path = input.path();
    if (core::detectFileFormat(path) == core::FileFormat::Gzip) {
        std::string error;
        core::LoadControl unpackControl;
        if (!core::gunzipFile(input.path(), unpacked.path(), error, &unpackControl)) return 0;
        std::error_code ec;
        if (std::filesystem::file_size(std::filesystem::path(unpacked.path()), ec) > kMaxUnpacked) return 0;
        path = unpacked.path();
    }

    core::FileProcessor processor;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    core::LoadControl control;
    const bool ok = processor.processFile(path, packets, message, &control);
    if (!ok && packets.empty()) return 0;
    analyse(path, processor, packets);
    return 0;
}
