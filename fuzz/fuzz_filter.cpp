// Fuzzes the display filter compiler (core/src/filter/filter.cpp) and the evaluator.
//
// Input: the text of a display filter expression. When it compiles, it is evaluated against a fixed set of sample
// packets (HTTP over TCP, DNS over UDP, ARP) dissected by the real parser, once without and once with the capture
// context (previous packet, epoch, Ethernet address table).

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include <filter/filter.h>
#include <packet/packet_info.h>
#include <packet/packet_parser.h>

#include "fuzz_common.h"

namespace {
    constexpr size_t kMaxInput = 2048; // deeply nested or very long expressions are limited by the UI as well

    using Bytes = std::vector<char>;

    void append(Bytes &out, std::initializer_list<int> bytes) {
        for (int b: bytes) out.push_back(static_cast<char>(b));
    }
    void append(Bytes &out, const std::string &text) { out.insert(out.end(), text.begin(), text.end()); }

    Bytes ipv4Frame(uint8_t protocol, const Bytes &payload) {
        Bytes f;
        append(f, {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x00});
        const size_t total = 20 + payload.size();
        append(f, {0x45, 0x00, int(total >> 8), int(total & 0xff), 0x12, 0x34, 0x40, 0x00, 0x40, protocol, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2});
        f.insert(f.end(), payload.begin(), payload.end());
        return f;
    }

    std::vector<Bytes> sampleFrames() {
        std::vector<Bytes> frames;
        {   // HTTP request in a TCP segment
            const std::string http = "GET /index.html HTTP/1.1\r\nHost: example.test\r\nUser-Agent: fuzz\r\n\r\n";
            Bytes tcp;
            append(tcp, {0xc3, 0x50, 0x00, 0x50, 0, 0, 0, 1, 0, 0, 0, 1, 0x50, 0x18, 0x72, 0x10, 0, 0, 0, 0});
            append(tcp, http);
            frames.push_back(ipv4Frame(6, tcp));
        }
        {   // DNS query for example.test (A)
            Bytes udp;
            append(udp, {0xd4, 0x31, 0x00, 0x35, 0x00, 0x1f, 0, 0});
            append(udp, {0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 7});
            append(udp, "example");
            append(udp, {4});
            append(udp, "test");
            append(udp, {0, 0, 1, 0, 1});
            frames.push_back(ipv4Frame(17, udp));
        }
        {   // ARP request
            Bytes f;
            append(f, {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x08, 0x06});
            append(f, {0, 1, 8, 0, 6, 4, 0, 1, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 10, 0, 0, 2});
            frames.push_back(f);
        }
        return frames;
    }

    const std::vector<packet::PacketInfo> &samples() {
        static const std::vector<packet::PacketInfo> packets = [] {
            std::vector<packet::PacketInfo> result;
            packet::PacketParser parser;
            for (const auto &frame: sampleFrames()) {
                packet::PacketInfo pack(static_cast<int>(result.size()) + 1);
                pack.time = 0.001 * static_cast<double>(result.size());
                pack.captured_length = pack.frame_length = static_cast<uint32_t>(frame.size());
                parser.parsePacket(pack, frame, dissect::ParseMode::Summary);
                result.push_back(std::move(pack));
            }
            return result;
        }();
        return packets;
    }
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size > kMaxInput) return 0;
    const std::string_view text(reinterpret_cast<const char *>(data), size);
    const auto compiled = filter::Filter::compile(text);
    if (!compiled.ok) {
        FUZZ_CHECK(!compiled.error.message.empty());
        FUZZ_CHECK(compiled.error.position <= size);
        return 0;
    }

    const auto &packets = samples();
    for (const auto &pack: packets) (void) compiled.filter.matches(pack);

    filter::Context context;
    context.captureStartEpoch = 1700000000.5;
    const packet::PacketInfo *previous = nullptr;
    for (const auto &pack: packets) {
        context.previous = previous;
        (void) compiled.filter.matches(pack, context);
        previous = &pack;
    }
    return 0;
}
