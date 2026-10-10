// Fuzzes the dissection of one captured frame: link layer, network, transport and every application dissector.
//
// Input: byte 0 selects the link type (fuzz_common.h: kLinkTypes), byte 1 holds option bits (0x01 ESP-NULL heuristic,
// 0x02 four FCS bytes, 0x04 the frame was truncated on the wire), the rest is the frame.
//
// Per input the frame goes through
//  - a Full parse (summary + field tree) whose tree must stay inside the frame,
//  - a Summary parse of the same bytes by the same parser (the load pass keeps TCP / reassembly state between packets),
//  - a Replay parse against the frozen session tables, as the details pane does, and
//  - every extractor of the display filter field table on the resulting summaries.

#include <cstddef>
#include <cstdint>
#include <vector>

#include <dissect/context.h>
#include <filter/fields.h>
#include <packet/packet_info.h>
#include <packet/packet_parser.h>

#include "fuzz_common.h"

namespace {
    constexpr size_t kMaxInput = 70000; // a jumbo frame plus the two selector bytes

    void walkFields(const packet::PacketInfo &pack, const dissect::SessionTables &sessions) {
        static const std::vector<filter::FieldDef> fields = filter::builtinFields();
        filter::Context context;
        context.ethernet = &sessions.ethernetAddresses();
        context.ipsec = &sessions.ipsecHeaders();
        for (const auto &field: fields) {
            filter::Values values;
            field.extract(pack, context, values);
            FUZZ_CHECK(values.n >= 0 && values.n <= 2);
        }
    }
} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 2 || size > kMaxInput) return 0;
    const uint32_t linkType = fuzz::linkTypeFor(data[0]);
    const uint8_t options = data[1];
    const std::vector<char> frame(reinterpret_cast<const char *>(data) + 2, reinterpret_cast<const char *>(data) + size);

    packet::PacketParser parser;
    parser.sessions().setEspNullHeuristic((options & 0x01) != 0);

    auto prepare = [&](int number) {
        packet::PacketInfo pack(number);
        pack.link_type = linkType;
        pack.captured_length = static_cast<uint32_t>(frame.size());
        pack.frame_length = static_cast<uint32_t>(frame.size()) + ((options & 0x04) ? 100 : 0);
        pack.fcs_length = (options & 0x02) ? 4 : 0;
        return pack;
    };

    // Full: the field tree is part of the contract (offsets inside the frame)
    packet::PacketInfo full = prepare(1);
    parser.parsePacket(full, frame, dissect::ParseMode::Full);
    for (const auto &field: full.fields) FUZZ_CHECK(fuzz::fieldsInside(field, frame.size()));
    walkFields(full, parser.sessions());

    // Summary: the same frame again as a second packet of the capture (retransmission / duplicate fragment paths)
    packet::PacketInfo summary = prepare(2);
    parser.parsePacket(summary, frame, dissect::ParseMode::Summary);
    for (const auto &field: summary.fields) std::fprintf(stderr, "summary parse built a field: %s\n", field.text.c_str());
    FUZZ_CHECK(summary.fields.empty());
    walkFields(summary, parser.sessions());

    // Replay: details of a loaded packet are built with frozen tables and a fresh parser
    parser.sessions().freeze();
    packet::PacketParser replayParser;
    replayParser.setSessions(&parser.sessions());
    packet::PacketInfo replay = summary;
    replayParser.parsePacket(replay, frame, dissect::ParseMode::Replay);
    for (const auto &field: replay.fields) FUZZ_CHECK(fuzz::fieldsInside(field, frame.size()));
    walkFields(replay, parser.sessions());
    return 0;
}
