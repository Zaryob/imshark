// Filter fields of the frame summary columns (B4): declared here, next to the dissector, and registered once at startup from the
// list in filter/field_modules.cpp. The extractors read the summary facts the dissector stores in PacketInfo.
#include <filter/field_helpers.h>
#include <filter/field_modules.h>

namespace filter {
    void registerFrameFields(FieldRegistry &registry) {
        using namespace fh;
        registry.addAll({
            {"frame.number", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { o.addU(static_cast<uint64_t>(p.number)); }, "Packet number (1-based)"},
            {"frame.comment", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { o.addU(p.has_comment); }, "The capture file has a comment for this packet (pcapng)"},
            {"frame.len", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { o.addU(p.frame_length); }, "Length of the frame on the wire"},
            {"frame.cap_len", FieldType::Unsigned, [](const PacketInfo &p, const Context &, Values &o) { o.addU(p.captured_length); }, "Number of bytes captured"},
            {"frame.time_relative", FieldType::Float, [](const PacketInfo &p, const Context &, Values &o) { o.addD(p.time); }, "Seconds since the first packet"},
            {"frame.time_delta", FieldType::Float, [](const PacketInfo &p, const Context &c, Values &o) { o.addD(c.previous ? p.time - c.previous->time : 0.0); }, "Seconds since the previous captured packet"},
            {"frame.time_epoch", FieldType::Float, [](const PacketInfo &p, const Context &c, Values &o) { o.addD(c.captureStartEpoch + p.time); }, "Arrival time as UTC epoch seconds"},
            {"_ws.col.protocol", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { o.addS(p.protocol); }, "Protocol column"},
            {"protocol", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { o.addS(p.protocol); }, "Protocol column (alias of _ws.col.protocol)"},
            {"_ws.col.info", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { o.addS(p.info); }, "Info column"},
            {"info", FieldType::String, [](const PacketInfo &p, const Context &, Values &o) { o.addS(p.info); }, "Info column (alias of _ws.col.info)"},
            {"malformed", FieldType::Boolean, [](const PacketInfo &p, const Context &, Values &o) { if (isProtocol(p, "Malformed") || p.info.find("[Malformed Packet") != std::string::npos) o.addU(1); }, "Packet that could not be fully decoded"},
        });
    }
} // namespace filter
