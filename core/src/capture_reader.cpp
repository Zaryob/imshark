#include "capture_reader.h"

#include <core.h>

core::CaptureReader::CaptureReader(const std::string &filepath)
    : file_(pathFromUtf8(filepath), std::ios::binary) {}

bool core::CaptureReader::read(const packet::PacketInfo &summary, std::vector<char> &out) {
    if (!file_.is_open()) return false;
    file_.clear(); // a previous short read must not poison the next one
    file_.seekg(static_cast<std::streamoff>(summary.file_offset));
    out.resize(summary.captured_length);
    return summary.captured_length == 0 || file_.read(out.data(), summary.captured_length).good();
}

bool core::scanPackets(const std::string &filepath, const std::vector<packet::PacketInfo> &packets,
                       const std::vector<uint32_t> &order,
                       const std::function<bool(const packet::PacketInfo &, const std::vector<char> &)> &visit,
                       ScanControl *control) {
    CaptureReader reader(filepath);
    if (!reader.isOpen()) return false;
    if (control) {
        control->total = order.size();
        control->done = 0;
    }
    std::vector<char> frame;
    uint64_t n = 0;
    for (uint32_t index: order) {
        if (control && control->cancelRequested) return false;
        if (index < packets.size() && reader.read(packets[index], frame)) {
            if (!visit(packets[index], frame)) break;
        }
        if (control && (++n & 0xFF) == 0) control->done = n;
    }
    if (control) control->done = order.size();
    return true;
}
