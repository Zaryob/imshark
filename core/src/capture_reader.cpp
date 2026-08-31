#include "capture_reader.h"

#include <algorithm>

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

namespace {
    // The IP fragment (payload slice + flags) carried by a captured frame: IPv4 or IPv6 (Fragment Header).
    bool readFragment(const std::vector<char> &frame, const packet::PacketInfo &p, network::IpFragment &out) {
        const size_t ip = p.l2_size;
        const auto u8 = [&](size_t i) { return static_cast<uint8_t>(frame[ip + i]); };
        out.packetNumber = static_cast<uint32_t>(p.number);
        out.time = p.time;

        if (p.ip_version == 4) {
            if (frame.size() < ip + 20) return false;
            const size_t ihl = static_cast<size_t>(u8(0) & 0x0F) * 4;
            const size_t total = (static_cast<size_t>(u8(2)) << 8) | u8(3);
            const uint16_t field = static_cast<uint16_t>((u8(6) << 8) | u8(7));
            if (ihl < 20 || total < ihl || frame.size() < ip + ihl) return false;
            const size_t end = std::min(frame.size(), ip + total);
            out.offset = (field & 0x1FFF) * 8u;
            out.moreFragments = (field & 0x2000) != 0;
            out.protocol = u8(9);
            out.data.assign(frame.begin() + static_cast<std::ptrdiff_t>(ip + ihl), frame.begin() + static_cast<std::ptrdiff_t>(end));
            return true;
        }
        if (p.ip_version == 6) {
            if (frame.size() < ip + 40) return false;
            const size_t payloadEnd = std::min(frame.size(), ip + 40 + ((static_cast<size_t>(u8(4)) << 8) | u8(5)));
            uint8_t next = u8(6);
            size_t pos = ip + 40;
            while (next == 0 || next == 43 || next == 51 || next == 60) { // headers in front of the Fragment Header
                if (pos + 8 > payloadEnd) return false;
                const size_t len = next == 51 ? (static_cast<size_t>(static_cast<uint8_t>(frame[pos + 1])) + 2) * 4
                                              : (static_cast<size_t>(static_cast<uint8_t>(frame[pos + 1])) + 1) * 8;
                next = static_cast<uint8_t>(frame[pos]);
                pos += len;
            }
            if (next != 44 || pos + 8 > payloadEnd) return false;
            const uint16_t field = static_cast<uint16_t>((static_cast<uint8_t>(frame[pos + 2]) << 8) | static_cast<uint8_t>(frame[pos + 3]));
            out.offset = static_cast<uint32_t>(field >> 3) * 8;
            out.moreFragments = (field & 1) != 0;
            out.protocol = static_cast<uint8_t>(frame[pos]);
            out.data.assign(frame.begin() + static_cast<std::ptrdiff_t>(pos + 8), frame.begin() + static_cast<std::ptrdiff_t>(payloadEnd));
            return true;
        }
        return false;
    }
} // namespace

bool core::reassembleIpPayload(CaptureReader &reader, const std::vector<packet::PacketInfo> &packets,
                               const packet::PacketInfo &completing, std::vector<char> &payload,
                               std::vector<uint32_t> *fragmentNumbers, uint8_t *protocol) {
    std::vector<network::IpFragment> fragments;
    std::vector<char> frame;
    for (const auto &p: packets) {
        // the earlier fragments were annotated with the packet that completed their datagram while loading
        if (!(p.number == completing.number || (p.ip_frag == 1 && p.reassembled_in == static_cast<uint32_t>(completing.number)))) continue;
        network::IpFragment f;
        if (reader.read(p, frame) && readFragment(frame, p, f)) fragments.push_back(std::move(f));
    }
    if (!network::assembleIpv4Payload(fragments, payload)) return false;

    uint8_t first = 0;
    std::vector<uint32_t> numbers;
    for (const auto &f: fragments) {
        numbers.push_back(f.packetNumber);
        if (f.offset == 0 && first == 0) first = f.protocol;
    }
    std::sort(numbers.begin(), numbers.end());
    numbers.erase(std::unique(numbers.begin(), numbers.end()), numbers.end());
    if (fragmentNumbers) *fragmentNumbers = std::move(numbers);
    if (protocol) *protocol = first;
    return true;
}
