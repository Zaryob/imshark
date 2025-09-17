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

bool core::reassembleTcpPdu(CaptureReader &reader, const std::vector<packet::PacketInfo> &packets, const packet::PacketInfo &completing,
                            std::string &pdu, std::vector<uint32_t> &numbers) {
    const uint32_t start = completing.tcp_pdu_start, length = completing.tcp_pdu_len;
    if (completing.tcp_pdu_state != 2 || length == 0) return false;
    pdu.assign(length, '\0');
    std::vector<bool> filled(length, false);
    numbers.clear();
    std::vector<char> frame, whole;

    for (const auto &p: packets) {
        if (p.ip_protocol != 6 || p.ip_version != completing.ip_version || p.ip_frag == 1 || p.tcp_relative_seq < 0 || p.payload_length == 0) continue;
        if (p.source != completing.source || p.destination != completing.destination || p.src_port != completing.src_port ||
            p.dst_port != completing.dst_port) continue;
        // position of the segment's first byte relative to the message start (wrap-around safe)
        const int32_t first = static_cast<int32_t>(static_cast<uint32_t>(p.tcp_relative_seq) - start);
        if (first >= static_cast<int64_t>(length) || static_cast<int64_t>(first) + p.payload_length <= 0) continue;   // no overlap

        const char *bytes = nullptr;
        if (p.ip_frag == 2) {   // the TCP segment was reassembled from IP fragments: its payload is not in the frame
            if (!reassembleIpPayload(reader, packets, p, whole) || static_cast<uint64_t>(p.payload_offset) + p.payload_length > whole.size()) return false;
            bytes = whole.data() + p.payload_offset;
        } else {
            if (!reader.read(p, frame) || static_cast<uint64_t>(p.payload_offset) + p.payload_length > frame.size()) return false;
            bytes = frame.data() + p.payload_offset;
        }
        bool contributed = false;
        for (uint32_t i = 0; i < p.payload_length; ++i) {
            const int64_t at = static_cast<int64_t>(first) + i;
            if (at < 0 || at >= length || filled[static_cast<size_t>(at)]) continue;
            pdu[static_cast<size_t>(at)] = bytes[i];
            filled[static_cast<size_t>(at)] = true;
            contributed = true;
        }
        if (contributed) numbers.push_back(static_cast<uint32_t>(p.number));
    }
    return std::find(filled.begin(), filled.end(), false) == filled.end();
}
