#include "follow.h"

#include <algorithm>
#include <utility>

namespace stream {
    namespace {
        bool isStreamProtocol(const packet::PacketInfo &p) { return p.ip_version != 0 && (p.ip_protocol == 6 || p.ip_protocol == 17); }

        // One direction of a TCP stream: the next expected relative sequence number and data held back
        struct Half {
            bool started = false;
            uint32_t next = 0;
            std::vector<std::pair<uint32_t, std::string>> pending; // out-of-order segments (relative seq, bytes)
        };

        int32_t diff(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b); }

        class Builder {
        public:
            Builder(Stream &out, uint64_t maxBytes) : out_(out), max_(maxBytes) {}

            bool full() const { return out_.truncated; }

            // appends bytes that are now known to be in order
            void emit(Direction dir, const char *bytes, size_t n, int packetNumber, uint64_t missingBefore = 0) {
                if (n == 0 || out_.truncated) return;
                if (out_.bytesAtoB + out_.bytesBtoA + n > max_) {
                    n = static_cast<size_t>(max_ - (out_.bytesAtoB + out_.bytesBtoA));
                    out_.truncated = true;
                    if (n == 0) return;
                }
                (dir == Direction::AtoB ? out_.bytesAtoB : out_.bytesBtoA) += n;
                out_.missingBytes += missingBefore;
                if (!out_.chunks.empty() && out_.chunks.back().direction == dir && missingBefore == 0) {
                    out_.chunks.back().data.append(bytes, n);
                } else {
                    Chunk c;
                    c.direction = dir;
                    c.data.assign(bytes, n);
                    c.missingBefore = missingBefore;
                    c.firstPacket = packetNumber;
                    out_.chunks.push_back(std::move(c));
                }
            }

            // a segment that starts at or before `half.next`: take the part that is new
            void apply(Half &half, Direction dir, uint32_t seq, const std::string &data, int packetNumber, uint64_t missingBefore = 0) {
                const int32_t d = diff(seq, half.next);
                const size_t skip = d < 0 ? static_cast<size_t>(-static_cast<int64_t>(d)) : 0; // already delivered bytes
                if (skip >= data.size()) return;                                                 // a retransmission
                emit(dir, data.data() + skip, data.size() - skip, packetNumber, missingBefore);
                half.next = seq + static_cast<uint32_t>(skip) + static_cast<uint32_t>(data.size() - skip);
            }

            // deliver every held-back segment that became contiguous
            void drain(Half &half, Direction dir, int packetNumber) {
                bool progress = true;
                while (progress) {
                    progress = false;
                    for (size_t i = 0; i < half.pending.size(); ++i) {
                        if (diff(half.pending[i].first, half.next) <= 0) {
                            auto seg = std::move(half.pending[i]);
                            half.pending.erase(half.pending.begin() + static_cast<std::ptrdiff_t>(i));
                            apply(half, dir, seg.first, seg.second, packetNumber);
                            progress = true;
                            break;
                        }
                    }
                }
            }

            // end of the capture: what is still held back follows after a hole
            void flush(Half &half, Direction dir) {
                while (!half.pending.empty() && !full()) {
                    auto it = std::min_element(half.pending.begin(), half.pending.end(),
                                               [&](const auto &a, const auto &b) { return diff(a.first, half.next) < diff(b.first, half.next); });
                    auto seg = std::move(*it);
                    half.pending.erase(it);
                    const int32_t gap = diff(seg.first, half.next);
                    const uint64_t missing = gap > 0 ? static_cast<uint64_t>(gap) : 0;
                    if (gap > 0) half.next = seg.first;
                    apply(half, dir, seg.first, seg.second, 0, missing);
                    drain(half, dir, 0);
                }
            }

        private:
            Stream &out_;
            uint64_t max_;
        };
    } // namespace

    std::vector<uint32_t> conversationPackets(const std::vector<packet::PacketInfo> &packets, uint32_t index) {
        std::vector<uint32_t> out;
        if (index >= packets.size() || !isStreamProtocol(packets[index])) return out;
        const auto &base = packets[index];
        for (uint32_t i = 0; i < packets.size(); ++i) {
            const auto &p = packets[i];
            if (p.ip_version != base.ip_version || p.ip_protocol != base.ip_protocol) continue;
            const bool forward = p.source == base.source && p.destination == base.destination && p.src_port == base.src_port && p.dst_port == base.dst_port;
            const bool backward = p.source == base.destination && p.destination == base.source && p.src_port == base.dst_port && p.dst_port == base.src_port;
            if (forward || backward) out.push_back(i);
        }
        return out;
    }

    bool reassemble(const std::string &capturePath, const std::vector<packet::PacketInfo> &packets,
                    const std::vector<uint32_t> &indices, Stream &out, core::ScanControl *control, uint64_t maxBytes) {
        out = Stream();
        out.packets = static_cast<int>(indices.size());
        if (indices.empty()) return true;

        const auto &first = packets[indices.front()];
        out.tcp = first.ip_protocol == 6;
        out.addressA = first.source;
        out.portA = first.src_port;
        out.addressB = first.destination;
        out.portB = first.dst_port;

        Builder builder(out, maxBytes);
        Half halves[2];
        core::CaptureReader fragmentReader(capturePath);   // only used for datagrams that were reassembled from fragments

        const bool completed = core::scanPackets(capturePath, packets, indices, [&](const packet::PacketInfo &p, const std::vector<char> &frame) {
            const Direction dir = (p.source == out.addressA && p.src_port == out.portA) ? Direction::AtoB : Direction::BtoA;
            Half &half = halves[dir == Direction::AtoB ? 0 : 1];

            std::string data;
            if (p.ip_frag == 2) {
                // reassembled from fragments: the payload position is relative to the reassembled IP payload, not to this frame
                std::vector<char> whole;
                if (p.payload_length > 0 && core::reassembleIpPayload(fragmentReader, packets, p, whole) &&
                    static_cast<uint64_t>(p.payload_offset) + p.payload_length <= whole.size()) {
                    data.assign(whole.data() + p.payload_offset, p.payload_length);
                }
            } else if (p.payload_length > 0 && static_cast<uint64_t>(p.payload_offset) + p.payload_length <= frame.size()) {
                data.assign(frame.data() + p.payload_offset, p.payload_length);
            }

            if (!out.tcp) { // UDP: datagrams as they come
                builder.emit(dir, data.data(), data.size(), p.number);
                return !builder.full();
            }

            const uint32_t seq = p.tcp_relative_seq >= 0 ? static_cast<uint32_t>(p.tcp_relative_seq) : 0;
            const bool syn = p.tcp_flags & 0x02;
            if (!half.started) { // the first segment seen defines where the stream starts (SYN uses one sequence number)
                half.started = true;
                half.next = seq + (syn ? 1u : 0u);
            }
            if (data.empty()) return true;

            if (diff(seq, half.next) > 0) {
                half.pending.emplace_back(seq, std::move(data)); // a hole before it: wait for the missing part
            } else {
                builder.apply(half, dir, seq, data, p.number);
                builder.drain(half, dir, p.number);
            }
            return !builder.full();
        }, control);

        if (!completed) return false; // cancelled or the capture file could not be read
        if (out.tcp) {
            builder.flush(halves[0], Direction::AtoB);
            builder.flush(halves[1], Direction::BtoA);
        }
        return true;
    }
} // namespace stream
