#include "tcp_streams.h"

#include <algorithm>

namespace dissect {
    namespace {
        int32_t diff(uint32_t a, uint32_t b) { return static_cast<int32_t>(a - b); } // a - b with wrap-around
    }

    void TcpStreams::reset(Dir &d) {
        d.buf.clear();
        d.contributors.clear();
        d.pending.clear();
        d.pendingBytes = 0;
        d.protocol = nullptr;
        d.plain = false;
        d.midMessage = false;
    }

    // Appends the new bytes of an in-order or overlapping segment and then every waiting segment that became contiguous.
    bool TcpStreams::accept(Dir &d, uint32_t packet, uint32_t seq, const char *data, size_t size) {
        const int32_t behind = diff(d.next, seq);                     // bytes of this segment that were already seen
        if (behind > 0) {
            if (static_cast<size_t>(behind) >= size) return false;    // a pure retransmission
            data += behind;
            size -= static_cast<size_t>(behind);
            seq += static_cast<uint32_t>(behind);
        }
        if (d.buf.empty()) d.bufStart = seq;
        d.buf.append(data, size);
        d.contributors.push_back({packet, seq, seq + static_cast<uint32_t>(size)});
        d.next = seq + static_cast<uint32_t>(size);

        bool progress = true;
        while (progress && !d.pending.empty()) {
            progress = false;
            for (size_t i = 0; i < d.pending.size(); ++i) {
                if (diff(d.pending[i].seq, d.next) > 0) continue;     // still a hole in front of it
                Pending p = std::move(d.pending[i]);
                d.pending.erase(d.pending.begin() + static_cast<std::ptrdiff_t>(i));
                d.pendingBytes -= p.data.size();
                const int32_t overlap = diff(d.next, p.seq);
                if (static_cast<size_t>(overlap) < p.data.size()) {
                    const size_t skip = static_cast<size_t>(overlap);
                    d.buf.append(p.data, skip, std::string::npos);
                    d.contributors.push_back({p.packet, d.next, d.next + static_cast<uint32_t>(p.data.size() - skip)});
                    d.next += static_cast<uint32_t>(p.data.size() - skip);
                }
                progress = true;
                break;
            }
        }
        return true;
    }

    StreamFeedResult TcpStreams::feed(const std::string &key, uint32_t packet, uint32_t relSeq, const char *data, size_t size,
                                      bool syn, bool closed, const Selector &select, const Selector &takeOver) {
        StreamFeedResult result;
        if (dirs_.size() >= kMaxDirections && dirs_.find(key) == dirs_.end()) dirs_.clear(); // bounded memory
        Dir &d = dirs_[key];

        if (syn) { // a new connection (or a retransmitted SYN): start over; the SYN itself uses one sequence number
            reset(d);
            d.started = true;
            d.next = d.bufStart = relSeq + 1;
            if (size == 0) return result;
            relSeq += 1;
        }
        if (!d.started) {
            d.started = true;
            d.next = d.bufStart = relSeq;
        }

        bool inPending = false, added = false;
        const bool wasEmpty = d.buf.empty() && d.pending.empty();
        if (size > 0) {
            if (diff(relSeq, d.next) > 0 && d.plain && d.buf.empty() && d.pending.empty()) {
                d.next = d.bufStart = relSeq;                     // not a stream protocol: nothing to wait for, resynchronise
                added = accept(d, packet, relSeq, data, size);
            } else if (diff(relSeq, d.next) > 0) {
                // a hole in front of this segment: keep it until the missing bytes arrive, but not forever
                if (d.pendingBytes + size > kMaxPending) {
                    reset(d);                                     // give the hole up: the partial message is lost
                    d.next = d.bufStart = relSeq;
                    added = accept(d, packet, relSeq, data, size);
                } else {
                    d.pending.push_back({relSeq, std::string(data, size), packet});
                    d.pendingBytes += size;
                    inPending = true;
                }
            } else {
                added = accept(d, packet, relSeq, data, size);
            }
        }
        if (d.buf.size() > kMaxBuffer) { reset(d); d.bufStart = d.next; }   // a message that never ends

        // cut messages out of the buffer
        bool sawPartial = false, reselected = false;
        while (!d.buf.empty()) {
            if (!d.protocol) {
                d.protocol = select(d.buf.data(), d.buf.size(), d.bufStart);
                if (d.protocol) d.plain = false;
                if (!d.protocol) {                                // not a stream protocol: decode segments on their own
                    d.plain = true;
                    d.buf.clear();
                    d.contributors.clear();
                    d.bufStart = d.next;
                    break;
                }
            }
            if (takeOver) {
                if (const StreamProtocol *other = takeOver(d.buf.data(), d.buf.size(), d.bufStart)) d.protocol = other;
            }
            const StreamFramer &framer = d.midMessage && d.protocol->frameContinuation ? d.protocol->frameContinuation : d.protocol->frame;
            const StreamFrame f = framer(d.buf.data(), d.buf.size());
            size_t take = 0;
            if (f.kind == StreamFrame::Kind::Complete && f.length > 0 && f.length <= d.buf.size()) {
                take = f.length;
            } else if (f.kind == StreamFrame::Kind::UntilClose && closed) {
                take = d.buf.size();
            } else if (f.kind == StreamFrame::Kind::Reject) {
                d.protocol = nullptr;                             // these bytes are not (or no longer) this protocol
                d.midMessage = false;
                if (!reselected && !d.buf.empty()) {              // another protocol may take over right here (a TLS handshake after STARTTLS)
                    reselected = true;
                    continue;
                }
                d.plain = true;
                d.buf.clear();
                d.contributors.clear();
                d.bufStart = d.next;
                break;
            } else {
                sawPartial = true;                                // NeedMore / UntilClose / a nonsensical length: wait
                break;
            }

            reselected = false;
            d.midMessage = f.kind == StreamFrame::Kind::Complete && f.continues;
            StreamPdu pdu;
            pdu.data = d.buf.substr(0, take);
            pdu.startSeq = d.bufStart;
            pdu.protocol = d.protocol;
            const uint32_t end = d.bufStart + static_cast<uint32_t>(take);
            for (const auto &c: d.contributors) {
                if (diff(c.end, d.bufStart) <= 0 || diff(c.start, end) >= 0) continue;
                if (std::find(pdu.packets.begin(), pdu.packets.end(), c.packet) == pdu.packets.end()) pdu.packets.push_back(c.packet);
            }
            std::sort(pdu.packets.begin(), pdu.packets.end());   // capture order, like the replay of a single packet finds them
            pdu.wholeInSegment = pdu.packets.size() == 1 && pdu.packets[0] == packet;
            d.buf.erase(0, take);
            d.bufStart = end;
            d.contributors.erase(std::remove_if(d.contributors.begin(), d.contributors.end(),
                                                [&](const Contributor &c) { return diff(c.end, end) <= 0; }),
                                 d.contributors.end());
            if (!pdu.wholeInSegment) {
                for (uint32_t p: pdu.packets) {
                    if (p != packet && std::find(result.earlier.begin(), result.earlier.end(), p) == result.earlier.end()) result.earlier.push_back(p);
                }
            }
            result.pdus.push_back(std::move(pdu));
        }

        if (closed) reset(d); // the connection ends: nothing that is still waiting can complete any more

        const bool anyReassembled = std::any_of(result.pdus.begin(), result.pdus.end(), [](const StreamPdu &p) { return !p.wholeInSegment; });
        if (anyReassembled) result.action = StreamFeedResult::Action::Pdu;
        else if (!result.pdus.empty()) result.action = StreamFeedResult::Action::Whole;
        else if ((sawPartial && added) || inPending) {
            result.action = StreamFeedResult::Action::Segment;
            result.startsMessage = wasEmpty && !inPending;
        }
        else result.action = StreamFeedResult::Action::None;
        return result;
    }
} // namespace dissect
