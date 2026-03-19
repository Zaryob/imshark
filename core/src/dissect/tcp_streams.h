#pragma once

// In-order reassembly of TCP byte streams while a capture is loaded, so that application protocols whose messages
// span several segments (or share one) can be decoded as whole messages.
//
// One state per connection direction: the bytes that are contiguous and not yet part of a finished message, the
// out-of-order segments waiting for a hole to fill, and which packets contributed to the bytes in the buffer.
// Retransmissions and overlaps only add their new bytes, a hole that does not fill within a bounded window is given
// up (the partial message is dropped), and FIN/RST end a message that runs until the connection closes.

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include "context.h"

namespace dissect {
    /// One complete message found in a stream.
    struct StreamPdu {
        std::string data;                  // the message bytes
        uint32_t startSeq = 0;             // relative sequence number of its first byte
        std::vector<uint32_t> packets;     // numbers of the packets whose bytes it is made of (capture order of arrival)
        const StreamProtocol *protocol = nullptr;
        bool wholeInSegment = false;       // made of the bytes of the current segment only
    };

    struct StreamFeedResult {
        enum class Action {
            None,      // not handled by a stream protocol: decode the segment on its own, as before
            Segment,   // its bytes belong to a message that is not complete yet
            Pdu,       // at least one message completed that includes bytes of earlier segments
            Whole,     // a message that lies entirely inside this segment: decoded by its stream protocol, no reassembly shown
        } action = Action::None;
        std::vector<StreamPdu> pdus;       // all messages completed by this segment (Action::Pdu)
        bool startsMessage = false;        // Action::Segment: the segment is where the message begins (nothing was buffered before it)
        std::vector<uint32_t> earlier;     // packets (other than the current one) that made up those messages
    };

    class TcpStreams {
    public:
        /// Chooses the protocol of the message that starts at `data`, at relative sequence number `startSeq` (nullptr: none of them).
        using Selector = std::function<const StreamProtocol *(const char *data, size_t size, uint32_t startSeq)>;

        /// Feeds one TCP segment: `relSeq` is the relative sequence number of its first payload byte, `syn` resets the
        /// direction, `closed` (FIN or RST) completes a message that runs until close.
        /// `takeOver` (optional) is asked at the start of every message of a direction that already has a protocol: a non-null
        /// answer replaces the protocol from this message on (a plain protocol that continues as TLS after STARTTLS).
        StreamFeedResult feed(const std::string &key, uint32_t packet, uint32_t relSeq, const char *data, size_t size, bool syn,
                              bool closed, const Selector &select, const Selector &takeOver = nullptr);

        size_t directions() const { return dirs_.size(); }

        static constexpr size_t kMaxBuffer = 8u << 20;        // bytes buffered per direction before giving up
        static constexpr size_t kMaxPending = 1u << 20;       // out-of-order bytes waiting for a hole
        static constexpr size_t kMaxDirections = 100000;      // tracked connection directions

    private:
        struct Contributor { uint32_t packet, start, end; };
        struct Pending { uint32_t seq; std::string data; uint32_t packet; };
        struct Dir {
            bool started = false;
            uint32_t next = 0;               // next expected relative sequence number
            uint32_t bufStart = 0;           // sequence number of buf[0]
            std::string buf;
            std::vector<Contributor> contributors;
            std::vector<Pending> pending;
            size_t pendingBytes = 0;
            const StreamProtocol *protocol = nullptr;
            bool plain = false;              // the last bytes were not a stream protocol: a hole just resynchronises
        };

        /// Returns false if the segment had no new bytes (a pure retransmission).
        bool accept(Dir &d, uint32_t packet, uint32_t seq, const char *data, size_t size);
        static void reset(Dir &d);

        std::map<std::string, Dir> dirs_;
    };
} // namespace dissect
