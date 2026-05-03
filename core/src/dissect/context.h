#pragma once

#include <cstddef>
#include <functional>
#include <string>

#include <network/tcp_connection.h>
#include <packet/packet_info.h>

namespace dissect {
    class Registry;

    /// What a parse run produces.
    enum class ParseMode {
        Summary, // list columns only (protocol, addresses, info); tracks TCP state; no field tree
        Full,    // summary + field tree; tracks TCP state (stand-alone use, e.g. tests)
        Replay,  // summary + field tree for one packet of an already loaded capture: TCP numbers are
                 // taken from the packet instead of the connection table
    };

    /// Everything a dissector may use while decoding one frame.
    struct Context {
        packet::PacketInfo &pack;           // the packet being filled in
        const char *frame;                  // start of the captured frame (for absolute offsets)
        size_t frameLength;
        network::TCPConnection &tcp;        // per-capture TCP state (relative seq/ack)
        const Registry &registry;           // lookup of the next-layer dissector
        ParseMode mode = ParseMode::Full;

        /// Dissectors skip building the (comparatively expensive) field tree when this is false.
        bool wantFields() const { return mode != ParseMode::Summary; }

        /// Absolute offset of `p` inside the frame.
        size_t offsetOf(const char *p) const { return static_cast<size_t>(p - frame); }

        /// Marks the packet as malformed (keeps an already detected protocol name).
        void markMalformed(const std::string &reason) {
            if (pack.protocol.empty()) pack.protocol = "Malformed";
            pack.info = "[Malformed Packet: " + reason + "]";
        }

        /// Appends a top-level layer to the protocol tree. The reference is only valid until the next
        /// layer is added.
        packet::Field &addLayer(std::string name, size_t offset, size_t length) {
            return pack.fields.emplace_back(packet::Field{std::move(name), static_cast<uint32_t>(offset),
                                                          static_cast<uint32_t>(length), {}});
        }
    };

    /// A dissector decodes `length` bytes starting at `data` (never reads beyond them), fills `ctx.pack`
    /// (protocol, info, header copy, field tree) and may hand the payload to the next layer through
    /// `ctx.registry`.
    using Dissector = std::function<void(Context &ctx, const char *data, size_t length)>;
} // namespace dissect
