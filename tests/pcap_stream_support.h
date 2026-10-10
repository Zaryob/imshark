#pragma once

// Synthetic classic pcap byte streams for the capture worker / worker stream tests: any magic (both byte orders, micro and
// nanosecond), version, snaplen, link type and arbitrary record headers, so that valid and hostile streams can be built.
#include <cstdint>
#include <string>
#include <vector>

namespace pcapstream {
    struct Options {
        bool bigEndian = false;
        bool nano = false;
        uint16_t versionMajor = 2;
        uint32_t snaplen = 65535;
        uint32_t linkType = 1;
    };

    inline void put(std::string &out, uint64_t v, int bytes, bool big) {
        for (int i = 0; i < bytes; ++i) {
            const int shift = big ? 8 * (bytes - 1 - i) : 8 * i;
            out += static_cast<char>((v >> shift) & 0xff);
        }
    }

    inline std::string header(const Options &o = {}) {
        std::string out;
        // the magic is written in the stream's own byte order
        put(out, o.nano ? 0xa1b23c4dull : 0xa1b2c3d4ull, 4, o.bigEndian);
        put(out, o.versionMajor, 2, o.bigEndian);
        put(out, 4, 2, o.bigEndian);
        put(out, 0, 4, o.bigEndian);
        put(out, 0, 4, o.bigEndian);
        put(out, o.snaplen, 4, o.bigEndian);
        put(out, o.linkType, 4, o.bigEndian);
        return out;
    }

    /// A record with arbitrary header values; `bodyBytes` bytes of body follow (default: inclLen of them).
    inline std::string record(const Options &o, uint32_t sec, uint32_t fraction, uint32_t inclLen, uint32_t origLen, int64_t bodyBytes = -1,
                              char fill = 'x') {
        std::string out;
        put(out, sec, 4, o.bigEndian);
        put(out, fraction, 4, o.bigEndian);
        put(out, inclLen, 4, o.bigEndian);
        put(out, origLen, 4, o.bigEndian);
        const int64_t n = bodyBytes < 0 ? inclLen : bodyBytes;
        out.append(static_cast<size_t>(n), fill);
        return out;
    }

    /// A well formed record whose body is `body`.
    inline std::string packet(const Options &o, uint32_t sec, uint32_t fraction, const std::string &body, uint32_t origLen = 0) {
        std::string out = record(o, sec, fraction, static_cast<uint32_t>(body.size()), origLen ? origLen : static_cast<uint32_t>(body.size()), 0);
        return out + body;
    }
} // namespace pcapstream
