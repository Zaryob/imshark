// NTP (RFC 5905): the 48-byte packet with its timestamps.
#include "protocols.h"

#include "util.h"

#include <network/timeutil.h>

using packet::Field;

namespace {
    using namespace dissect;

    constexpr double kNtpToUnix = 2208988800.0; // seconds between 1900-01-01 and 1970-01-01

    const char *modeName(unsigned m) {
        switch (m) {
            case 1: return "symmetric active";
            case 2: return "symmetric passive";
            case 3: return "client";
            case 4: return "server";
            case 5: return "broadcast";
            case 6: return "reserved for NTP control message";
            case 7: return "reserved for private use";
            default: return "reserved";
        }
    }

    std::string timestamp(const char *d) {
        const uint32_t secs = be32(d), frac = be32(d + 4);
        if (secs == 0 && frac == 0) return "Not set";
        return network::formatUtcTime(static_cast<double>(secs) - kNtpToUnix + static_cast<double>(frac) / 4294967296.0) + " UTC";
    }

    std::string fixed1616(const char *d) { return std::to_string(static_cast<double>(be32(d)) / 65536.0) + " seconds"; }
} // namespace

void dissect::dissectNtp(Context &ctx, const char *data, size_t length) {
    auto &pack = ctx.pack;
    pack.protocol = "NTP";
    if (length < 48) {
        ctx.markMalformed("NTP packet shorter than 48 bytes");
        return;
    }
    const uint8_t b0 = static_cast<uint8_t>(data[0]);
    const unsigned leap = b0 >> 6, version = (b0 >> 3) & 7, mode = b0 & 7;
    const unsigned stratum = static_cast<uint8_t>(data[1]);
    pack.app_type = static_cast<uint16_t>(mode);
    pack.app_code = static_cast<uint16_t>(stratum);
    pack.app_flags = static_cast<uint16_t>(version);
    pack.info = "NTP Version " + std::to_string(version) + ", " + modeName(mode);

    if (!ctx.wantFields()) return;
    const size_t o = ctx.offsetOf(data);
    Field &l = ctx.addLayer("Network Time Protocol (" + std::string(modeName(mode)) + ")", o, length);
    static const char *leapText[] = {"no warning", "last minute has 61 seconds", "last minute has 59 seconds", "unknown (clock unsynchronized)"};
    l.add(std::string("Flags: Leap Indicator: ") + leapText[leap] + ", Version: " + std::to_string(version) + ", Mode: " + modeName(mode) +
              " (" + std::to_string(mode) + ")", o, 1);
    l.add("Peer Clock Stratum: " + std::to_string(stratum) + (stratum == 0 ? " (unspecified or invalid)" : stratum == 1 ? " (primary reference)" : " (secondary reference)"), o + 1, 1);
    l.add("Peer Polling Interval: " + std::to_string(static_cast<uint8_t>(data[2])), o + 2, 1);
    l.add("Peer Clock Precision: " + std::to_string(static_cast<int8_t>(data[3])), o + 3, 1);
    l.add("Root Delay: " + fixed1616(data + 4), o + 4, 4);
    l.add("Root Dispersion: " + fixed1616(data + 8), o + 8, 4);
    std::string refId;
    if (stratum <= 1) {
        for (int i = 0; i < 4; ++i) if (data[12 + i] >= 32 && data[12 + i] < 127) refId += data[12 + i];
    } else {
        refId = ip4(data + 12);
    }
    l.add("Reference ID: " + refId, o + 12, 4);
    l.add("Reference Timestamp: " + timestamp(data + 16), o + 16, 8);
    l.add("Origin Timestamp: " + timestamp(data + 24), o + 24, 8);
    l.add("Receive Timestamp: " + timestamp(data + 32), o + 32, 8);
    l.add("Transmit Timestamp: " + timestamp(data + 40), o + 40, 8);
}
