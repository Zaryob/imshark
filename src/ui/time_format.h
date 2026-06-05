#pragma once

#include <string>

#include <packet/packet_info.h>

namespace ui {
    enum class TimeFormat : int {
        SinceCaptureStart = 0,  // seconds since the first packet          1.234567
        SincePrevious = 1,      // seconds since the previous packet       0.000123
        UtcDateTime = 2,        // UTC date and time of day                2023-11-14 22:13:20.123456
        EpochSeconds = 3,       // seconds since 1970-01-01 UTC            1700000000.123456
    };

    const char *timeFormatName(TimeFormat format);
    const char *timeFormatKey(TimeFormat format);            // for the settings file
    TimeFormat timeFormatFromKey(const std::string &key);    // unknown keys give SinceCaptureStart

    /// Text for the Time column. `previous` is the previous captured packet (nullptr for the first).
    std::string formatPacketTime(const packet::PacketInfo &packet, const packet::PacketInfo *previous,
                                 double captureStartEpoch, TimeFormat format);

    /// "2023-11-14 22:13:20.123456" for epoch seconds (UTC, microsecond precision, no platform time API).
    std::string formatUtc(double epochSeconds);
} // namespace ui
