#include "time_format.h"

#include <cmath>
#include <cstdint>
#include <cstdio>

const char *ui::timeFormatName(TimeFormat f) {
    switch (f) {
        case TimeFormat::SinceCaptureStart: return "Seconds Since Beginning of Capture";
        case TimeFormat::SincePrevious: return "Seconds Since Previous Packet";
        case TimeFormat::UtcDateTime: return "UTC Date and Time of Day";
        case TimeFormat::EpochSeconds: return "Seconds Since Epoch (1970)";
    }
    return "";
}

const char *ui::timeFormatKey(TimeFormat f) {
    switch (f) {
        case TimeFormat::SinceCaptureStart: return "relative";
        case TimeFormat::SincePrevious: return "delta";
        case TimeFormat::UtcDateTime: return "utc";
        case TimeFormat::EpochSeconds: return "epoch";
    }
    return "relative";
}

ui::TimeFormat ui::timeFormatFromKey(const std::string &key) {
    for (auto f: {TimeFormat::SincePrevious, TimeFormat::UtcDateTime, TimeFormat::EpochSeconds}) {
        if (key == timeFormatKey(f)) return f;
    }
    return TimeFormat::SinceCaptureStart;
}

std::string ui::formatUtc(double epochSeconds) {
    // whole microseconds since the epoch; floor so that negative times keep a positive fraction
    const int64_t micros = static_cast<int64_t>(std::llround(epochSeconds * 1e6));
    int64_t seconds = micros / 1000000;
    int64_t frac = micros % 1000000;
    if (frac < 0) { frac += 1000000; --seconds; }

    // civil date from days since 1970-01-01 (Howard Hinnant's algorithm, valid for the whole int64 range of interest)
    int64_t days = seconds / 86400;
    int64_t secOfDay = seconds % 86400;
    if (secOfDay < 0) { secOfDay += 86400; --days; }
    const int64_t z = days + 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const int64_t doe = z - era * 146097;
    const int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const int64_t mp = (5 * doy + 2) / 153;
    const int64_t day = doy - (153 * mp + 2) / 5 + 1;
    const int64_t month = mp < 10 ? mp + 3 : mp - 9;
    const int64_t year = yoe + era * 400 + (month <= 2 ? 1 : 0);

    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04lld-%02lld-%02lld %02lld:%02lld:%02lld.%06lld", static_cast<long long>(year),
                  static_cast<long long>(month), static_cast<long long>(day), static_cast<long long>(secOfDay / 3600),
                  static_cast<long long>(secOfDay % 3600 / 60), static_cast<long long>(secOfDay % 60), static_cast<long long>(frac));
    return buf;
}

std::string ui::formatPacketTime(const packet::PacketInfo &packet, const packet::PacketInfo *previous,
                                 double captureStartEpoch, TimeFormat format) {
    char buf[48];
    switch (format) {
        case TimeFormat::SinceCaptureStart:
            std::snprintf(buf, sizeof(buf), "%.6f", packet.time);
            return buf;
        case TimeFormat::SincePrevious:
            std::snprintf(buf, sizeof(buf), "%.6f", previous ? packet.time - previous->time : 0.0);
            return buf;
        case TimeFormat::UtcDateTime:
            return formatUtc(captureStartEpoch + packet.time);
        case TimeFormat::EpochSeconds:
            std::snprintf(buf, sizeof(buf), "%.6f", captureStartEpoch + packet.time);
            return buf;
    }
    return "";
}
