#include "time_format.h"

#include <network/timeutil.h>

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

std::string ui::formatUtc(double epochSeconds) { return network::formatUtcTime(epochSeconds); }

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
