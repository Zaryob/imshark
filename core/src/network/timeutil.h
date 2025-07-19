#pragma once

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>

namespace network {
    /// "2023-11-14 22:13:20.123456" for epoch seconds (UTC, microsecond precision). Done with a
    /// civil-from-days algorithm instead of gmtime: thread-safe and identical on every platform.
    inline std::string formatUtcTime(double epochSeconds) {
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
} // namespace network
