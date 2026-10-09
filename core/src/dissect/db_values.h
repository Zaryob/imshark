#pragma once

// Value formatting shared by the PostgreSQL and MySQL dissectors.
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <string>

namespace dissect {

// shortest %g form that reads back as the same number
inline std::string dbFloatText(double d, bool single) {
    if (std::isnan(d)) return "NaN";
    if (std::isinf(d)) return d < 0 ? "-Infinity" : "Infinity";
    char buf[40];
    for (int precision = 1; precision <= 17; ++precision) {
        std::snprintf(buf, sizeof buf, "%.*g", precision, d);
        const double back = std::strtod(buf, nullptr);
        if (single ? static_cast<float>(back) == static_cast<float>(d) : back == d) break;
    }
    return buf;
}

// days since 1970-01-01 -> civil date (proleptic Gregorian)
inline void dbCivilDate(int64_t z, int64_t &year, unsigned &month, unsigned &day) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    day = doy - (153 * mp + 2) / 5 + 1;
    month = mp < 10 ? mp + 3 : mp - 9;
    year = static_cast<int64_t>(yoe) + era * 400 + (month <= 2);
}

inline std::string dbTwoDigits(unsigned v) { char b[8]; std::snprintf(b, sizeof b, "%02u", v); return b; }

} // namespace dissect
