#pragma once

#include "context.h"

namespace dissect {
    /// Dissects a Radiotap header (LinkType 127).
    /// Extracts TSFT, flags, rate, channel frequency, dBm signal/noise,
    /// natural-alignment fields, handles FCS present flag, and delegates
    /// the encapsulated 802.11 frame to dissectIeee80211.
    void dissectRadiotap(Context &ctx, const char *data, size_t length);
} // namespace dissect
