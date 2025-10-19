#pragma once

#include "context.h"

namespace dissect {
    /// Dissects an IEEE 802.11 wireless frame (LinkType 105).
    /// Decodes Frame Control, Duration/AID, MAC addresses (RA/TA/DA/SA/BSSID),
    /// Sequence Control, QoS Control, HT Control, Management frames (Beacon,
    /// Probe, Auth, Assoc, etc.), Control frames (ACK, CTS, RTS, BlockAck, etc.),
    /// and Data frames (handling protected payloads and LLC/SNAP encapsulation).
    void dissectIeee80211(Context &ctx, const char *data, size_t length);
} // namespace dissect
