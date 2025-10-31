#pragma once

#include <cstddef>
#include <cstdint>

#include "context.h"

namespace dissect {
    /// Dissects an LLDP / LLDPDU frame (EtherType 0x88CC, IEEE 802.1AB).
    /// Parses the TLV sequence (chassis ID, port ID, TTL, system name, capabilities and
    /// the organizationally specific TLVs) until the End-of-LLDPDU TLV or the frame ends.
    void dissectLldp(Context &ctx, const char *data, size_t length);
} // namespace dissect
