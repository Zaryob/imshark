#pragma once

#include <cstddef>
#include <cstdint>

#include "context.h"

namespace dissect {
    /// Dissects an Ethernet Slow Protocol frame (EtherType 0x8809, IEEE 802.3).
    /// The first byte is the subtype, currently LACP (0x01) is decoded in full.
    void dissectSlowProtocols(Context &ctx, const char *data, size_t length);
} // namespace dissect
