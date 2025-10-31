#pragma once

#include <cstddef>
#include <cstdint>

#include "context.h"

namespace dissect {
    /// Dissects an Ethernet MAC Control frame (EtherType 0x8808, IEEE 802.3 Annex 31B).
    /// Decodes the PAUSE (0x0001) and Priority Flow Control (0x0101) opcodes.
    void dissectEthernetControl(Context &ctx, const char *data, size_t length);
} // namespace dissect
