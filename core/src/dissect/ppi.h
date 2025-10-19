#pragma once

#include "context.h"

namespace dissect {
    /// Dissects a Packet Processing Information (PPI) header (LinkType 192).
    /// Extracts pph_version, pph_flags, pph_len, pph_dlt, walks PPI TLVs
    /// (including 802.11 Common TLV type 2), and delegates the payload to the
    /// encapsulated Data Link Type (e.g. 105 for 802.11).
    void dissectPpi(Context &ctx, const char *data, size_t length);
} // namespace dissect
