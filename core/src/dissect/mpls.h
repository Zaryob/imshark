#pragma once

#include <cstddef>
#include <cstdint>

#include "context.h"

namespace dissect {
    /// Dissects an MPLS (Multiprotocol Label Switching) label stack (RFC 3031, RFC 3032).
    /// Parses 32-bit label stack entries (Label: 20 bits, TC/Exp: 3 bits, S: 1 bit, TTL: 8 bits)
    /// until the bottom of stack (S=1) is reached, then inspects and unwraps encapsulated IPv4,
    /// IPv6, or Pseudowire/Ethernet payload.
    void dissectMpls(Context &ctx, const char *data, size_t length);
} // namespace dissect
