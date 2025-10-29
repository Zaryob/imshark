#pragma once

#include <cstddef>
#include <cstdint>

#include "context.h"

namespace dissect {
    /// Dissects a GRE (Generic Routing Encapsulation) header (RFC 2784, RFC 2890) and dispatches
    /// the inner protocol (IPv4, IPv6, ARP, transparent Ethernet bridging, PPP, MPLS) or, for the
    /// Cisco ERSPAN protocol types (0x88BE / 0x22EB), the mirrored Ethernet frame.
    void dissectGre(Context &ctx, const char *data, size_t length);
} // namespace dissect
