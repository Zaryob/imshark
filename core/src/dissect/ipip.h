#pragma once

#include <cstddef>
#include <cstdint>

#include "context.h"

namespace dissect {
    /// Dissects an IP-in-IP tunnel payload (RFC 2003 for IPv4, RFC 2473 for IPv6).
    /// The outer IP header announces protocol 4 (IPv4) or 41 (IPv6); the payload is another
    /// IP datagram, whose version nibble selects the inner dissector.
    void dissectIpInIp(Context &ctx, const char *data, size_t length);
} // namespace dissect
