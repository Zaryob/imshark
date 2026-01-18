#pragma once

#include "context.h"

namespace dissect {
    /// Dissects IPsec Authentication Header (AH, IP protocol 51) - RFC 4302
    void dissectAh(Context &ctx, const char *data, size_t length);

    /// Dissects IPsec Encapsulating Security Payload (ESP, IP protocol 50) - RFC 4303
    void dissectEsp(Context &ctx, const char *data, size_t length);

    /// Dissects Internet Key Exchange (IKEv1 / IKEv2 / ISAKMP, UDP port 500 / 4500) - RFC 2408 / 7296
    void dissectIke(Context &ctx, const char *data, size_t length);
} // namespace dissect
