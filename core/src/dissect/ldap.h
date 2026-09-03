#pragma once

#include "context.h"

namespace dissect {
    /// Dissects LDAP (Lightweight Directory Access Protocol, RFC 4511) over TCP (Port 389 / 636, global catalog 3268 / 3269)
    void dissectLdap(Context &ctx, const char *data, size_t length);

    /// Framing for LDAP over TCP stream
    StreamFrame frameLdap(const char *data, size_t length);
} // namespace dissect
