#pragma once

#include "context.h"

namespace dissect {
    /// Dissects SCTP (Stream Control Transmission Protocol, IP protocol 132) - RFC 4960
    void dissectSctp(Context &ctx, const char *data, size_t length);
} // namespace dissect
