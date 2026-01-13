#pragma once

#include "context.h"

namespace dissect {
    /// Dissects IGMP (Internet Group Management Protocol, IP protocol 2) - RFC 1112 / 2236 / 3376
    void dissectIgmp(Context &ctx, const char *data, size_t length);
} // namespace dissect
