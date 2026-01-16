#pragma once

#include "context.h"

namespace dissect {
    /// Dissects OSPF (Open Shortest Path First, IP protocol 89) - RFC 2328 (v2) / RFC 5340 (v3)
    void dissectOspf(Context &ctx, const char *data, size_t length);
} // namespace dissect
