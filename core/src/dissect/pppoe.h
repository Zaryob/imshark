#pragma once

#include "context.h"

namespace dissect {
    void dissectPppoeDiscovery(Context &ctx, const char *data, size_t length);
    void dissectPppoeSession(Context &ctx, const char *data, size_t length);
} // namespace dissect
