#pragma once

#include "context.h"

namespace dissect {
    void dissectStp(Context &ctx, const char *data, size_t length);
} // namespace dissect
