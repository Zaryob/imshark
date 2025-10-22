#pragma once

#include "context.h"

namespace dissect {
    void dissectLlc(Context &ctx, const char *data, size_t length);
} // namespace dissect
