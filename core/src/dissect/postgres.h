#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects PostgreSQL frontend/backend protocol packets (TCP port 5432).
void dissectPostgreSql(Context &ctx, const char *data, size_t length);

/// Frames PostgreSQL stream messages.
StreamFrame framePostgreSql(const char *data, size_t length);

} // namespace dissect
