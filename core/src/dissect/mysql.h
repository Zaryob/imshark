#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects MySQL client/server protocol packets (TCP port 3306).
void dissectMySql(Context &ctx, const char *data, size_t length);

/// Frames MySQL packets over a TCP stream (3-byte length + 1-byte sequence ID).
StreamFrame frameMySql(const char *data, size_t length);

} // namespace dissect
