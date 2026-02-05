#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects TDS (Tabular Data Stream, Microsoft SQL Server / Sybase) packets (TCP port 1433).
void dissectTds(Context &ctx, const char *data, size_t length);

/// Frames TDS packets over a TCP stream (8-byte header: type, status, 2-byte big-endian length).
StreamFrame frameTds(const char *data, size_t length);

} // namespace dissect
