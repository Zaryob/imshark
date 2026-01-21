#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects Kerberos (v5) protocol packets (RFC 4120).
/// Supported over UDP (port 88) and TCP (port 88 with 4-byte big-endian length prefix).
void dissectKerberos(Context &ctx, const char *data, size_t length);

/// Frames Kerberos PDUs from a TCP stream.
StreamFrame frameKerberos(const char *data, size_t length);

} // namespace dissect
