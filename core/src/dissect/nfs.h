#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects ONC RPC (RFC 5531) and NFS (RFC 1813 / RFC 7530) packets over UDP/TCP.
void dissectNfs(Context &ctx, const char *data, size_t length);

/// Frames ONC RPC record marking (RFC 5531 §11) over TCP stream.
StreamFrame frameRpc(const char *data, size_t length);

} // namespace dissect
