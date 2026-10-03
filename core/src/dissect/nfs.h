#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects ONC RPC (RFC 5531) and NFS (RFC 1813 / RFC 7530) packets over UDP/TCP.
void dissectNfs(Context &ctx, const char *data, size_t length);

/// Frames ONC RPC record marking (RFC 5531 §11) over TCP stream.
StreamFrame frameRpc(const char *data, size_t length);

/// Frames the bytes after a record fragment that was not the last: the record mark only, the bytes behind it are the middle of a message.
StreamFrame frameRpcContinuation(const char *data, size_t length);

} // namespace dissect
