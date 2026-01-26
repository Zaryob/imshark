#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects DCE/RPC (Distributed Computing Environment / Remote Procedure Calls) packets.
/// Supported over TCP (port 135) and SMB named pipes.
void dissectDceRpc(Context &ctx, const char *data, size_t length);

/// Frames connection-oriented DCE/RPC PDUs from a TCP stream.
StreamFrame frameDceRpc(const char *data, size_t length);

} // namespace dissect
