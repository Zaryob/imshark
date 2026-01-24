#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects SMB2/SMB3 protocol packets (over direct TCP port 445 or NetBIOS port 139).
void dissectSmb2(Context &ctx, const char *data, size_t length);

/// Frames SMB2/SMB3 packets over TCP stream (NetBIOS session service framing).
StreamFrame frameSmb2(const char *data, size_t length);

} // namespace dissect
