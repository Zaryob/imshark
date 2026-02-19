#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects Modbus/TCP packets (TCP port 502).
void dissectModbus(Context &ctx, const char *data, size_t length);

/// Frames Modbus/TCP stream messages (MBAP header: 7 bytes).
StreamFrame frameModbus(const char *data, size_t length);

/// Dissects DNP3 (Distributed Network Protocol 3.0) packets (TCP/UDP port 20000).
void dissectDnp3(Context &ctx, const char *data, size_t length);

/// Frames DNP3 stream messages (Start bytes 0x05 0x64, len in byte 2).
StreamFrame frameDnp3(const char *data, size_t length);

/// Dissects CAN / SocketCAN frames (LinkType 227: LINKTYPE_CAN_SOCKETCAN).
void dissectSocketCan(Context &ctx, const char *data, size_t length);

} // namespace dissect
