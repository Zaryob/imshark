#pragma once

#include "context.h"
#include <cstdint>

namespace dissect {

/// Dissects SIP (Session Initiation Protocol, RFC 3261) and SDP (RFC 4566) over UDP/TCP.
void dissectSip(Context &ctx, const char *data, size_t length);

/// Frames SIP messages over a TCP stream using Content-Length or boundary scanning.
StreamFrame frameSip(const char *data, size_t length);

/// Dissects RTP (Real-time Transport Protocol, RFC 3550) over UDP.
void dissectRtp(Context &ctx, const char *data, size_t length);

/// Dissects RTCP (RTP Control Protocol, RFC 3550) over UDP.
void dissectRtcp(Context &ctx, const char *data, size_t length);

/// Dissects RTSP (Real Time Streaming Protocol, RFC 2326 / RFC 7826) over TCP.
void dissectRtsp(Context &ctx, const char *data, size_t length);

/// Frames RTSP messages over a TCP stream.
StreamFrame frameRtsp(const char *data, size_t length);

} // namespace dissect
