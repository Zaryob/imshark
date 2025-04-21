#pragma once

#include "context.h"

// Built-in dissectors. Each one has the `Dissector` signature (see context.h).
namespace dissect {
    void dissectIPv4(Context &ctx, const char *data, size_t length);
    void dissectIPv6(Context &ctx, const char *data, size_t length);
    void dissectArp(Context &ctx, const char *data, size_t length, bool reverse);   // reverse = RARP
    void dissectIcmp(Context &ctx, const char *data, size_t length, bool v6);
    void dissectTcp(Context &ctx, const char *data, size_t length);
    void dissectUdp(Context &ctx, const char *data, size_t length);
    void dissectDns(Context &ctx, const char *data, size_t length);
    void dissectDhcp(Context &ctx, const char *data, size_t length);
    void dissectSnmp(Context &ctx, const char *data, size_t length);
    void dissectTelnet(Context &ctx, const char *data, size_t length);
    void dissectSmtp(Context &ctx, const char *data, size_t length);
    void dissectBgp(Context &ctx, const char *data, size_t length);
} // namespace dissect
