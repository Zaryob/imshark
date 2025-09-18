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
    void dissectDns(Context &ctx, const char *data, size_t length);        // DNS over UDP
    void dissectDnsTcp(Context &ctx, const char *data, size_t length);     // DNS over TCP (2-byte length prefix)
    StreamFrame frameDnsTcp(const char *data, size_t length);              // message boundary of DNS over TCP
    void dissectMdns(Context &ctx, const char *data, size_t length);       // multicast DNS
    void dissectDhcp(Context &ctx, const char *data, size_t length);
    void dissectNtp(Context &ctx, const char *data, size_t length);
    void dissectSnmp(Context &ctx, const char *data, size_t length);
    void dissectTelnet(Context &ctx, const char *data, size_t length);
    void dissectSmtp(Context &ctx, const char *data, size_t length);
    void dissectBgp(Context &ctx, const char *data, size_t length);
    bool dissectHttp(Context &ctx, const char *data, size_t length);   // heuristic: false if it is not HTTP/1.x
    bool dissectTls(Context &ctx, const char *data, size_t length);    // heuristic: false if it is not a TLS record
} // namespace dissect
