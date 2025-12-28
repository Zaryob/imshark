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
    StreamFrame frameDnsTcpHeuristic(const char *data, size_t length);     // same, but only for bytes that look like DNS (any port)
    bool dissectDnsHeuristic(Context &ctx, const char *data, size_t length);   // DNS over UDP on any port, validated structurally
    void dissectMdns(Context &ctx, const char *data, size_t length);       // multicast DNS
    void dissectDhcp(Context &ctx, const char *data, size_t length);
    void dissectNtp(Context &ctx, const char *data, size_t length);
    void dissectSnmp(Context &ctx, const char *data, size_t length);
    void dissectTelnet(Context &ctx, const char *data, size_t length);
    void dissectSmtp(Context &ctx, const char *data, size_t length);
    void dissectFtp(Context &ctx, const char *data, size_t length);
    void dissectFtpData(Context &ctx, const char *data, size_t length);
    void dissectTftp(Context &ctx, const char *data, size_t length);
    void dissectSsh(Context &ctx, const char *data, size_t length);
    void dissectBgp(Context &ctx, const char *data, size_t length);
    StreamFrame frameBgp(const char *data, size_t length);
    StreamFrame frameHttp(const char *data, size_t length);            // message boundary of HTTP/1.x (Content-Length, chunked, until close)
    bool dissectHttp(Context &ctx, const char *data, size_t length);   // heuristic: false if it is not HTTP/1.x
    StreamFrame frameTls(const char *data, size_t length);             // message boundary of TLS records (handshake messages may span records)
    bool dissectTls(Context &ctx, const char *data, size_t length);    // heuristic: false if it is not a TLS record
    void dissectDtlsPort(Context &ctx, const char *data, size_t length);       // DTLS on a registered port / Decode As: leaves the packet alone if the bytes are no DTLS
    bool dissectDtlsHeuristic(Context &ctx, const char *data, size_t length);  // DTLS over UDP on any port: the datagram must be nothing but valid records
    void dissectHttp2(Context &ctx, const char *data, size_t length);
    StreamFrame frameHttp2(const char *data, size_t length);
    bool dissectHttp2Heuristic(Context &ctx, const char *data, size_t length);
    void dissectIeee80211(Context &ctx, const char *data, size_t length);
    void dissectRadiotap(Context &ctx, const char *data, size_t length);
    void dissectPpi(Context &ctx, const char *data, size_t length);
    void dissectEapol(Context &ctx, const char *data, size_t length);
    void dissectLlc(Context &ctx, const char *data, size_t length);
    void dissectStp(Context &ctx, const char *data, size_t length);
    void dissectPpp(Context &ctx, const char *data, size_t length);
    void dissectPppoeDiscovery(Context &ctx, const char *data, size_t length);
    void dissectPppoeSession(Context &ctx, const char *data, size_t length);
    void dissectMpls(Context &ctx, const char *data, size_t length);
    void dissectIpInIp(Context &ctx, const char *data, size_t length);        // IP protocol 4 (IPIP) / 41 (IPv6-in-IP)
    void dissectGre(Context &ctx, const char *data, size_t length);           // IP protocol 47, RFC 2784/2890 + ERSPAN
    void dissectLldp(Context &ctx, const char *data, size_t length);          // EtherType 0x88CC, IEEE 802.1AB
    void dissectSlowProtocols(Context &ctx, const char *data, size_t length); // EtherType 0x8809, LACP (subtype 0x01)
    void dissectEthernetControl(Context &ctx, const char *data, size_t length); // EtherType 0x8808, PAUSE / PFC
} // namespace dissect
