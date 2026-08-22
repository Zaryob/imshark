#pragma once

#include <string>

#include "context.h"

namespace dissect {
    /// Notes that the packet has an AH header (RFC 4302) with this SPI and sequence number: sets PacketInfo::has_ah and, in the load
    /// pass, records the pair in the session tables (packet::IpsecTable). Used by dissectAh and the IPv6 extension header walk.
    void noteAhHeader(Context &ctx, uint32_t spi, uint32_t sequence);

    /// The name of an IP protocol number as the IPsec headers show it in their Next Header field ("TCP (6)").
    std::string ipsecProtocolName(uint8_t protocol);

    /// Dissects IPsec Authentication Header (AH, IP protocol 51) - RFC 4302
    void dissectAh(Context &ctx, const char *data, size_t length);

    /// Dissects IPsec Encapsulating Security Payload (ESP, IP protocol 50) - RFC 4303
    void dissectEsp(Context &ctx, const char *data, size_t length);

    /// Dissects Internet Key Exchange (IKEv1 / IKEv2 / ISAKMP, UDP port 500 / 4500) - RFC 2408 / 7296
    void dissectIke(Context &ctx, const char *data, size_t length);
} // namespace dissect
