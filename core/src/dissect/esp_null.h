#pragma once

// The ESP-NULL heuristic (RFC 4303 + RFC 2410): ESP with the NULL encryption algorithm carries its payload in the clear, but nothing
// in the packet says so - the algorithms are negotiated out of band (IKE). The heuristic decides from the bytes whether an ESP
// packet looks like that. A wrong "plaintext" would show invented protocol content, so it is deliberately strict: every one of the
// conditions below has to hold and, where the two common ICV sizes both fit, the answer is "encrypted".
//
// An ESP packet is SPI (4) | Sequence Number (4) | Payload Data | Padding | Pad Length (1) | Next Header (1) | ICV (RFC 4303 2). Seen
// from the bytes after the Sequence Number, with T = size - ICV:
//   - the ICV is 12 bytes (HMAC-MD5-96 / HMAC-SHA1-96) or 16 bytes (HMAC-SHA-256-128 / AES-GMAC and friends); exactly one fits
//   - T is a multiple of 4 (RFC 4303 2.4: Pad Length and Next Header are right aligned in a 32-bit word, and NULL has block size 4)
//   - Pad Length is at most 3 and the padding bytes are 1, 2, 3 ... (the default padding of RFC 4303 2.4)
//   - Next Header is ICMP, IPv4, TCP, UDP or IPv6 (ICMPv6 is left out: its checksum needs the pseudo header and its other fields do
//     not constrain random bytes enough)
//   - the payload is a valid header of that protocol that accounts for its length exactly (IPv4: version, header length, a total length
//     equal to the payload, a correct header checksum; IPv6: version, payload length; UDP: length field; TCP: data offset, reserved
//     bits, one of the usual flag combinations and a zero urgent pointer; ICMP: known type, correct checksum)
// Random bytes (cipher text) are taken for ESP-NULL with a probability of about 1e-10 per packet (the product of the trailer check,
// about 1e-5, and the check of the payload header, 1e-5 or less); tests/test_esp_null.cpp measures it on millions of random packets.

#include <cstddef>
#include <cstdint>

namespace dissect {
    struct EspNullResult {
        bool plaintext = false;     // the payload looks unencrypted (ESP-NULL)
        uint8_t nextHeader = 0;     // protocol of the payload
        size_t payloadLength = 0;   // bytes of payload data (after the Sequence Number)
        size_t padLength = 0;
        size_t icvLength = 0;
    };

    /// `body` is the ESP packet after SPI and Sequence Number, `size` its length.
    EspNullResult inspectEspNull(const uint8_t *body, size_t size);
} // namespace dissect
