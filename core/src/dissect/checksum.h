#pragma once

// Internet checksum (RFC 1071) verification for the IPv4 header and for TCP, UDP, ICMP and ICMPv6, which also need a
// pseudo header (RFC 793 / 2460) made of the addresses of the IP layer below.
//
// Results are stored per packet in two bits per layer (packet::PacketInfo::checksum_state):
//   kNone        no checksum to check (UDP over IPv4 with a zero checksum) or not looked at
//   kGood        the sum over everything is 0xffff
//   kBad         it is not
//   kUnverified  cannot be decided: the capture cut the segment short, or the stored value is what a NIC leaves
//                for checksum offload (zero IPv4 header checksum, or the unfinished pseudo header sum)

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "context.h"

namespace dissect {
    enum ChecksumState : uint8_t { kChecksumNone = 0, kChecksumGood = 1, kChecksumBad = 2, kChecksumUnverified = 3 };

    inline uint32_t checksumAdd(uint32_t sum, const char *p, size_t n) {
        size_t i = 0;
        for (; i + 1 < n; i += 2) sum += (static_cast<uint32_t>(static_cast<uint8_t>(p[i])) << 8) | static_cast<uint8_t>(p[i + 1]);
        if (i < n) sum += static_cast<uint32_t>(static_cast<uint8_t>(p[i])) << 8;   // an odd last byte is padded with zero
        return sum;
    }

    inline uint16_t checksumFold(uint32_t sum) {
        while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
        return static_cast<uint16_t>(sum);
    }

    struct ChecksumResult {
        uint8_t state = kChecksumNone;
        uint16_t stored = 0;
        uint16_t expected = 0;   // what the field should hold (meaningful for kChecksumBad)
    };

    inline void setIpChecksumState(packet::PacketInfo &p, uint8_t s) { p.checksum_state = static_cast<uint8_t>((p.checksum_state & ~0x03) | s); }
    inline void setTransportChecksumState(packet::PacketInfo &p, uint8_t s) { p.checksum_state = static_cast<uint8_t>((p.checksum_state & ~0x0c) | (s << 2)); }
    inline uint8_t ipChecksumState(const packet::PacketInfo &p) { return p.checksum_state & 0x03; }
    inline uint8_t transportChecksumState(const packet::PacketInfo &p) { return (p.checksum_state >> 2) & 0x03; }

    /// IPv4 header checksum over `headerLength` bytes (a zero field is what offloading NICs leave: unverified).
    inline ChecksumResult checkIpv4Header(const char *h, size_t headerLength) {
        ChecksumResult r;
        r.stored = static_cast<uint16_t>((static_cast<uint8_t>(h[10]) << 8) | static_cast<uint8_t>(h[11]));
        uint32_t sum = checksumAdd(0, h, 10);
        sum = checksumAdd(sum, h + 12, headerLength - 12);
        r.expected = static_cast<uint16_t>(~checksumFold(sum));
        r.state = r.stored == 0 ? kChecksumUnverified : (r.expected == r.stored ? kChecksumGood : kChecksumBad);
        return r;
    }

    /// TCP / UDP / ICMPv6 (pseudo header) or ICMPv4 (none) checksum over `needed` bytes of the segment at `d`, of which
    /// `avail` were captured. `field` is the offset of the checksum inside the segment. `pseudoLength` is the length the
    /// pseudo header carries when that is not `needed` (UDP-Lite, RFC 3828: the whole datagram, while the sum covers less).
    inline ChecksumResult checkTransport(const Context &ctx, uint8_t protocol, const char *d, size_t avail, size_t needed, size_t field,
                                         size_t pseudoLength = 0) {
        ChecksumResult r;
        if (needed < field + 2 || avail < needed) { r.state = kChecksumUnverified; return r; }   // cut by the snap length
        r.stored = static_cast<uint16_t>((static_cast<uint8_t>(d[field]) << 8) | static_cast<uint8_t>(d[field + 1]));
        uint32_t pseudo = 0;
        const bool needsPseudo = protocol != 1;
        if (needsPseudo) {
            if (!ctx.addrs.valid) { r.state = kChecksumUnverified; return r; }
            pseudo = checksumAdd(0, reinterpret_cast<const char *>(ctx.addrs.src), ctx.addrs.length);
            pseudo = checksumAdd(pseudo, reinterpret_cast<const char *>(ctx.addrs.dst), ctx.addrs.length);
            const size_t plen = pseudoLength ? pseudoLength : needed;
            if (ctx.addrs.length == 16) {   // IPv6: upper-layer length (32 bits), three zero bytes, next header
                pseudo += static_cast<uint32_t>(plen >> 16) + static_cast<uint32_t>(plen & 0xffff) + protocol;
            } else {
                pseudo += protocol + static_cast<uint32_t>(plen);
            }
        }
        uint32_t sum = checksumAdd(pseudo, d, field);
        sum = checksumAdd(sum, d + field + 2, needed - field - 2);
        // the field sits at an even offset in every protocol handled here, so skipping it keeps the 16-bit alignment
        r.expected = static_cast<uint16_t>(~checksumFold(sum));
        if (protocol == 17 && r.stored == 0) {
            r.state = ctx.addrs.length == 16 ? kChecksumBad : kChecksumNone;                 // IPv4: no checksum used; IPv6: not allowed
            if (r.state == kChecksumBad) r.expected = r.expected == 0 ? 0xffff : r.expected;
            return r;
        }
        if (protocol == 17 && r.expected == 0) r.expected = 0xffff;                           // UDP sends a computed zero as all ones
        if (r.expected == r.stored) { r.state = kChecksumGood; return r; }
        // what a NIC leaves in the field before it completes the checksum: the folded pseudo header sum, not complemented
        if ((protocol == 6 || protocol == 17) && (r.stored == checksumFold(pseudo) || r.stored == 0)) { r.state = kChecksumUnverified; return r; }   // NICs offload TCP and UDP only
        r.state = kChecksumBad;
        return r;
    }

    inline const char *checksumStateText(uint8_t s) {
        switch (s) {
            case kChecksumGood: return "Good";
            case kChecksumBad: return "Bad";
            case kChecksumUnverified: return "Unverified";
            default: return "Not present";
        }
    }

    /// Castagnoli CRC-32 (CRC-32C, polynomial 0x1EDC6F41 reversed 0x82F63B78), used by SCTP (RFC 4960).
    inline uint32_t crc32c(const char *data, size_t n, uint32_t initial = 0xFFFFFFFFU) {
        static constexpr uint32_t table[16] = {
            0x00000000, 0x105ec76f, 0x20bd8ede, 0x30e349b1,
            0x417b1dbc, 0x5125dad3, 0x61c69362, 0x7198540d,
            0x82f63b78, 0x92a8fc17, 0xa24bb5a6, 0xb21572c9,
            0xc38d26c4, 0xd3d3e1ab, 0xe330a81a, 0xf36e6f75
        };
        uint32_t crc = initial;
        const auto *p = reinterpret_cast<const uint8_t *>(data);
        for (size_t i = 0; i < n; ++i) {
            crc ^= p[i];
            crc = (crc >> 4) ^ table[crc & 0x0f];
            crc = (crc >> 4) ^ table[crc & 0x0f];
        }
        return crc ^ 0xFFFFFFFFU;
    }

    /// SCTP CRC-32C verification: checksum field is at offset 8..11, calculated with checksum bytes replaced by zeros.
    inline bool checkSctpCrc32c(const char *packet, size_t n, uint32_t *outStored = nullptr, uint32_t *outCalculated = nullptr) {
        if (n < 12) return false;
        const auto *p = reinterpret_cast<const uint8_t *>(packet);
        // SCTP stores CRC-32C in little-endian byte order (RFC 4960 section 3.1)
        uint32_t stored = static_cast<uint32_t>(p[8]) |
                         (static_cast<uint32_t>(p[9]) << 8) |
                         (static_cast<uint32_t>(p[10]) << 16) |
                         (static_cast<uint32_t>(p[11]) << 24);
        if (outStored) *outStored = stored;

        // Compute over prefix (first 8 bytes: src port, dst port, verification tag)
        uint32_t crc = 0xFFFFFFFFU;
        static constexpr uint32_t table[16] = {
            0x00000000, 0x105ec76f, 0x20bd8ede, 0x30e349b1,
            0x417b1dbc, 0x5125dad3, 0x61c69362, 0x7198540d,
            0x82f63b78, 0x92a8fc17, 0xa24bb5a6, 0xb21572c9,
            0xc38d26c4, 0xd3d3e1ab, 0xe330a81a, 0xf36e6f75
        };
        for (size_t i = 0; i < 8; ++i) {
            crc ^= p[i];
            crc = (crc >> 4) ^ table[crc & 0x0f];
            crc = (crc >> 4) ^ table[crc & 0x0f];
        }
        // 4 zero bytes in place of the checksum field
        for (size_t i = 0; i < 4; ++i) {
            crc = (crc >> 4) ^ table[crc & 0x0f];
            crc = (crc >> 4) ^ table[crc & 0x0f];
        }
        // Rest of the packet
        for (size_t i = 12; i < n; ++i) {
            crc ^= p[i];
            crc = (crc >> 4) ^ table[crc & 0x0f];
            crc = (crc >> 4) ^ table[crc & 0x0f];
        }
        uint32_t calculated = crc ^ 0xFFFFFFFFU;
        if (outCalculated) *outCalculated = calculated;
        return stored == calculated;
    }

    /// CRC-16/DNP (IEEE 1815 / IEC 60870-5-1): polynomial 0x3D65 reflected (0xA6BC), initial value 0, final xor 0xFFFF.
    /// The catalogue check value for "123456789" is 0xEA82. DNP3 stores it little endian after the link header and after
    /// every block of up to 16 user data bytes.
    inline uint16_t crc16dnp(const char *data, size_t n) {
        uint16_t crc = 0;
        const auto *p = reinterpret_cast<const uint8_t *>(data);
        for (size_t i = 0; i < n; ++i) {
            crc ^= p[i];
            for (int bit = 0; bit < 8; ++bit) crc = (crc & 1) ? static_cast<uint16_t>((crc >> 1) ^ 0xA6BC) : static_cast<uint16_t>(crc >> 1);
        }
        return static_cast<uint16_t>(~crc);
    }

    /// The two running sums of the Fletcher checksum (RFC 905 Annex B / ISO 8473, modulo 255): c0 is the sum of the
    /// bytes, c1 the sum of the running c0. For "abcde" they are c0 = 0xF0 and c1 = 0xC8.
    struct FletcherSums { uint8_t c0 = 0, c1 = 0; };

    inline FletcherSums fletcherSums(const char *data, size_t n) {
        uint32_t c0 = 0, c1 = 0;
        const auto *p = reinterpret_cast<const uint8_t *>(data);
        for (size_t i = 0; i < n; ++i) {
            c0 = (c0 + p[i]) % 255;
            c1 = (c1 + c0) % 255;
        }
        return {static_cast<uint8_t>(c0), static_cast<uint8_t>(c1)};
    }

    /// A buffer carries a valid Fletcher checksum when both sums over all of it, check bytes included, are zero.
    inline bool fletcherValid(const char *data, size_t n) {
        const FletcherSums s = fletcherSums(data, n);
        return s.c0 == 0 && s.c1 == 0;
    }

    /// The two check bytes (X high, Y low) RFC 905 Annex B puts at zero-based offset `field` of an `n` byte buffer so
    /// that fletcherValid() holds; the two bytes at `field` are taken as zero whatever they hold. A result byte of 0 is
    /// sent as 255 (both are zero modulo 255). OSPF LSAs (RFC 2328 12.1.7) use it from the byte after the LS age.
    inline uint16_t fletcherCheckBytes(const char *data, size_t n, size_t field) {
        uint32_t c0 = 0, c1 = 0;
        const auto *p = reinterpret_cast<const uint8_t *>(data);
        for (size_t i = 0; i < n; ++i) {
            c0 = (c0 + ((i == field || i == field + 1) ? 0 : p[i])) % 255;
            c1 = (c1 + c0) % 255;
        }
        const int64_t k = static_cast<int64_t>(n) - static_cast<int64_t>(field) - 1;   // L - n in the RFC, n being 1-based
        int64_t x = (k % 255 * c0 - c1) % 255;
        int64_t y = (c1 - (k + 1) % 255 * c0) % 255;
        if (x < 0) x += 255;
        if (y < 0) y += 255;
        if (x == 0) x = 255;
        if (y == 0) y = 255;
        return static_cast<uint16_t>((x << 8) | y);
    }

    /// Verdict for a Fletcher checksum stored at `field`: Good when the sums over the buffer are zero (a stored 00 and a
    /// computed FF are the same value modulo 255, so both are accepted); `expected` is what the field should hold.
    inline ChecksumResult checkFletcher(const char *data, size_t n, size_t field) {
        ChecksumResult r;
        r.stored = static_cast<uint16_t>((static_cast<uint8_t>(data[field]) << 8) | static_cast<uint8_t>(data[field + 1]));
        r.expected = fletcherCheckBytes(data, n, field);
        r.state = fletcherValid(data, n) ? kChecksumGood : kChecksumBad;
        return r;
    }
} // namespace dissect
