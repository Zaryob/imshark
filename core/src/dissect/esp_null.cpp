// ESP-NULL heuristic (see esp_null.h)
#include "esp_null.h"

#include "checksum.h"

namespace {
    using namespace dissect;

    uint16_t be16(const uint8_t *p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }

    bool validIcmp(const uint8_t *p, size_t n) {
        if (n < 8) return false;
        static const uint8_t kTypes[] = {0, 3, 4, 5, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18};   // RFC 792 and its successors up to RFC 1256
        bool known = false;
        for (uint8_t t: kTypes) known = known || p[0] == t;
        if (!known) return false;
        // ICMP's checksum covers the whole message and no pseudo header
        return checksumFold(checksumAdd(0, reinterpret_cast<const char *>(p), n)) == 0xffff;
    }

    bool validUdp(const uint8_t *p, size_t n) {
        if (n < 8) return false;
        return be16(p + 4) == n && (be16(p) != 0 || be16(p + 2) != 0);
    }

    bool validTcp(const uint8_t *p, size_t n) {
        if (n < 20) return false;
        const size_t offset = static_cast<size_t>(p[12] >> 4) * 4;
        if (offset < 20 || offset > n) return false;
        if ((p[12] & 0x0e) != 0) return false;           // reserved bits (RFC 9293 3.1; the lowest data offset bit is the NS flag)
        if (be16(p) == 0 || be16(p + 2) == 0) return false;
        // the flag combinations real stacks send (CWR / ECE aside): SYN, SYN+ACK, ACK, PSH+ACK, FIN+ACK, FIN+PSH+ACK, RST, RST+ACK.
        // URG is not among them, so the urgent pointer has to be 0 (RFC 9293 3.1: it is only significant with URG)
        switch (p[13] & 0x3f) {
            case 0x02: case 0x12: case 0x10: case 0x18: case 0x11: case 0x19: case 0x04: case 0x14: break;
            default: return false;
        }
        return be16(p + 18) == 0;
    }

    bool validIpv4(const uint8_t *p, size_t n) {
        if (n < 20 || (p[0] >> 4) != 4) return false;
        const size_t header = static_cast<size_t>(p[0] & 0x0f) * 4;
        if (header < 20 || header > n) return false;
        if (be16(p + 2) != n) return false;              // the datagram is exactly the payload
        return checkIpv4Header(reinterpret_cast<const char *>(p), header).state == kChecksumGood;
    }

    bool validIpv6(const uint8_t *p, size_t n) {
        if (n < 40 || (p[0] >> 4) != 6) return false;
        return be16(p + 4) + 40u == n;
    }

    bool validPayload(uint8_t next, const uint8_t *p, size_t n) {
        switch (next) {
            case 1: return validIcmp(p, n);
            case 4: return validIpv4(p, n);
            case 6: return validTcp(p, n);
            case 17: return validUdp(p, n);
            case 41: return validIpv6(p, n);
            default: return false;
        }
    }

    EspNullResult tryIcv(const uint8_t *body, size_t size, size_t icv) {
        EspNullResult r;
        if (size < icv + 2 + 1) return r;
        const size_t t = size - icv;
        if (t % 4 != 0) return r;
        const size_t padLength = body[t - 2];
        const uint8_t next = body[t - 1];
        if (padLength > 3 || t < 2 + padLength + 1) return r;
        const size_t payload = t - 2 - padLength;
        for (size_t i = 0; i < padLength; ++i) {
            if (body[payload + i] != i + 1) return r;
        }
        if (!validPayload(next, body, payload)) return r;
        r.plaintext = true;
        r.nextHeader = next;
        r.payloadLength = payload;
        r.padLength = padLength;
        r.icvLength = icv;
        return r;
    }
} // namespace

dissect::EspNullResult dissect::inspectEspNull(const uint8_t *body, size_t size) {
    const EspNullResult a = tryIcv(body, size, 12), b = tryIcv(body, size, 16);
    if (a.plaintext && b.plaintext) return {};   // ambiguous: treat as encrypted
    return a.plaintext ? a : b;
}
