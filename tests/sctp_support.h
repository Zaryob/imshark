#pragma once

// Hand-built SCTP packets for the SCTP tests. The CRC-32C here is an independent bitwise implementation (reflected
// polynomial 0x82F63B78, initial value and final xor 0xffffffff); the tests check it against crc32c("123456789") == 0xe3069283
// and against values computed by a Python script, so the dissector's own CRC code is not what makes the packets valid.
#include <cstdint>
#include <string>
#include <vector>

#include "frame_sweep.h"

namespace sctptest {
    using framesweep::Bytes;

    inline uint32_t crc32c(const Bytes &data) {
        uint32_t crc = 0xffffffffu;
        for (uint8_t b: data) {
            crc ^= b;
            for (int i = 0; i < 8; ++i) crc = (crc >> 1) ^ ((crc & 1) ? 0x82F63B78u : 0);
        }
        return ~crc;
    }

    inline void put16(Bytes &b, uint16_t v) { b.push_back(static_cast<uint8_t>(v >> 8)); b.push_back(static_cast<uint8_t>(v)); }
    inline void put32(Bytes &b, uint32_t v) { put16(b, static_cast<uint16_t>(v >> 16)); put16(b, static_cast<uint16_t>(v)); }
    inline Bytes cat(std::initializer_list<Bytes> parts) { Bytes out; for (const auto &p: parts) out.insert(out.end(), p.begin(), p.end()); return out; }
    inline Bytes text(const std::string &s) { return Bytes(s.begin(), s.end()); }
    inline void pad4(Bytes &b) { while (b.size() % 4) b.push_back(0); }

    /// A chunk: type, flags, Length = 4 + body, padded to 4 bytes. `length` overrides the Length field (damaged chunks).
    inline Bytes chunk(uint8_t type, uint8_t flags, const Bytes &body, int length = -1) {
        Bytes c = {type, flags};
        put16(c, static_cast<uint16_t>(length >= 0 ? length : 4 + body.size()));
        c.insert(c.end(), body.begin(), body.end());
        pad4(c);
        return c;
    }
    /// A TLV parameter / error cause.
    inline Bytes tlv(uint16_t type, const Bytes &value, int length = -1) {
        Bytes p;
        put16(p, type);
        put16(p, static_cast<uint16_t>(length >= 0 ? length : 4 + value.size()));
        p.insert(p.end(), value.begin(), value.end());
        pad4(p);
        return p;
    }
    /// DATA chunk (RFC 9260 3.3.1): flags are I|U|B|E
    inline Bytes data(uint8_t flags, uint32_t tsn, uint16_t stream, uint16_t ssn, uint32_t ppid, const std::string &user) {
        Bytes body;
        put32(body, tsn); put16(body, stream); put16(body, ssn); put32(body, ppid);
        const Bytes u = text(user);
        body.insert(body.end(), u.begin(), u.end());
        return chunk(0, flags, body);
    }
    /// I-DATA chunk (RFC 8260 2.1): the field after the MID is the PPID in the first fragment (B bit) and the FSN otherwise
    inline Bytes idata(uint8_t flags, uint32_t tsn, uint16_t stream, uint32_t mid, uint32_t ppidOrFsn, const std::string &user) {
        Bytes body;
        put32(body, tsn); put16(body, stream); put16(body, 0); put32(body, mid); put32(body, ppidOrFsn);
        const Bytes u = text(user);
        body.insert(body.end(), u.begin(), u.end());
        return chunk(64, flags, body);
    }

    /// The SCTP packet (common header + chunks) with its CRC-32C (stored little endian, RFC 9260 appendix A)
    inline Bytes sctpPacket(uint16_t sport, uint16_t dport, uint32_t vtag, const Bytes &chunks) {
        Bytes p;
        put16(p, sport); put16(p, dport); put32(p, vtag); put32(p, 0);
        p.insert(p.end(), chunks.begin(), chunks.end());
        const uint32_t crc = crc32c(p);
        for (int i = 0; i < 4; ++i) p[8 + i] = static_cast<uint8_t>(crc >> (8 * i));
        return p;
    }

    inline Bytes ipFrame(const Bytes &sctpPacket, Bytes src = {10, 0, 0, 1}, Bytes dst = {10, 0, 0, 2}) {
        return framesweep::ethernet(0x0800, framesweep::ipv4Packet(132, sctpPacket, src, dst));
    }

    inline std::string treeText(const std::vector<packet::Field> &fields) {
        std::string out;
        for (const auto &f: fields) out += f.text + "\n" + treeText(f.children);
        return out;
    }
    inline bool has(const std::string &haystack, const std::string &needle) { return haystack.find(needle) != std::string::npos; }
} // namespace sctptest
