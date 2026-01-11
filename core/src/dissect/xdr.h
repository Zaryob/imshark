#pragma once

// XDR (External Data Representation, RFC 4506) reader based on ByteReader.
// In XDR, basic types (int, unsigned, bool, float) are 4-byte big-endian aligned,
// and variable-length data (strings, opaque bytes) are length-prefixed and padded
// to a 4-byte boundary.

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <span>

#include "reader.h"

namespace dissect {

class XdrReader {
public:
    explicit XdrReader(ByteReader &r) : r_(r) {}
    XdrReader(const void *data, size_t size) : ownedReader_(data, size), r_(ownedReader_) {}
    XdrReader(const char *data, size_t size) : ownedReader_(data, size), r_(ownedReader_) {}

    bool ok() const { return r_.ok(); }
    explicit operator bool() const { return r_.ok(); }
    size_t remaining() const { return r_.remaining(); }
    size_t pos() const { return r_.pos(); }

    /// Reads a 32-bit signed integer (XDR int / hyper low part).
    int32_t readInt() {
        return r_.i32_be();
    }

    /// Reads a 32-bit unsigned integer (XDR unsigned int).
    uint32_t readUnsignedInt() {
        return r_.u32_be();
    }

    /// Reads an XDR boolean (4 bytes: 0 for FALSE, 1 for TRUE).
    bool readBool() {
        uint32_t val = r_.u32_be();
        if (!r_.ok()) return false;
        return val != 0;
    }

    /// Reads an XDR hyper (64-bit signed integer, big-endian).
    int64_t readHyper() {
        return r_.i64_be();
    }

    /// Reads an XDR unsigned hyper (64-bit unsigned integer, big-endian).
    uint64_t readUnsignedHyper() {
        return r_.u64_be();
    }

    /// Reads fixed-length opaque data (padded to 4-byte boundary).
    std::span<const uint8_t> readFixedOpaque(size_t len) {
        if (!r_.ok() || r_.remaining() < len) {
            r_.fail();
            return {};
        }
        auto data = r_.readBytes(len);
        size_t pad = (4 - (len % 4)) % 4;
        if (pad > 0) {
            r_.skip(pad);
        }
        return data;
    }

    /// Reads variable-length opaque data (4-byte length prefix, padded to 4-byte boundary).
    std::span<const uint8_t> readOpaque(size_t maxLen = 0xFFFFFFFFU) {
        uint32_t len = r_.u32_be();
        if (!r_.ok() || len > maxLen || r_.remaining() < len) {
            r_.fail();
            return {};
        }
        return readFixedOpaque(len);
    }

    /// Reads an XDR string (4-byte length prefix, padded to 4-byte boundary).
    std::string readString(size_t maxLen = 0xFFFFFFFFU) {
        auto bytes = readOpaque(maxLen);
        if (!r_.ok()) return {};
        return std::string(reinterpret_cast<const char *>(bytes.data()), bytes.size());
    }

    /// Skips padding to ensure 4-byte alignment from current position if needed.
    void align4() {
        size_t rem = r_.pos() % 4;
        if (rem != 0) {
            r_.skip(4 - rem);
        }
    }

private:
    ByteReader ownedReader_;
    ByteReader &r_;
};

} // namespace dissect
