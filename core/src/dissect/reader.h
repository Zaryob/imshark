#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <string_view>

namespace dissect {

/// Sınır denetimli, big/little endian bayt okuyucu.
/// Herhangi bir okuma sınırları aşarsa okuyucu hata durumuna geçer (ok() == false)
/// ve sonraki tüm okumalar 0 / boş döner.
class ByteReader {
public:
    ByteReader() : data_(nullptr), size_(0), pos_(0), ok_(false) {}

    ByteReader(const void *data, size_t size)
        : data_(static_cast<const uint8_t *>(data)), size_(size), pos_(0), ok_(data != nullptr || size == 0) {}

    ByteReader(const uint8_t *data, size_t size)
        : data_(data), size_(size), pos_(0), ok_(data != nullptr || size == 0) {}

    ByteReader(const char *data, size_t size)
        : data_(reinterpret_cast<const uint8_t *>(data)), size_(size), pos_(0), ok_(data != nullptr || size == 0) {}

    explicit ByteReader(std::span<const uint8_t> s)
        : data_(s.data()), size_(s.size()), pos_(0), ok_(true) {}

    explicit ByteReader(std::string_view sv)
        : data_(reinterpret_cast<const uint8_t *>(sv.data())), size_(sv.size()), pos_(0), ok_(true) {}

    bool ok() const { return ok_; }
    explicit operator bool() const { return ok_; }

    size_t offset() const { return pos_; }
    size_t pos() const { return pos_; }
    size_t size() const { return size_; }
    size_t remaining() const { return (ok_ && pos_ <= size_) ? (size_ - pos_) : 0; }
    bool empty() const { return remaining() == 0; }

    const uint8_t *data() const { return data_; }
    const uint8_t *current() const { return (data_ && pos_ <= size_) ? (data_ + pos_) : nullptr; }

    void fail() { ok_ = false; }

    bool skip(size_t n) {
        if (!ok_ || remaining() < n) {
            fail();
            return false;
        }
        pos_ += n;
        return true;
    }

    bool seek(size_t newPos) {
        if (!ok_ || newPos > size_) {
            fail();
            return false;
        }
        pos_ = newPos;
        return true;
    }

    uint8_t peek_u8() const {
        if (!ok_ || remaining() < 1) return 0;
        return data_[pos_];
    }

    uint8_t u8() {
        if (!ok_ || remaining() < 1) {
            fail();
            return 0;
        }
        return data_[pos_++];
    }

    int8_t i8() {
        return static_cast<int8_t>(u8());
    }

    uint16_t u16_be() {
        if (!ok_ || remaining() < 2) {
            fail();
            return 0;
        }
        const uint16_t val = (static_cast<uint16_t>(data_[pos_]) << 8) |
                             static_cast<uint16_t>(data_[pos_ + 1]);
        pos_ += 2;
        return val;
    }

    uint16_t u16_le() {
        if (!ok_ || remaining() < 2) {
            fail();
            return 0;
        }
        const uint16_t val = static_cast<uint16_t>(data_[pos_]) |
                             (static_cast<uint16_t>(data_[pos_ + 1]) << 8);
        pos_ += 2;
        return val;
    }

    uint16_t u16() { return u16_be(); }
    int16_t i16_be() { return static_cast<int16_t>(u16_be()); }
    int16_t i16_le() { return static_cast<int16_t>(u16_le()); }
    int16_t i16() { return i16_be(); }

    uint32_t u24_be() {
        if (!ok_ || remaining() < 3) {
            fail();
            return 0;
        }
        const uint32_t val = (static_cast<uint32_t>(data_[pos_]) << 16) |
                             (static_cast<uint32_t>(data_[pos_ + 1]) << 8) |
                             static_cast<uint32_t>(data_[pos_ + 2]);
        pos_ += 3;
        return val;
    }

    uint32_t u24_le() {
        if (!ok_ || remaining() < 3) {
            fail();
            return 0;
        }
        const uint32_t val = static_cast<uint32_t>(data_[pos_]) |
                             (static_cast<uint32_t>(data_[pos_ + 1]) << 8) |
                             (static_cast<uint32_t>(data_[pos_ + 2]) << 16);
        pos_ += 3;
        return val;
    }

    uint32_t u24() { return u24_be(); }

    uint32_t u32_be() {
        if (!ok_ || remaining() < 4) {
            fail();
            return 0;
        }
        const uint32_t val = (static_cast<uint32_t>(data_[pos_]) << 24) |
                             (static_cast<uint32_t>(data_[pos_ + 1]) << 16) |
                             (static_cast<uint32_t>(data_[pos_ + 2]) << 8) |
                             static_cast<uint32_t>(data_[pos_ + 3]);
        pos_ += 4;
        return val;
    }

    uint32_t u32_le() {
        if (!ok_ || remaining() < 4) {
            fail();
            return 0;
        }
        const uint32_t val = static_cast<uint32_t>(data_[pos_]) |
                             (static_cast<uint32_t>(data_[pos_ + 1]) << 8) |
                             (static_cast<uint32_t>(data_[pos_ + 2]) << 16) |
                             (static_cast<uint32_t>(data_[pos_ + 3]) << 24);
        pos_ += 4;
        return val;
    }

    uint32_t u32() { return u32_be(); }
    int32_t i32_be() { return static_cast<int32_t>(u32_be()); }
    int32_t i32_le() { return static_cast<int32_t>(u32_le()); }
    int32_t i32() { return i32_be(); }

    uint64_t u64_be() {
        if (!ok_ || remaining() < 8) {
            fail();
            return 0;
        }
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i) {
            val = (val << 8) | static_cast<uint64_t>(data_[pos_ + i]);
        }
        pos_ += 8;
        return val;
    }

    uint64_t u64_le() {
        if (!ok_ || remaining() < 8) {
            fail();
            return 0;
        }
        uint64_t val = 0;
        for (int i = 7; i >= 0; --i) {
            val = (val << 8) | static_cast<uint64_t>(data_[pos_ + i]);
        }
        pos_ += 8;
        return val;
    }

    uint64_t u64() { return u64_be(); }
    int64_t i64_be() { return static_cast<int64_t>(u64_be()); }
    int64_t i64_le() { return static_cast<int64_t>(u64_le()); }
    int64_t i64() { return i64_be(); }

    /// len baytlık alt okuyucu döndürür ve pos'u len kadar ilerletir.
    ByteReader sub(size_t len) {
        if (!ok_ || remaining() < len) {
            fail();
            ByteReader bad;
            bad.fail();
            return bad;
        }
        ByteReader child(data_ + pos_, len);
        pos_ += len;
        return child;
    }

    std::span<const uint8_t> readBytes(size_t len) {
        if (!ok_ || remaining() < len) {
            fail();
            return {};
        }
        std::span<const uint8_t> res(data_ + pos_, len);
        pos_ += len;
        return res;
    }

    bool readBytes(void *dest, size_t len) {
        if (!ok_ || remaining() < len) {
            fail();
            return false;
        }
        if (dest && len > 0) {
            std::memcpy(dest, data_ + pos_, len);
        }
        pos_ += len;
        return true;
    }

    std::string readString(size_t len) {
        if (!ok_ || remaining() < len) {
            fail();
            return {};
        }
        std::string s(reinterpret_cast<const char *>(data_ + pos_), len);
        pos_ += len;
        return s;
    }

    std::span<const uint8_t> remainingBytes() {
        return readBytes(remaining());
    }

    std::string remainingString() {
        return readString(remaining());
    }

private:
    const uint8_t *data_ = nullptr;
    size_t size_ = 0;
    size_t pos_ = 0;
    bool ok_ = true;
};

} // namespace dissect
