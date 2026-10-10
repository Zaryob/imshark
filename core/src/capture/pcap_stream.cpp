#include "pcap_stream.h"

#include <algorithm>

namespace capture {
    namespace {
        constexpr size_t kHeaderSize = 24, kRecordHeaderSize = 16;
        constexpr uint32_t kMagicMicro = 0xa1b2c3d4, kMagicMicroSwapped = 0xd4c3b2a1;
        constexpr uint32_t kMagicNano = 0xa1b23c4d, kMagicNanoSwapped = 0x4d3cb2a1;
        constexpr uint32_t kMaxLinkType = 0xffff;   // LINKTYPE_ values are small; the upper bits of the field are FCS flags
    } // namespace

    uint32_t PcapStreamParser::u32(const char *p) const {
        const auto *b = reinterpret_cast<const unsigned char *>(p);
        if (header_.bigEndian) return (uint32_t(b[0]) << 24) | (uint32_t(b[1]) << 16) | (uint32_t(b[2]) << 8) | b[3];
        return (uint32_t(b[3]) << 24) | (uint32_t(b[2]) << 16) | (uint32_t(b[1]) << 8) | b[0];
    }

    uint16_t PcapStreamParser::u16(const char *p) const {
        const auto *b = reinterpret_cast<const unsigned char *>(p);
        return header_.bigEndian ? static_cast<uint16_t>((b[0] << 8) | b[1]) : static_cast<uint16_t>((b[1] << 8) | b[0]);
    }

    bool PcapStreamParser::fail(const std::string &text) {
        failed_ = true;
        error_ = text;
        buffer_.clear();
        return false;
    }

    bool PcapStreamParser::parseHeader() {
        const char *p = buffer_.data();
        const auto *b = reinterpret_cast<const unsigned char *>(p);
        const uint32_t magicLe = (uint32_t(b[3]) << 24) | (uint32_t(b[2]) << 16) | (uint32_t(b[1]) << 8) | b[0];
        PcapStreamHeader h;
        switch (magicLe) {
            case kMagicMicro: break;
            case kMagicMicroSwapped: h.bigEndian = true; break;
            case kMagicNano: h.nanosecond = true; break;
            case kMagicNanoSwapped: h.bigEndian = true; h.nanosecond = true; break;
            default: return fail("The capture helper sent data that is not a pcap stream (bad magic number)");
        }
        header_ = h;     // u16 / u32 need the byte order
        const uint16_t major = u16(p + 4);
        if (major != 2) return fail("The capture helper sent an unsupported pcap version " + std::to_string(major));
        h.snaplen = u32(p + 16);
        if (h.snaplen == 0 || h.snaplen > kMaxStreamSnaplen) return fail("The capture helper sent an invalid snapshot length (" + std::to_string(h.snaplen) + ")");
        const uint32_t linkRaw = u32(p + 20);
        h.linkType = linkRaw & 0x0fffffff;
        if (h.linkType > kMaxLinkType) return fail("The capture helper sent an invalid link type (" + std::to_string(h.linkType) + ")");
        header_ = h;
        headerSeen_ = true;
        if (onHeader_ && !onHeader_(header_)) return fail("The capture stream was refused");
        return true;
    }

    bool PcapStreamParser::parseRecordHeader() {
        const char *p = buffer_.data();
        recSeconds_ = u32(p);
        recFraction_ = u32(p + 4);
        recCaptured_ = u32(p + 8);
        recOriginal_ = u32(p + 12);
        if (recCaptured_ > header_.snaplen) {
            return fail("The capture helper sent a packet longer than the snapshot length (" + std::to_string(recCaptured_) + " > " +
                        std::to_string(header_.snaplen) + ")");
        }
        if (recCaptured_ > kMaxStreamSnaplen) return fail("The capture helper sent an oversized packet (" + std::to_string(recCaptured_) + " bytes)");
        if (recFraction_ >= (header_.nanosecond ? 1000000000u : 1000000u)) return fail("The capture helper sent a packet with an invalid timestamp");
        if (recCaptured_ == 0) {
            ++records_;
            if (onRecord_) onRecord_(recSeconds_, header_.nanosecond ? recFraction_ / 1000 : recFraction_, "", 0, recOriginal_);
            return true;
        }
        inRecord_ = true;
        return true;
    }

    bool PcapStreamParser::feed(const char *data, size_t size) {
        if (failed_) return false;
        consumed_ += size;
        size_t pos = 0;
        while (pos < size) {
            const size_t need = !headerSeen_ ? kHeaderSize : inRecord_ ? recCaptured_ : kRecordHeaderSize;
            const size_t take = std::min(need - buffer_.size(), size - pos);
            buffer_.insert(buffer_.end(), data + pos, data + pos + take);
            pos += take;
            if (buffer_.size() < need) break;
            if (!headerSeen_) {
                if (!parseHeader()) return false;
            } else if (!inRecord_) {
                if (!parseRecordHeader()) return false;
            } else {
                ++records_;
                if (onRecord_) onRecord_(recSeconds_, header_.nanosecond ? recFraction_ / 1000 : recFraction_, buffer_.data(), recCaptured_, recOriginal_);
                inRecord_ = false;
            }
            buffer_.clear();
        }
        return true;
    }

    bool PcapStreamParser::finish() {
        if (failed_) return false;
        if (!headerSeen_) return fail(buffer_.empty() ? "The capture helper sent no data" : "The capture helper's data ended inside the pcap header");
        if (inRecord_ || !buffer_.empty()) return fail("The capture helper's data ended inside a packet record");
        return true;
    }
} // namespace capture
