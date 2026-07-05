// AIX iptrace 2.0 (the documented subset; the byte layout below is the one libwiretap's iptrace reader uses and has not
// been compared with a file written by AIX, see docs/KNOWN_ISSUES.md). Everything is big endian.
//
//   file header: the 11 characters "iptrace 2.0"; the first record follows at offset 11
//   packet record, repeated
//     0   4  record length: this 40 byte header + the frame bytes
//     4   24 not used by ImShark (unknown / interface name and unit)
//     28  1  interface type (ifnet type, table below)
//     29  1  direction: 0 received, 1 transmitted (not shown)
//     30  2  not used
//     32  4  timestamp seconds (since 1970)
//     36  4  timestamp nanoseconds
//     40  .  record length - 40 bytes of frame data
//
// iptrace stores no wire length, so the original length is the captured length. Interface types: 0x06 Ethernet and
// 0x07 IEEE 802.3 -> link type 1; 0x09 token ring -> 6 and 0x0f FDDI -> 10 (no dissector, "Unsupported link type");
// anything else (loopback, SLIP, X.25, ATM, ...) is shown as raw data with a note on the load. iptrace 1.0 files
// (a different header) are refused with a message.

#include <io/format_registry.h>
#include <io/reader_util.h>

#include <istream>

namespace {
    using namespace core::io;

    constexpr uint64_t kMagicSize = 11;
    constexpr uint64_t kRecordHeader = 40;

    class IptraceReader final : public CaptureFileReader {
    public:
        bool open(std::istream &in, ReaderContext &ctx, std::string &message) override {
            in_ = &in;
            ctx_ = &ctx;
            fileSize_ = ctx.fileSize;
            char magic[kMagicSize];
            if (!in.read(magic, sizeof(magic))) {
                message = "File is too short to be an iptrace file";
                return false;
            }
            if (std::memcmp(magic, "iptrace 1.0", kMagicSize) == 0) {
                message = "Unsupported iptrace version 1.0 (only 2.0 is read)";
                return false;
            }
            if (std::memcmp(magic, "iptrace 2.0", kMagicSize) != 0) {
                message = "Not an iptrace file";
                return false;
            }
            ctx.info = core::CaptureInfo();
            ctx.info.fileSize = fileSize_;
            ctx.info.format = "AIX iptrace 2.0";
            consumed_ = kMagicSize;
            return true;
        }

        Status next(CaptureRecord &rec, ReadIssue &issue) override {
            uint8_t h[kRecordHeader];
            in_->read(reinterpret_cast<char *>(h), sizeof(h));
            const auto got = in_->gcount();
            if (got == 0) return Status::End;
            if (got < static_cast<std::streamsize>(sizeof(h))) {
                issue.message = "Truncated packet header after packet " + std::to_string(count_);
                return Status::End;
            }
            const uint32_t recordLength = be32(h);
            if (recordLength < kRecordHeader || recordLength - kRecordHeader > kMaxRecordSize ||
                recordLength - kRecordHeader > remainingBytes(*in_, fileSize_)) {
                issue.message = "Truncated or corrupt packet " + std::to_string(count_ + 1);
                return Status::End;
            }
            const uint32_t captured = recordLength - static_cast<uint32_t>(kRecordHeader);
            rec.frame.resize(captured);
            if (captured > 0 && !in_->read(rec.frame.data(), captured)) {
                issue.message = "Failed to read packet " + std::to_string(count_ + 1);
                return Status::End;
            }

            const uint8_t ifType = h[28];
            uint32_t linkType = kUnmappedLinkType;
            switch (ifType) {
                case 0x06:
                case 0x07: linkType = 1; break;
                case 0x09: linkType = 6; break;
                case 0x0f: linkType = 10; break;
                default: unmapped_.note("interface type 0x" + hex2(ifType)); break;
            }
            rec.seconds = be32(h + 32);
            rec.fraction = be32(h + 36);
            rec.ticksPerSecond = 1000000000;
            rec.hasTimestamp = true;
            rec.originalLength = captured;
            rec.linkType = linkType;
            rec.fcsLength = 0;
            rec.fileOffset = consumed_ + kRecordHeader;
            rec.interfaceIndex = interfaces_.find(ctx_->info, ifType, linkType, 1000000000, "interface type 0x" + hex2(ifType));
            rec.comment.clear();
            consumed_ += recordLength;
            ++count_;
            return Status::Record;
        }

        uint64_t bytesConsumed() const override { return std::min(consumed_, fileSize_); }
        uint64_t minRecordBytes() const override { return kRecordHeader + 14; }
        void finish(std::string &message) override { unmapped_.report(message); }

    private:
        static std::string hex2(uint8_t v) {
            static const char *digits = "0123456789abcdef";
            return std::string{digits[v >> 4], digits[v & 15]};
        }

        std::istream *in_ = nullptr;
        ReaderContext *ctx_ = nullptr;
        uint64_t fileSize_ = 0;
        InterfaceTable interfaces_;
        UnmappedMedia unmapped_;
        uint64_t consumed_ = 0;
        uint64_t count_ = 0;
    };
} // namespace

std::unique_ptr<core::io::CaptureFileReader> core::io::makeIptraceReader() { return std::make_unique<IptraceReader>(); }
