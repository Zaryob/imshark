// Sun snoop (RFC 1761). Everything is big endian.
//
//   file header, 16 bytes
//     0   8  identification pattern "snoop\0\0\0"
//     8   4  version number (2)
//     12  4  datalink type (table below)
//   packet record, repeated
//     0   4  original length (on the wire)
//     4   4  included length (captured; the frame bytes that follow)
//     8   4  packet record length: this 24 byte header + the data + padding to a multiple of 4
//     12  4  cumulative drops
//     16  4  timestamp seconds (since 1970)
//     20  4  timestamp microseconds
//     24  .  included length bytes of frame data, then the padding
//
// Datalink types of RFC 1761: 0 IEEE 802.3, 1 IEEE 802.4 token bus, 2 IEEE 802.5 token ring, 3 IEEE 802.6 metro net,
// 4 Ethernet, 5 HDLC, 6 character synchronous, 7 IBM channel-to-channel, 8 FDDI, 9 other.
// Mapping to link types: 0 and 4 -> Ethernet (1); 2 -> Token Ring (6) and 8 -> FDDI (10), which have no dissector
// (the packet list says "Unsupported link type"); everything else is shown as raw data with a note on the load.

#include <io/format_registry.h>
#include <io/reader_util.h>

#include <istream>

namespace {
    using namespace core::io;

    constexpr uint64_t kRecordHeader = 24;

    const char *datalinkName(uint32_t type) {
        static const char *names[] = {"IEEE 802.3", "IEEE 802.4 token bus", "IEEE 802.5 token ring", "IEEE 802.6 metro net", "Ethernet",
                                      "HDLC", "character synchronous", "IBM channel-to-channel", "FDDI", "other"};
        return type < 10 ? names[type] : "unassigned";
    }

    class SnoopReader final : public CaptureFileReader {
    public:
        bool open(std::istream &in, ReaderContext &ctx, std::string &message) override {
            in_ = &in;
            fileSize_ = ctx.fileSize;
            uint8_t h[16];
            if (!in.read(reinterpret_cast<char *>(h), sizeof(h))) {
                message = "File is too short to be a snoop file";
                return false;
            }
            if (std::memcmp(h, "snoop\0\0\0", 8) != 0) {
                message = "Not a snoop file";
                return false;
            }
            const uint32_t version = be32(h + 8);
            if (version != 2) {
                message = "Unsupported snoop version " + std::to_string(version) + " (only version 2 is defined)";
                return false;
            }
            const uint32_t datalink = be32(h + 12);
            switch (datalink) {
                case 0:
                case 4: linkType_ = 1; break;
                case 2: linkType_ = 6; break;
                case 8: linkType_ = 10; break;
                default: linkType_ = kUnmappedLinkType; unmapped_ = true; break;
            }
            mediumName_ = std::string("datalink type ") + std::to_string(datalink) + " (" + datalinkName(datalink) + ")";

            ctx.info = core::CaptureInfo();
            ctx.info.fileSize = fileSize_;
            ctx.info.format = "Sun snoop, version " + std::to_string(version) + ", " + mediumName_;
            core::InterfaceInfo itf;
            itf.linkType = linkType_;
            itf.ticksPerSecond = 1000000;
            ctx.info.interfaces.push_back(itf);
            consumed_ = sizeof(h);
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
            const uint32_t original = be32(h), included = be32(h + 4), recordLength = be32(h + 8);
            // the record length covers header, data and padding; a value that does not is damage, and so is data that is not in the file
            if (recordLength < kRecordHeader + uint64_t(included) || included > kMaxRecordSize || included > remainingBytes(*in_, fileSize_)) {
                issue.message = "Truncated or corrupt packet " + std::to_string(count_ + 1);
                return Status::End;
            }
            rec.frame.resize(included);
            if (included > 0 && !in_->read(rec.frame.data(), included)) {
                issue.message = "Failed to read packet " + std::to_string(count_ + 1);
                return Status::End;
            }
            const uint64_t padding = recordLength - kRecordHeader - included;
            if (padding > 0) in_->ignore(static_cast<std::streamsize>(padding));

            rec.seconds = be32(h + 16);
            rec.fraction = be32(h + 20);
            rec.ticksPerSecond = 1000000;
            rec.hasTimestamp = true;
            rec.originalLength = original;
            rec.linkType = linkType_;
            rec.fcsLength = 0;
            rec.fileOffset = consumed_ + kRecordHeader;
            rec.interfaceIndex = 0;
            rec.comment.clear();
            consumed_ += recordLength;
            ++count_;
            if (unmapped_) unmappedMedia_.note(mediumName_);
            return Status::Record;
        }

        uint64_t bytesConsumed() const override { return std::min(consumed_, fileSize_); }
        uint64_t minRecordBytes() const override { return kRecordHeader + 14; }
        void finish(std::string &message) override { unmappedMedia_.report(message); }

    private:
        std::istream *in_ = nullptr;
        uint64_t fileSize_ = 0;
        uint32_t linkType_ = 1;
        bool unmapped_ = false;
        std::string mediumName_;
        UnmappedMedia unmappedMedia_;
        uint64_t consumed_ = 0;
        uint64_t count_ = 0;
    };
} // namespace

std::unique_ptr<core::io::CaptureFileReader> core::io::makeSnoopReader() { return std::make_unique<SnoopReader>(); }
