// Microsoft Network Monitor 2.x capture files (.cap). Everything is little endian. The frames are located through a
// frame table at the end of the file, so the reader reads the table in open() and then walks it.
//
//   file header, 72 bytes
//     0   4  magic "GMBU"
//     4   1  version, minor        5   1  version, major (2)
//     6   2  MAC (media) type
//     8   16 capture start time as a Windows SYSTEMTIME: year, month, day of week, day, hour, minute, second,
//            milliseconds (eight uint16); taken as UTC
//     24  4  frame table offset    28  4  frame table length (bytes)
//     32  4  user data offset      36  4  user data length
//     40  4  comment offset        44  4  comment length
//     48  4  statistics offset     52  4  statistics length
//     56  4  network info offset   60  4  network info length
//     64  4  conversation stats offset   68  4  conversation stats length
//   frame table: frame table length / 4 uint32 absolute file offsets of the frame records, in capture order
//   frame record, 16 byte header at each offset
//     0   8  time offset from the capture start in microseconds (uint64)
//     8   4  original length     12  4  included length (the frame bytes that follow the header)
//     16  .  included length bytes of frame data (later 2.x revisions append extra data that is ignored)
//
// MAC types: 1 Ethernet -> link type 1; 2 Token Ring -> 6 and 3 FDDI -> 10 (no dissector, "Unsupported link type");
// every other medium (ATM, wireless WAN, ...) is shown as raw data with a note on the load. Version 1.x files
// (a different record layout) are refused with a message.

#include <io/format_registry.h>
#include <io/reader_util.h>

#include <istream>

namespace {
    using namespace core::io;

    constexpr uint64_t kHeaderSize = 72;
    constexpr uint64_t kRecordHeader = 16;

    // days since 1970-01-01 of a proleptic Gregorian date (Howard Hinnant's algorithm)
    int64_t daysFromCivil(int64_t y, unsigned m, unsigned d) {
        y -= m <= 2;
        const int64_t era = (y >= 0 ? y : y - 399) / 400;
        const unsigned yoe = static_cast<unsigned>(y - era * 400);
        const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
        const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        return era * 146097 + static_cast<int64_t>(doe) - 719468;
    }

    class NetMonReader final : public CaptureFileReader {
    public:
        bool open(std::istream &in, ReaderContext &ctx, std::string &message) override {
            in_ = &in;
            fileSize_ = ctx.fileSize;
            uint8_t h[kHeaderSize];
            if (!in.read(reinterpret_cast<char *>(h), sizeof(h))) {
                message = "File is too short to be a Network Monitor file";
                return false;
            }
            if (std::memcmp(h, "GMBU", 4) != 0) {
                message = "Not a Network Monitor file";
                return false;
            }
            const unsigned minor = h[4], major = h[5];
            if (major != 2) {
                message = "Unsupported Network Monitor version " + std::to_string(major) + "." + std::to_string(minor) + " (only 2.x is read)";
                return false;
            }
            const unsigned macType = le16(h + 6);
            switch (macType) {
                case 1: linkType_ = 1; break;
                case 2: linkType_ = 6; break;
                case 3: linkType_ = 10; break;
                default: linkType_ = kUnmappedLinkType; unmapped_ = true; break;
            }
            static const char *const names[] = {"unknown", "Ethernet", "Token Ring", "FDDI", "ATM", "IP over IEEE 1394", "wireless WAN"};
            mediumName_ = "MAC type " + std::to_string(macType) + (macType < 7 ? std::string(" (") + names[macType] + ")" : "");

            // capture start: year, month, day of week, day, hour, minute, second, milliseconds
            const unsigned year = le16(h + 8), month = le16(h + 10), day = le16(h + 14), hour = le16(h + 16), minute = le16(h + 18),
                    second = le16(h + 20), millis = le16(h + 22);
            if (year >= 1970 && month >= 1 && month <= 12 && day >= 1 && day <= 31 && hour < 24 && minute < 60 && second < 61 && millis < 1000) {
                startSeconds_ = static_cast<uint64_t>(daysFromCivil(year, month, day)) * 86400 + hour * 3600 + minute * 60 + second;
                startMicros_ = millis * 1000ull;
            }

            const uint32_t tableOffset = le32(h + 24), tableLength = le32(h + 28);
            if (tableOffset < kHeaderSize || uint64_t(tableOffset) + tableLength > fileSize_) {
                message = "Network Monitor frame table lies outside the file (the file is damaged or cut short)";
                return false;
            }
            const uint64_t count = tableLength / 4;
            in.seekg(static_cast<std::streamoff>(tableOffset));
            std::vector<char> raw(count * 4);
            if (count > 0 && !in.read(raw.data(), static_cast<std::streamsize>(raw.size()))) {
                message = "Network Monitor frame table is unreadable";
                return false;
            }
            table_.resize(count);
            for (uint64_t i = 0; i < count; ++i) table_[i] = le32(reinterpret_cast<const uint8_t *>(raw.data()) + i * 4);

            ctx.info = core::CaptureInfo();
            ctx.info.fileSize = fileSize_;
            ctx.info.format = "Microsoft Network Monitor, version " + std::to_string(major) + "." + std::to_string(minor) + ", " + mediumName_;
            core::InterfaceInfo itf;
            itf.linkType = linkType_;
            itf.ticksPerSecond = 1000000;
            ctx.info.interfaces.push_back(itf);
            consumed_ = sizeof(h);
            return true;
        }

        Status next(CaptureRecord &rec, ReadIssue &issue) override {
            if (index_ >= table_.size()) return Status::End;
            const uint64_t start = table_[index_];
            if (start < kHeaderSize || start + kRecordHeader > fileSize_) {
                issue.message = "Frame " + std::to_string(index_ + 1) + " lies outside the file";
                return Status::End;
            }
            uint8_t h[kRecordHeader];
            in_->clear();
            in_->seekg(static_cast<std::streamoff>(start));
            if (!in_->read(reinterpret_cast<char *>(h), sizeof(h))) {
                issue.message = "Truncated frame header " + std::to_string(index_ + 1);
                return Status::End;
            }
            const uint32_t original = le32(h + 8), included = le32(h + 12);
            if (included > kMaxRecordSize || included > fileSize_ - (start + kRecordHeader)) {
                issue.message = "Truncated or corrupt frame " + std::to_string(index_ + 1);
                return Status::End;
            }
            rec.frame.resize(included);
            if (included > 0 && !in_->read(rec.frame.data(), included)) {
                issue.message = "Failed to read frame " + std::to_string(index_ + 1);
                return Status::End;
            }
            const uint64_t micros = startMicros_ + le64(h);   // wraps only for an absurd offset
            rec.seconds = startSeconds_ + micros / 1000000;
            rec.fraction = micros % 1000000;
            rec.ticksPerSecond = 1000000;
            rec.hasTimestamp = true;
            rec.originalLength = original;
            rec.linkType = linkType_;
            rec.fcsLength = 0;
            rec.fileOffset = start + kRecordHeader;
            rec.interfaceIndex = 0;
            rec.comment.clear();
            consumed_ = std::max(consumed_, rec.fileOffset + included);
            ++index_;
            if (unmapped_) unmappedMedia_.note(mediumName_);
            return Status::Record;
        }

        uint64_t bytesConsumed() const override { return std::min(consumed_, fileSize_); }
        uint64_t minRecordBytes() const override { return kRecordHeader + 4 + 14; }
        void finish(std::string &message) override { unmappedMedia_.report(message); }

    private:
        std::istream *in_ = nullptr;
        uint64_t fileSize_ = 0;
        uint32_t linkType_ = 1;
        bool unmapped_ = false;
        std::string mediumName_;
        UnmappedMedia unmappedMedia_;
        uint64_t startSeconds_ = 0, startMicros_ = 0;
        std::vector<uint32_t> table_;
        size_t index_ = 0;
        uint64_t consumed_ = 0;
    };
} // namespace

std::unique_ptr<core::io::CaptureFileReader> core::io::makeNetMonReader() { return std::make_unique<NetMonReader>(); }
