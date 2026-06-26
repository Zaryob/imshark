// Classic pcap (libpcap savefile): a 24 byte global header, then records of a 16 byte header and the captured bytes.
// The magic number gives both the byte order and the timestamp precision of the file.

#include <io/format_registry.h>
#include <io/reader_util.h>

#include <istream>

namespace {
    using namespace core::io;

    class PcapReader final : public CaptureFileReader {
    public:
        bool open(std::istream &in, ReaderContext &ctx, std::string &message) override {
            in_ = &in;
            fileSize_ = ctx.fileSize;
            uint8_t gh[24];
            if (!in.read(reinterpret_cast<char *>(gh), sizeof(gh))) {
                message = "File is too short to be a PCAP file";
                return false;
            }

            uint32_t magic;
            std::memcpy(&magic, gh, sizeof(magic));
            if (magic == kPcapMagicMicro || magic == kPcapMagicNano) {
                e_.swap = false;
            } else if (magic == swap32(kPcapMagicMicro) || magic == swap32(kPcapMagicNano)) {
                e_.swap = true;
            } else {
                const core::FileFormat fmt = identifyFormat(gh, sizeof(gh));
                const std::string diag = core::unsupportedFormatDiagnostic(fmt);
                message = diag.empty() ? "Incompatible PCAP file format" : diag;
                return false;
            }
            if (e_.u32(gh) == kPcapMagicNano) fractionsPerSecond_ = 1000000000;

            // The low 16 bits of the "network" field are the LINKTYPE; bits 28..31 carry the FCS length
            // when the FCS-present flag (bit 29) is set.
            const uint32_t rawLinkType = e_.u32(gh + 20);
            linkType_ = rawLinkType & 0xFFFF;
            // Bits 28..31: bit 28 says that an FCS length is given, bits 29..31 hold it in units of 16 bits
            // (pcap savefile format). 0x50000001 therefore means "Ethernet, 4 FCS bytes"; without bit 28 nothing is known.
            fcsLen_ = (rawLinkType & 0x10000000u) ? static_cast<uint8_t>(((rawLinkType >> 29) & 0x7) * 2) : 0;

            ctx.info = core::CaptureInfo();
            ctx.info.fileSize = fileSize_;
            ctx.info.format = std::string("pcap (") + (e_.swap ? "big" : "little") + " endian, " +
                              (fractionsPerSecond_ == 1000000000 ? "nanosecond" : "microsecond") + " timestamps), version " +
                              std::to_string(e_.u16(gh + 4)) + "." + std::to_string(e_.u16(gh + 6));
            core::InterfaceInfo itf;
            itf.linkType = linkType_;
            itf.snapLen = e_.u32(gh + 16);
            itf.ticksPerSecond = fractionsPerSecond_;
            itf.fcsLength = fcsLen_;
            ctx.info.interfaces.push_back(itf);
            consumed_ = sizeof(gh);
            return true;
        }

        Status next(CaptureRecord &rec, ReadIssue &issue) override {
            uint8_t ph[16];
            in_->read(reinterpret_cast<char *>(ph), sizeof(ph));
            const auto got = in_->gcount();
            if (got == 0) return Status::End; // clean end of file
            if (got < static_cast<std::streamsize>(sizeof(ph))) {
                issue.message = "Truncated packet header after packet " + std::to_string(count_);
                return Status::End;
            }

            const uint32_t inclLen = e_.u32(ph + 8);
            if (inclLen > kMaxRecordSize || inclLen > remainingBytes(*in_, fileSize_)) {
                issue.message = "Truncated or corrupt packet " + std::to_string(count_ + 1);
                return Status::End;
            }
            rec.frame.resize(inclLen);
            if (inclLen > 0 && !in_->read(rec.frame.data(), inclLen)) {
                issue.message = "Failed to read packet " + std::to_string(count_ + 1);
                return Status::End;
            }

            rec.seconds = e_.u32(ph);
            rec.fraction = e_.u32(ph + 4);
            rec.ticksPerSecond = fractionsPerSecond_;
            rec.hasTimestamp = true;
            rec.originalLength = e_.u32(ph + 12);
            rec.linkType = linkType_;
            rec.fcsLength = fcsLen_;
            rec.fileOffset = consumed_ + sizeof(ph);
            rec.interfaceIndex = 0;
            rec.comment.clear();
            consumed_ = rec.fileOffset + inclLen;
            ++count_;
            return Status::Record;
        }

        uint64_t bytesConsumed() const override { return consumed_; }
        uint64_t minRecordBytes() const override { return 16 + 28; }

    private:
        std::istream *in_ = nullptr;
        Endian e_;
        uint64_t fileSize_ = 0;
        uint64_t fractionsPerSecond_ = 1000000;
        uint32_t linkType_ = 1;
        uint8_t fcsLen_ = 0;
        uint64_t consumed_ = 0;
        uint64_t count_ = 0;
    };
} // namespace

std::unique_ptr<core::io::CaptureFileReader> core::io::makePcapReader() { return std::make_unique<PcapReader>(); }
