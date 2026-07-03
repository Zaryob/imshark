// Endace ERF (Extensible Record Format). A file is a plain sequence of records, there is no file header: the first
// record starts at offset 0. Per the Endace ERF Types Reference:
//
//   record header, 16 bytes
//     0   8  timestamp, LITTLE endian 32.32 fixed point: upper 32 bits seconds since 1970, lower 32 bits the fraction
//     8   1  type: bits 0..6 record type, bit 7 set = an extension header follows
//     9   1  flags: bits 0..1 capture interface, bit 2 varlen, bit 3 truncated, bit 4 rx error, bit 5 ds error
//     10  2  record length (rlen): header + extension headers + type header + data + padding   (big endian)
//     12  2  loss counter (lctr)   (big endian)
//     14  2  wire length (wlen)    (big endian)
//   extension headers, 8 bytes each while bit 7 of the first byte of the previous one is set (0 or more)
//   type header: Ethernet records (types 2, 11, 16, 20) have a 2 byte pad before the frame
//   data: the frame, captured length = min(what is left of rlen, wlen); the rest of rlen is padding
//
// Record types: 1 HDLC_POS, 2 ETH, 3 ATM, 4 AAL5, 5 MC_HDLC, 6 MC_RAW, 7 MC_ATM, 8 MC_RAW_CHANNEL, 9 MC_AAL5, 10 COLOR_HDLC_POS,
// 11 COLOR_ETH, 12 MC_AAL2, 13 IP_COUNTER, 14 TCP_FLOW_COUNTER, 15 DSM_COLOR_HDLC_POS, 16 DSM_COLOR_ETH, 17 COLOR_MC_HDLC_POS,
// 18 AAL2, 19 COLOR_HASH_POS, 20 COLOR_HASH_ETH, 21 INFINIBAND, 22 IPV4, 23 IPV6, 24 RAW_LINK, 25 INFINIBAND_LINK, 26 META, 27 OPA_SNC.
// Mapping: Ethernet types -> link type 1; IPV4 and IPV6 -> raw IP (101); the packet-over-SONET types (1, 10, 15, 17, 19)
// when the frame starts with the PPP-in-HDLC address and control bytes ff 03 -> PPP (9) with those two bytes dropped
// (Cisco HDLC and the rest are raw data); counters (13, 14) and META (26) carry no packet and are skipped; every other
// type (ATM, AAL, multi-channel, InfiniBand, ...) is shown as raw data with a note on the load.

#include <io/format_registry.h>
#include <io/reader_util.h>

#include <istream>

namespace {
    using namespace core::io;

    constexpr uint64_t kHeaderSize = 16;
    constexpr uint64_t kExtensionSize = 8;
    constexpr uint64_t kTicksPerSecond = 1ull << 32;

    bool isEthernet(unsigned type) { return type == 2 || type == 11 || type == 16 || type == 20; }
    bool isPos(unsigned type) { return type == 1 || type == 10 || type == 15 || type == 17 || type == 19; }
    bool carriesNoPacket(unsigned type) { return type == 13 || type == 14 || type == 26; }

    class ErfReader final : public CaptureFileReader {
    public:
        bool open(std::istream &in, ReaderContext &ctx, std::string &) override {
            in_ = &in;
            ctx_ = &ctx;
            fileSize_ = ctx.fileSize;
            ctx.info = core::CaptureInfo();
            ctx.info.fileSize = fileSize_;
            ctx.info.format = "Endace ERF";
            return true;   // no file header: the first record starts at offset 0
        }

        Status next(CaptureRecord &rec, ReadIssue &issue) override {
            while (true) {
                uint8_t h[kHeaderSize];
                in_->read(reinterpret_cast<char *>(h), sizeof(h));
                const auto got = in_->gcount();
                if (got == 0) return Status::End;
                if (got < static_cast<std::streamsize>(sizeof(h))) {
                    issue.message = "Truncated record header after record " + std::to_string(records_);
                    return Status::End;
                }
                const unsigned type = h[8] & 0x7F;
                const bool extended = (h[8] & 0x80) != 0;
                const unsigned interface = h[9] & 3;
                const uint32_t rlen = be16(h + 10), wlen = be16(h + 14);
                if (rlen < kHeaderSize) {
                    issue.message = "Corrupt record header after record " + std::to_string(records_);
                    return Status::End;
                }
                uint64_t available = rlen - kHeaderSize;   // bytes of this record after the header
                if (available > remainingBytes(*in_, fileSize_)) {
                    issue.message = "Truncated or corrupt record " + std::to_string(records_ + 1);
                    return Status::End;
                }
                const uint64_t start = consumed_;
                consumed_ += rlen;
                ++records_;
                uint64_t position = start + kHeaderSize;   // file offset of the next unread byte of the record

                // extension headers: the top bit of the first byte says that another one follows
                bool more = extended, damaged = false;
                while (more) {
                    uint8_t ext[kExtensionSize];
                    if (available < kExtensionSize || !in_->read(reinterpret_cast<char *>(ext), sizeof(ext))) { damaged = true; break; }
                    available -= kExtensionSize;
                    position += kExtensionSize;
                    more = (ext[0] & 0x80) != 0;
                }
                const uint64_t typeHeader = isEthernet(type) ? 2 : 0;
                if (!damaged && available < typeHeader) damaged = true;
                if (damaged) {
                    issue.message = "Record " + std::to_string(records_) + " is shorter than its headers";
                    return Status::End;
                }
                if (typeHeader > 0) {
                    in_->ignore(static_cast<std::streamsize>(typeHeader));
                    available -= typeHeader;
                    position += typeHeader;
                }

                // the frame: whatever wire length says, but never more than the record holds (the rest is padding)
                const uint64_t captured = (wlen != 0 && wlen < available) ? wlen : available;
                if (carriesNoPacket(type)) {
                    in_->ignore(static_cast<std::streamsize>(available));
                    continue;
                }
                rec.frame.resize(captured);
                if (captured > 0 && !in_->read(rec.frame.data(), static_cast<std::streamsize>(captured))) {
                    issue.message = "Failed to read record " + std::to_string(records_);
                    return Status::End;
                }
                if (available > captured) in_->ignore(static_cast<std::streamsize>(available - captured));

                uint32_t linkType = kUnmappedLinkType;
                uint32_t original = std::max<uint32_t>(wlen, static_cast<uint32_t>(captured));
                if (isEthernet(type)) {
                    linkType = 1;
                } else if (type == 22 || type == 23) {
                    linkType = 101;
                } else if (isPos(type) && captured >= 2 && static_cast<uint8_t>(rec.frame[0]) == 0xff && static_cast<uint8_t>(rec.frame[1]) == 0x03) {
                    rec.frame.erase(rec.frame.begin(), rec.frame.begin() + 2);   // the PPP dissector starts at the protocol field
                    position += 2;
                    original = original >= 2 ? original - 2 : 0;
                    linkType = 9;
                } else {
                    unmapped_.note("ERF record type " + std::to_string(type));
                }

                const uint64_t ts = le64(h);
                rec.seconds = ts >> 32;
                rec.fraction = ts & 0xFFFFFFFFull;
                rec.ticksPerSecond = kTicksPerSecond;
                rec.hasTimestamp = true;
                rec.originalLength = original;
                rec.linkType = linkType;
                rec.fcsLength = 0;
                rec.fileOffset = position;
                rec.interfaceIndex = interfaces_.find(ctx_->info, uint64_t(linkType) << 2 | interface, linkType, kTicksPerSecond,
                                                      "ERF interface " + std::to_string(interface));
                rec.comment.clear();
                return Status::Record;
            }
        }

        uint64_t bytesConsumed() const override { return std::min(consumed_, fileSize_); }
        uint64_t minRecordBytes() const override { return kHeaderSize + 2 + 14; }
        void finish(std::string &message) override { unmapped_.report(message); }

    private:
        std::istream *in_ = nullptr;
        ReaderContext *ctx_ = nullptr;
        uint64_t fileSize_ = 0;
        InterfaceTable interfaces_;
        UnmappedMedia unmapped_;
        uint64_t consumed_ = 0;
        uint64_t records_ = 0;
    };
} // namespace

std::unique_ptr<core::io::CaptureFileReader> core::io::makeErfReader() { return std::make_unique<ErfReader>(); }
