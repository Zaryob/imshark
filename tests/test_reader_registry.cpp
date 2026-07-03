// The capture file reader interface and the format registry (ROADMAP B5).
#include <gtest/gtest.h>

#include <sstream>

#include <core.h>
#include <io/format_registry.h>
#include "support.h"

namespace {
    using core::FileFormat;
    using namespace core::io;

    std::vector<char> pcap(bool nano, const std::vector<std::vector<char>> &frames) {
        std::vector<char> b;
        support::put<uint32_t>(b, nano ? 0xa1b23c4d : 0xa1b2c3d4);
        support::put<uint16_t>(b, 2); support::put<uint16_t>(b, 4);
        support::put<uint32_t>(b, 0); support::put<uint32_t>(b, 0);
        support::put<uint32_t>(b, 65535); support::put<uint32_t>(b, 1);
        uint32_t ts = 100;
        for (const auto &f: frames) {
            support::put<uint32_t>(b, ts++); support::put<uint32_t>(b, 7);
            support::put<uint32_t>(b, uint32_t(f.size())); support::put<uint32_t>(b, uint32_t(f.size() + 2));
            b.insert(b.end(), f.begin(), f.end());
        }
        return b;
    }

    std::vector<uint8_t> bytesOf(const std::vector<char> &v) { return std::vector<uint8_t>(v.begin(), v.end()); }

    // A reader for a headerless record stream in the style of Endace ERF (16 byte big endian record header, no file
    // header) and for a Network Monitor style layout (frame table at the end, frames in the middle): both fit the
    // interface, which is the point of this test.
    class HeaderlessReader final : public CaptureFileReader {
    public:
        bool open(std::istream &in, ReaderContext &ctx, std::string &) override {
            in_ = &in;
            ctx.info.format = "headerless";
            return true; // no file header: the first record starts at offset 0
        }
        Status next(CaptureRecord &rec, ReadIssue &issue) override {
            uint8_t h[16];
            in_->read(reinterpret_cast<char *>(h), 16);
            if (in_->gcount() == 0) return Status::End;
            if (in_->gcount() < 16) { issue.message = "short header"; return Status::Error; }
            const uint16_t rlen = uint16_t(h[10] << 8 | h[11]), wlen = uint16_t(h[14] << 8 | h[15]);
            rec.frame.resize(rlen - 16);
            in_->read(rec.frame.data(), rlen - 16);
            rec.fileOffset = pos_ + 16;
            rec.originalLength = wlen;
            rec.linkType = 1;
            rec.seconds = uint64_t(h[7]);
            rec.fraction = 0;
            rec.ticksPerSecond = 1ull << 32; // ERF timestamps are 32.32 fixed point
            pos_ += rlen;
            return Status::Record;
        }
        uint64_t bytesConsumed() const override { return pos_; }
        uint64_t minRecordBytes() const override { return 16; }
    private:
        std::istream *in_ = nullptr;
        uint64_t pos_ = 0;
    };

    class FrameTableReader final : public CaptureFileReader {
    public:
        // layout: frames back to back, then the table of (uint32 offset, uint32 length) pairs and a uint32 count last
        bool open(std::istream &in, ReaderContext &ctx, std::string &) override {
            in_ = &in;
            in.seekg(-4, std::ios::end);
            uint32_t n = 0;
            in.read(reinterpret_cast<char *>(&n), 4);
            in.seekg(-4 - std::streamoff(n) * 8, std::ios::end);
            for (uint32_t i = 0; i < n; ++i) {
                uint32_t entry[2];
                in.read(reinterpret_cast<char *>(entry), 8);
                table_.push_back({entry[0], entry[1]});
            }
            ctx.info.fileSize = ctx.fileSize;
            return true;
        }
        Status next(CaptureRecord &rec, ReadIssue &) override {
            if (index_ >= table_.size()) return Status::End;
            const auto [offset, length] = table_[index_++];
            in_->seekg(offset);
            rec.frame.resize(length);
            in_->read(rec.frame.data(), length);
            rec.fileOffset = offset;
            rec.originalLength = length;
            rec.seconds = index_;
            rec.fraction = 0;
            return Status::Record;
        }
        uint64_t bytesConsumed() const override { return index_; }
        uint64_t minRecordBytes() const override { return 8; }
    private:
        std::istream *in_ = nullptr;
        std::vector<std::pair<uint32_t, uint32_t>> table_;
        size_t index_ = 0;
    };

    struct Loaded {
        std::vector<CaptureRecord> records;
        std::string message;
        bool opened = false;
        CaptureFileReader::Status last = CaptureFileReader::Status::End;
    };

    Loaded drain(CaptureFileReader &reader, const std::vector<char> &bytes) {
        std::istringstream in(std::string(bytes.begin(), bytes.end()), std::ios::binary);
        core::CaptureInfo info;
        dissect::SessionTables sessions;
        ReaderContext ctx{info, sessions, bytes.size()};
        Loaded out;
        out.opened = reader.open(in, ctx, out.message);
        if (!out.opened) return out;
        CaptureRecord rec;
        ReadIssue issue;
        while ((out.last = reader.next(rec, issue)) == CaptureFileReader::Status::Record) out.records.push_back(rec);
        out.message = issue.message;
        return out;
    }
} // namespace

TEST(ReaderRegistry, ProbesRunInOrderAndEveryFormatButGzipHasAReader) {
    const auto &formats = captureFormats();
    std::vector<FileFormat> order;
    for (const auto &f: formats) order.push_back(f.format);
    const std::vector<FileFormat> expected = {FileFormat::Pcap, FileFormat::Pcapng, FileFormat::Gzip, FileFormat::NetMon,
                                              FileFormat::Snoop, FileFormat::Iptrace, FileFormat::Erf};
    EXPECT_EQ(order, expected);   // ERF has no magic number: its heuristic comes last
    for (const auto &f: formats) {
        const bool readable = f.format == FileFormat::Pcap || f.format == FileFormat::Pcapng || f.format == FileFormat::Snoop || f.format == FileFormat::NetMon || f.format == FileFormat::Erf;
        EXPECT_EQ(f.makeReader != nullptr, readable) << f.name;
        EXPECT_EQ(makeReader(f.format) != nullptr, readable) << f.name;
        EXPECT_EQ(f.container, f.format == FileFormat::Gzip) << f.name;
        EXPECT_EQ(findFormat(f.format), &f);
    }
    EXPECT_EQ(findFormat(FileFormat::Unknown), nullptr);
    EXPECT_EQ(makeReader(FileFormat::Unknown), nullptr);
}

TEST(ReaderRegistry, IdentifiesMagicNumbersAndKeepsGzipApartFromErf) {
    auto id = [](const std::vector<char> &b) { const auto u = bytesOf(b); return identifyFormat(u.data(), u.size()); };
    EXPECT_EQ(id(pcap(false, {})), FileFormat::Pcap);
    EXPECT_EQ(id(support::hex("0a 0d 0d 0a 00 00 00 00")), FileFormat::Pcapng);
    // RFC 1952 header: 1f 8b, CM 8, FLG 0, MTIME, XFL 2, OS 3, then data. The bytes at 8..15 look like a plausible ERF record
    // header (type 2 = Ethernet, rlen 0x1000, wlen 0x0100), which the gzip probe has to win over.
    const auto gz = support::hex("1f 8b 08 00 00 00 00 00 02 03 10 00 aa bb 01 00");
    EXPECT_EQ(id(gz), FileFormat::Gzip);
    auto notGzip = gz;
    notGzip[2] = 0x07;   // not deflate: falls through to the ERF heuristic
    EXPECT_EQ(id(notGzip), FileFormat::Erf);
    EXPECT_EQ(id(support::hex("1f 8b")), FileFormat::Unknown);   // too short to be sure
    EXPECT_EQ(id({}), FileFormat::Unknown);
}

TEST(ReaderRegistry, DiagnosticsNameTheFormatOrTheMagicNumber) {
    EXPECT_EQ(core::unsupportedFormatDiagnostic(FileFormat::Iptrace), "Unsupported file format: AIX iptrace");
    EXPECT_EQ(core::unsupportedFormatDiagnostic(FileFormat::Snoop), "");
    EXPECT_EQ(core::unsupportedFormatDiagnostic(FileFormat::NetMon), "");
    EXPECT_EQ(core::unsupportedFormatDiagnostic(FileFormat::Erf), "");
    EXPECT_EQ(core::unsupportedFormatDiagnostic(FileFormat::Gzip), "Unsupported file format: gzip compressed capture (decompress it first)");
    EXPECT_EQ(core::unsupportedFormatDiagnostic(FileFormat::Pcap), "");
    EXPECT_EQ(core::unsupportedFormatDiagnostic(FileFormat::Pcapng), "");
    EXPECT_EQ(core::unsupportedFormatDiagnostic(FileFormat::Unknown), "");
    const auto elf = bytesOf(support::hex("7f 45 4c 46 02 01"));
    EXPECT_EQ(core::unknownFormatDiagnostic(elf.data(), elf.size()), "Unsupported file format: unknown magic number 7f 45 4c 46");
    EXPECT_EQ(core::unknownFormatDiagnostic(elf.data(), 3), "");

    // through processFile: an unrecognised file, a gzip file, a file too short to have a magic number
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    auto path = support::writeTemp("registry_elf.bin", support::hex("7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00"));
    EXPECT_FALSE(fp.processFile(path, packets, message));
    EXPECT_EQ(message, "Unsupported file format: unknown magic number 7f 45 4c 46");
    path = support::writeTemp("registry_gz.bin", support::hex("1f 8b 08 00 00 00 00 00 00 03 03 00 00 00 00 00 00 00 00 00"));
    EXPECT_FALSE(fp.processFile(path, packets, message));
    EXPECT_EQ(message, "Unsupported file format: gzip compressed capture (decompress it first)");
    path = support::writeTemp("registry_short.bin", support::hex("7f 45"));
    EXPECT_FALSE(fp.processFile(path, packets, message));
    EXPECT_EQ(message, "File is too short to be a PCAP file");
    std::remove(path.c_str());
}

TEST(ReaderRegistry, PcapReaderHandsOverRecordsWithOffsetsAndTimestamps) {
    const std::vector<char> f1 = support::hex("00 11 22 33"), f2 = support::hex("44 55");
    const auto bytes = pcap(true, {f1, f2});
    auto reader = makeReader(FileFormat::Pcap);
    ASSERT_TRUE(reader);
    const auto loaded = drain(*reader, bytes);
    ASSERT_TRUE(loaded.opened);
    EXPECT_EQ(loaded.last, CaptureFileReader::Status::End);
    ASSERT_EQ(loaded.records.size(), 2u);
    EXPECT_EQ(loaded.records[0].fileOffset, 24u + 16u);
    EXPECT_EQ(loaded.records[1].fileOffset, 24u + 16u + 4u + 16u);
    EXPECT_EQ(loaded.records[0].frame, f1);
    EXPECT_EQ(loaded.records[1].originalLength, 4u);
    EXPECT_EQ(loaded.records[0].seconds, 100u);
    EXPECT_EQ(loaded.records[0].fraction, 7u);
    EXPECT_EQ(loaded.records[0].ticksPerSecond, 1000000000u);   // nanosecond magic
    EXPECT_EQ(loaded.records[0].interfaceIndex, 0);
    EXPECT_EQ(reader->bytesConsumed(), bytes.size());
    // the offset is where the frame is: this is what Replay reads again
    EXPECT_EQ(std::vector<char>(bytes.begin() + 24 + 16, bytes.begin() + 24 + 16 + 4), f1);
}

TEST(ReaderRegistry, TruncatedPcapEndsWithAWarningAndEmptyPcapngIsAnError) {
    auto bytes = pcap(false, {support::hex("00 11 22 33"), support::hex("44 55 66 77")});
    bytes.resize(bytes.size() - 2);   // the last frame is cut
    auto reader = makeReader(FileFormat::Pcap);
    const auto loaded = drain(*reader, bytes);
    EXPECT_EQ(loaded.last, CaptureFileReader::Status::End);
    EXPECT_EQ(loaded.records.size(), 1u);
    EXPECT_EQ(loaded.message, "Truncated or corrupt packet 2");

    // pcapng: open() cannot tell an empty file from a good one, the first next() does; nothing was read, so nothing is kept
    auto ng = makeReader(FileFormat::Pcapng);
    std::istringstream in(std::string(), std::ios::binary);
    core::CaptureInfo info;
    dissect::SessionTables sessions;
    ReaderContext ctx{info, sessions, 0};
    std::string message;
    ASSERT_TRUE(ng->open(in, ctx, message));
    CaptureRecord rec;
    ReadIssue issue;
    EXPECT_EQ(ng->next(rec, issue), CaptureFileReader::Status::Error);
    EXPECT_EQ(issue.message, "Not a pcapng file");
    EXPECT_FALSE(issue.keepRecords);
}

TEST(ReaderRegistry, TheInterfaceFitsHeaderlessAndTableAtTheEndFraming) {
    {   // ERF style: no file header, offsets are those of the frame bytes after each 16 byte record header
        std::vector<char> b;
        for (int r = 0; r < 3; ++r) {
            std::vector<char> h(16, 0);
            h[7] = char(r + 1);
            h[8] = 2;
            const size_t payload = 4 + size_t(r);
            h[10] = 0; h[11] = char(16 + payload);
            h[15] = char(payload + 2);
            b.insert(b.end(), h.begin(), h.end());
            for (size_t i = 0; i < payload; ++i) b.push_back(char(0x40 + r * 16 + int(i)));
        }
        HeaderlessReader reader;
        const auto loaded = drain(reader, b);
        ASSERT_EQ(loaded.records.size(), 3u);
        for (size_t r = 0; r < 3; ++r) {
            const auto &rec = loaded.records[r];
            EXPECT_EQ(std::vector<char>(b.begin() + rec.fileOffset, b.begin() + rec.fileOffset + rec.frame.size()), rec.frame);
            EXPECT_EQ(rec.seconds, r + 1);
        }
        EXPECT_EQ(reader.bytesConsumed(), b.size());
    }
    {   // Network Monitor style: frames first, the table that locates them last
        std::vector<char> b;
        std::vector<std::pair<uint32_t, uint32_t>> table;
        for (int r = 0; r < 3; ++r) {
            table.push_back({uint32_t(b.size()), uint32_t(5 + r)});
            for (int i = 0; i < 5 + r; ++i) b.push_back(char(r * 10 + i));
        }
        for (const auto &[o, l]: table) { support::put<uint32_t>(b, o); support::put<uint32_t>(b, l); }
        support::put<uint32_t>(b, uint32_t(table.size()));
        FrameTableReader reader;
        const auto loaded = drain(reader, b);
        ASSERT_EQ(loaded.records.size(), 3u);
        for (size_t r = 0; r < 3; ++r) {
            EXPECT_EQ(loaded.records[r].fileOffset, table[r].first);
            EXPECT_EQ(std::vector<char>(b.begin() + table[r].first, b.begin() + table[r].first + table[r].second), loaded.records[r].frame);
        }
    }
}
