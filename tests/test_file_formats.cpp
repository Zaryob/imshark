#include <gtest/gtest.h>
#include <core.h>
#include "support.h"
#include "json_lite.h"
#include <fstream>

#include <vector>
#include <string>

namespace {
    std::vector<char> makeNetMonSample() {
        // NetMon 2.x header starts with "GMBU"
        std::vector<char> buf = {'G', 'M', 'B', 'U', 0, 2, 0, 0};
        buf.resize(128, 0);
        return buf;
    }

    std::vector<char> makeSnoopSample() {
        // Sun snoop header starts with "snoop\0\0\0"
        std::vector<char> buf = {'s', 'n', 'o', 'o', 'p', 0, 0, 0};
        buf.resize(128, 0);
        return buf;
    }

    std::vector<char> makeErfSample() {
        // ERF record header:
        // ts (8 bytes), type (1 byte: 2 = ETH), flags (1 byte), rlen (2 bytes BE: 64), lctr (2 bytes), wlen (2 bytes BE: 60)
        std::vector<char> buf(64, 0);
        buf[8] = 2; // TYPE_ETH
        buf[9] = 0; // flags
        buf[10] = 0; // rlen MSB
        buf[11] = 64; // rlen LSB (64 bytes)
        buf[12] = 0;
        buf[13] = 0;
        buf[14] = 0; // wlen MSB
        buf[15] = 60; // wlen LSB (60 bytes)
        return buf;
    }

    std::vector<char> makeIptrace1Sample() {
        // AIX iptrace 1.0 header starts with "iptrace 1.0"
        std::string magic = "iptrace 1.0";
        std::vector<char> buf(magic.begin(), magic.end());
        buf.resize(64, 0);
        return buf;
    }

    std::vector<char> makeIptrace2Sample() {
        // AIX iptrace 2.0 header starts with "iptrace 2.0"
        std::string magic = "iptrace 2.0";
        std::vector<char> buf(magic.begin(), magic.end());
        buf.resize(64, 0);
        return buf;
    }
} // namespace

TEST(FileFormats, FormatIdentificationAndDiagnostics) {
    // 1. NetMon: a reader exists now (tests/test_capture_readers.cpp); the sample has no frame table
    {
        const auto path = support::writeTemp("sample.cap", makeNetMonSample());
        EXPECT_EQ(core::detectFileFormat(path), core::FileFormat::NetMon);
        EXPECT_EQ(std::string(core::formatName(core::FileFormat::NetMon)), "Microsoft Network Monitor");
        EXPECT_EQ(core::unsupportedFormatDiagnostic(core::FileFormat::NetMon), "");

        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        bool ok = fp.processFile(path, packets, message);
        EXPECT_FALSE(ok);
        EXPECT_EQ(message, "Network Monitor frame table lies outside the file (the file is damaged or cut short)");
        std::remove(path.c_str());
    }

    // 2. Sun snoop: a reader exists now (tests/test_capture_readers.cpp); the all-zero sample has version 0
    {
        const auto path = support::writeTemp("sample.snoop", makeSnoopSample());
        EXPECT_EQ(core::detectFileFormat(path), core::FileFormat::Snoop);
        EXPECT_EQ(std::string(core::formatName(core::FileFormat::Snoop)), "Sun snoop");
        EXPECT_EQ(core::unsupportedFormatDiagnostic(core::FileFormat::Snoop), "");

        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        bool ok = fp.processFile(path, packets, message);
        EXPECT_FALSE(ok);
        EXPECT_EQ(message, "Unsupported snoop version 0 (only version 2 is defined)");
        std::remove(path.c_str());
    }

    // 3. Endace ERF
    {
        const auto path = support::writeTemp("sample.erf", makeErfSample());
        EXPECT_EQ(core::detectFileFormat(path), core::FileFormat::Erf);
        EXPECT_EQ(std::string(core::formatName(core::FileFormat::Erf)), "Endace ERF");
        EXPECT_EQ(core::unsupportedFormatDiagnostic(core::FileFormat::Erf), "");

        // the sample is one Ethernet record (rlen 64, wlen 60) of zero bytes: a reader exists now, the frame has 46 bytes
        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        bool ok = fp.processFile(path, packets, message);
        EXPECT_TRUE(ok) << message;
        ASSERT_EQ(packets.size(), 1u);
        EXPECT_EQ(packets[0].captured_length, 46u);
        std::remove(path.c_str());
    }

    // 4. AIX iptrace 1.0 & 2.0: the 2.0 reader exists now, 1.0 is refused with a message
    {
        const auto path1 = support::writeTemp("sample1.iptrace", makeIptrace1Sample());
        EXPECT_EQ(core::detectFileFormat(path1), core::FileFormat::Iptrace);
        EXPECT_EQ(std::string(core::formatName(core::FileFormat::Iptrace)), "AIX iptrace");
        EXPECT_EQ(core::unsupportedFormatDiagnostic(core::FileFormat::Iptrace), "");

        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        bool ok = fp.processFile(path1, packets, message);
        EXPECT_FALSE(ok);
        EXPECT_EQ(message, "Unsupported iptrace version 1.0 (only 2.0 is read)");
        std::remove(path1.c_str());

        // the 2.0 sample is the magic followed by zeros: the first record claims length 0, which is damage, but the file is a valid empty capture
        const auto path2 = support::writeTemp("sample2.iptrace", makeIptrace2Sample());
        EXPECT_EQ(core::detectFileFormat(path2), core::FileFormat::Iptrace);
        ok = fp.processFile(path2, packets, message);
        EXPECT_TRUE(ok) << message;
        EXPECT_TRUE(packets.empty());
        EXPECT_EQ(message, "Truncated or corrupt packet 1");
        std::remove(path2.c_str());
    }
}

namespace {
    const core::FileFormat kUnknown = core::FileFormat::Unknown;

    core::FileFormat detect(const std::vector<char> &bytes) {
        const auto path = support::writeTemp("probe.bin", bytes);
        const auto fmt = core::detectFileFormat(path);
        std::remove(path.c_str());
        return fmt;
    }

    // pcap global header (24 bytes) with no packets: magic 0xa1b2c3d4, version 2.4, snaplen 65535, link type 1
    std::vector<char> pcapHeader(bool bigEndian, bool nano) {
        std::vector<char> b;
        support::put<uint32_t>(b, nano ? 0xa1b23c4d : 0xa1b2c3d4, bigEndian);
        support::put<uint16_t>(b, 2, bigEndian);
        support::put<uint16_t>(b, 4, bigEndian);
        support::put<uint32_t>(b, 0, bigEndian);
        support::put<uint32_t>(b, 0, bigEndian);
        support::put<uint32_t>(b, 65535, bigEndian);
        support::put<uint32_t>(b, 1, bigEndian);
        return b;
    }
} // namespace

// Magic numbers (independent of the code): pcap 0xa1b2c3d4 / 0xa1b23c4d, pcapng 0x0a0d0d0a, Microsoft NetMon "GMBU",
// Sun snoop "snoop\0\0\0", AIX "iptrace 1.0"/"iptrace 2.0"
TEST(FileFormats, PcapAndPcapngRoutingIsUnchanged) {
    EXPECT_EQ(detect(pcapHeader(false, false)), core::FileFormat::Pcap);
    EXPECT_EQ(detect(pcapHeader(true, false)), core::FileFormat::Pcap);
    EXPECT_EQ(detect(pcapHeader(false, true)), core::FileFormat::Pcap);
    EXPECT_EQ(detect(pcapHeader(true, true)), core::FileFormat::Pcap);
    EXPECT_EQ(detect({'\x0a', '\x0d', '\x0d', '\x0a', 0, 0, 0, 0}), core::FileFormat::Pcapng);

    // an empty pcap loads through processFile (the legacy routing)
    const auto path = support::writeTemp("empty.pcap", pcapHeader(false, false));
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    EXPECT_TRUE(fp.processFile(path, packets, message)) << message;
    EXPECT_TRUE(packets.empty());
    std::remove(path.c_str());
}

TEST(FileFormats, EveryTruncatedMagicIsEitherItsFormatOrUnknown) {
    struct Sample { std::vector<char> bytes; core::FileFormat format; size_t magicLength; };
    const std::vector<Sample> samples = {
        {makeNetMonSample(), core::FileFormat::NetMon, 4},
        {makeSnoopSample(), core::FileFormat::Snoop, 8},
        {makeIptrace1Sample(), core::FileFormat::Iptrace, 11},
        {makeIptrace2Sample(), core::FileFormat::Iptrace, 11},
        {pcapHeader(false, false), core::FileFormat::Pcap, 4},
        {pcapHeader(true, true), core::FileFormat::Pcap, 4},
        {makeErfSample(), core::FileFormat::Erf, 16},
    };
    for (const auto &s: samples) {
        for (size_t n = 0; n <= 32 && n <= s.bytes.size(); ++n) {
            const std::vector<char> cut(s.bytes.begin(), s.bytes.begin() + n);
            const auto fmt = detect(cut);
            if (n >= s.magicLength) EXPECT_EQ(fmt, s.format) << "length " << n;
            else EXPECT_TRUE(fmt == s.format || fmt == kUnknown) << "length " << n;
            // loading never crashes whatever the length
            const auto path = support::writeTemp("cut.bin", cut);
            core::FileProcessor fp;
            std::vector<packet::PacketInfo> packets;
            std::string message;
            fp.processFile(path, packets, message);
            // every recognised format has a reader now: the "unsupported file format" diagnostic is for unknown magic numbers only
            if (fmt != kUnknown) EXPECT_EQ(message.find("Unsupported file format: " + std::string(core::formatName(fmt))), std::string::npos) << message;
            std::remove(path.c_str());
        }
    }
}

TEST(FileFormats, MutatedHeadersNeverCrashAndKeepTheMagicRouting) {
    uint32_t seed = 7;
    auto next = [&seed]() { seed = seed * 1664525u + 1013904223u; return seed >> 8; };
    const std::vector<std::vector<char>> seeds = {makeNetMonSample(), makeSnoopSample(), makeIptrace1Sample(), makeErfSample(),
                                                  pcapHeader(false, false), pcapHeader(true, true)};
    for (int round = 0; round < 300; ++round) {
        std::vector<char> b = seeds[next() % seeds.size()];
        for (int i = 0, flips = 1 + int(next() % 3); i < flips; ++i) b[next() % b.size()] = static_cast<char>(next());
        b.resize(next() % (b.size() + 1));
        const auto path = support::writeTemp("mut.bin", b);
        const auto fmt = core::detectFileFormat(path);
        // the detected format follows the leading bytes, not the rest
        uint32_t first = 0;
        std::memcpy(&first, b.data(), std::min<size_t>(4, b.size()));
        if (b.size() >= 4 && (first == 0xa1b2c3d4 || first == 0xa1b23c4d || first == 0xd4c3b2a1 || first == 0x4d3cb2a1)) EXPECT_EQ(fmt, core::FileFormat::Pcap);
        if (b.size() >= 4 && first == 0x0a0d0d0a) EXPECT_EQ(fmt, core::FileFormat::Pcapng);
        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        fp.processFile(path, packets, message);
        std::remove(path.c_str());
    }
}

TEST(FileFormats, ErfDetectionNeedsAPlausibleFirstRecordHeader) {
    auto erf = makeErfSample();
    EXPECT_EQ(detect(erf), core::FileFormat::Erf);
    erf[8] = 0;       // type 0 (legacy) is not claimed
    EXPECT_EQ(detect(erf), kUnknown);
    erf[8] = 2;
    erf[11] = 8;      // record length below the 16 byte header
    EXPECT_EQ(detect(erf), kUnknown);
    erf[11] = 64;
    erf[15] = 100;    // wire length above the record length
    EXPECT_EQ(detect(erf), kUnknown);
    erf[9] = 0x08;    // ... which is what a record cut by the capture length looks like: the truncated flag
    EXPECT_EQ(detect(erf), core::FileFormat::Erf);
}

TEST(FileFormats, CaptureFilesOfTheRepositoryAreDetectedAsTheirFormat) {
    std::ifstream mf(std::string(IMSHARK_TEST_DATA_DIR) + "/../corpus/manifest.json", std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(mf)), std::istreambuf_iterator<char>());
    const auto manifest = testutil::JsonParser(text).parse();
    int checked = 0;
    for (const auto &e: manifest.at("entries").items) {
        if (e.str("kind") != "synthetic") continue;
        const std::string path = std::string(IMSHARK_TEST_DATA_DIR) + "/../corpus/" + e.str("file");
        if (!std::ifstream(path)) continue;
        const std::string format = e.str("format");
        const core::FileFormat expected = format == "pcapng" ? core::FileFormat::Pcapng : format == "snoop" ? core::FileFormat::Snoop
                                          : format == "netmon" ? core::FileFormat::NetMon : format == "erf" ? core::FileFormat::Erf
                                          : format == "iptrace" ? core::FileFormat::Iptrace : core::FileFormat::Pcap;
        EXPECT_EQ(core::detectFileFormat(path), expected) << e.str("file");
        ++checked;
    }
    EXPECT_GT(checked, 0);
}

TEST(FileFormats, RealCapturesWhenAvailable) {
    const char *dir = std::getenv("IMSHARK_CORPUS_DIR");
    if (!dir) GTEST_SKIP() << "set IMSHARK_CORPUS_DIR to a directory with the captures listed in tests/corpus/manifest.json";
    std::ifstream mf(std::string(IMSHARK_TEST_DATA_DIR) + "/../corpus/manifest.json", std::ios::binary);
    const std::string text((std::istreambuf_iterator<char>(mf)), std::istreambuf_iterator<char>());
    const auto manifest = testutil::JsonParser(text).parse();
    int checked = 0;
    for (const auto &e: manifest.at("entries").items) {
        const std::string path = std::string(dir) + "/" + e.str("file");
        if (!std::ifstream(path)) continue;
        EXPECT_EQ(core::detectFileFormat(path), e.str("format") == "pcapng" ? core::FileFormat::Pcapng : core::FileFormat::Pcap) << e.str("file");
        ++checked;
    }
    if (checked == 0) GTEST_SKIP() << "no manifest capture is present in " << dir;
}
