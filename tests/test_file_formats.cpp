#include <gtest/gtest.h>
#include <core.h>
#include "support.h"

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
    // 1. NetMon
    {
        const auto path = support::writeTemp("sample.cap", makeNetMonSample());
        EXPECT_EQ(core::detectFileFormat(path), core::FileFormat::NetMon);
        EXPECT_EQ(std::string(core::formatName(core::FileFormat::NetMon)), "Microsoft Network Monitor");
        EXPECT_EQ(core::unsupportedFormatDiagnostic(core::FileFormat::NetMon),
                  "Desteklenmeyen dosya biçimi: Microsoft Network Monitor");

        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        bool ok = fp.processFile(path, packets, message);
        EXPECT_FALSE(ok);
        EXPECT_EQ(message, "Desteklenmeyen dosya biçimi: Microsoft Network Monitor");

        // Also test direct processPcapFile invocation
        ok = fp.processPcapFile(path, packets, message);
        EXPECT_FALSE(ok);
        EXPECT_EQ(message, "Desteklenmeyen dosya biçimi: Microsoft Network Monitor");
        std::remove(path.c_str());
    }

    // 2. Sun snoop
    {
        const auto path = support::writeTemp("sample.snoop", makeSnoopSample());
        EXPECT_EQ(core::detectFileFormat(path), core::FileFormat::Snoop);
        EXPECT_EQ(std::string(core::formatName(core::FileFormat::Snoop)), "Sun snoop");
        EXPECT_EQ(core::unsupportedFormatDiagnostic(core::FileFormat::Snoop),
                  "Desteklenmeyen dosya biçimi: Sun snoop");

        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        bool ok = fp.processFile(path, packets, message);
        EXPECT_FALSE(ok);
        EXPECT_EQ(message, "Desteklenmeyen dosya biçimi: Sun snoop");
        std::remove(path.c_str());
    }

    // 3. Endace ERF
    {
        const auto path = support::writeTemp("sample.erf", makeErfSample());
        EXPECT_EQ(core::detectFileFormat(path), core::FileFormat::Erf);
        EXPECT_EQ(std::string(core::formatName(core::FileFormat::Erf)), "Endace ERF");
        EXPECT_EQ(core::unsupportedFormatDiagnostic(core::FileFormat::Erf),
                  "Desteklenmeyen dosya biçimi: Endace ERF");

        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        bool ok = fp.processFile(path, packets, message);
        EXPECT_FALSE(ok);
        EXPECT_EQ(message, "Desteklenmeyen dosya biçimi: Endace ERF");
        std::remove(path.c_str());
    }

    // 4. AIX iptrace 1.0 & 2.0
    {
        const auto path1 = support::writeTemp("sample1.iptrace", makeIptrace1Sample());
        EXPECT_EQ(core::detectFileFormat(path1), core::FileFormat::Iptrace);
        EXPECT_EQ(std::string(core::formatName(core::FileFormat::Iptrace)), "AIX iptrace");
        EXPECT_EQ(core::unsupportedFormatDiagnostic(core::FileFormat::Iptrace),
                  "Desteklenmeyen dosya biçimi: AIX iptrace");

        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        bool ok = fp.processFile(path1, packets, message);
        EXPECT_FALSE(ok);
        EXPECT_EQ(message, "Desteklenmeyen dosya biçimi: AIX iptrace");
        std::remove(path1.c_str());

        const auto path2 = support::writeTemp("sample2.iptrace", makeIptrace2Sample());
        EXPECT_EQ(core::detectFileFormat(path2), core::FileFormat::Iptrace);
        ok = fp.processFile(path2, packets, message);
        EXPECT_FALSE(ok);
        EXPECT_EQ(message, "Desteklenmeyen dosya biçimi: AIX iptrace");
        std::remove(path2.c_str());
    }
}
