#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <numeric>
#include <sstream>

#include <core.h>
#include <export/export.h>

#include "support.h"

namespace {
    const char *kSample = IMSHARK_TEST_DATA_DIR "/sample.pcap";

    struct Sample {
        std::vector<packet::PacketInfo> packets;
        double epoch = 0;
        Sample() {
            core::FileProcessor fp;
            std::string message;
            fp.processPcapFile(kSample, packets, message);
            epoch = fp.captureStartEpoch();
        }
    };

    std::string tempFile(const std::string &name) { return (std::filesystem::temp_directory_path() / ("imshark_export_" + name)).string(); }

    std::string slurp(const std::string &path) {
        std::ifstream f(path, std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }

    struct Reloaded {
        std::vector<packet::PacketInfo> packets;
        std::string message;
        bool ok = false;
        double epoch = 0;
        Reloaded(const std::string &path, bool pcapng) {
            core::FileProcessor fp;
            ok = pcapng ? fp.processPcapngFile(path, packets, message) : fp.processPcapFile(path, packets, message);
            epoch = fp.captureStartEpoch();
        }
    };
} // namespace

TEST(ExportTables, CsvQuotesEverythingAndFollowsTheGivenOrder) {
    EXPECT_EQ(exporter::csvField("plain"), "\"plain\"");
    EXPECT_EQ(exporter::csvField("a,b \"q\"\nline"), "\"a,b \"\"q\"\"\nline\"");
    EXPECT_EQ(exporter::csvField(""), "\"\"");

    Sample s;
    std::ostringstream out;
    exporter::writeCsv(out, s.packets, {4, 0, 9999});   // 9999 is a stale index: ignored
    std::istringstream in(out.str());
    std::string line;
    std::getline(in, line);
    EXPECT_EQ(line, "\"No.\",\"Time\",\"Source\",\"Destination\",\"Protocol\",\"Length\",\"Info\"");
    std::getline(in, line);
    EXPECT_EQ(line.rfind("\"5\",\"1.000000\",\"10.0.0.1\",\"8.8.8.8\",\"DNS\",\"71\",\"Standard query 0x1234 A example.com\"", 0), 0u) << line;
    std::getline(in, line);
    EXPECT_EQ(line.rfind("\"1\",\"0.000000\"", 0), 0u);
    EXPECT_FALSE(std::getline(in, line));

    std::ostringstream none;
    exporter::writeCsv(none, s.packets, {});
    const std::string headerOnly = none.str();
    EXPECT_EQ(std::count(headerOnly.begin(), headerOnly.end(), '\n'), 1) << "just the header";
}

TEST(ExportTables, JsonEscapesAndStructure) {
    EXPECT_EQ(exporter::jsonString("a\"b\\c\n\t\x01"), "\"a\\\"b\\\\c\\n\\t\\u0001\"");
    Sample s;
    std::ostringstream out;
    exporter::writeJson(out, s.packets, {2, 4}, 1700000000.0);
    const std::string j = out.str();
    EXPECT_EQ(j.front(), '[');
    EXPECT_EQ(j.substr(j.size() - 2), "]\n");
    EXPECT_NE(j.find("\"number\": 3, \"time\": 0.500000, \"time_epoch\": 1700000000.500000, \"source\": \"10.0.0.1\""), std::string::npos) << j;
    EXPECT_NE(j.find("\"protocol\": \"ICMP\""), std::string::npos);
    EXPECT_NE(j.find("\"info\": \"Standard query 0x1234 A example.com\""), std::string::npos);
    EXPECT_EQ(std::count(j.begin(), j.end(), '{'), 2);
    EXPECT_EQ(std::count(j.begin(), j.end(), '}'), 2);

    std::ostringstream empty;
    exporter::writeJson(empty, s.packets, {}, 0);
    EXPECT_EQ(empty.str(), "[]\n");
}

TEST(ExportTables, FormatsHaveNamesAndExtensions) {
    for (auto f: {exporter::Format::Pcap, exporter::Format::Pcapng, exporter::Format::Csv, exporter::Format::Json}) {
        EXPECT_NE(std::string(exporter::formatName(f)), "");
        EXPECT_EQ(exporter::formatExtension(f)[0], '.');
    }
    EXPECT_TRUE(exporter::isCaptureFormat(exporter::Format::Pcapng));
    EXPECT_FALSE(exporter::isCaptureFormat(exporter::Format::Csv));
}

TEST(ExportCapture, SubsetRoundTripsThroughPcapAndPcapng) {
    Sample s;
    const std::vector<uint32_t> subset = {2, 3, 9, 15};   // ICMP, ICMP, HTTP, truncated TCP
    for (auto format: {exporter::Format::Pcap, exporter::Format::Pcapng}) {
        const bool ng = format == exporter::Format::Pcapng;
        SCOPED_TRACE(exporter::formatName(format));
        const auto path = tempFile(ng ? "subset.pcapng" : "subset.pcap");
        std::string error;
        ASSERT_TRUE(exporter::exportPackets(kSample, s.packets, subset, s.epoch, format, path, error)) << error;

        Reloaded r(path, ng);
        ASSERT_TRUE(r.ok) << r.message;
        ASSERT_EQ(r.packets.size(), subset.size());
        EXPECT_TRUE(r.message.empty());
        for (size_t i = 0; i < subset.size(); ++i) {
            const auto &orig = s.packets[subset[i]];
            const auto &copy = r.packets[i];
            std::vector<char> a, b;
            ASSERT_TRUE(core::readPacketBytes(kSample, orig, a));
            ASSERT_TRUE(core::readPacketBytes(path, copy, b));
            EXPECT_EQ(a, b) << "frame " << i;
            EXPECT_EQ(copy.protocol, orig.protocol);
            EXPECT_EQ(copy.info, orig.info) << "same dissection (TCP numbers differ only for packets whose connection was cut away)";
            EXPECT_EQ(copy.frame_length, orig.frame_length);
            EXPECT_EQ(copy.link_type, orig.link_type);
            // times keep their distances (the first exported packet becomes time 0)
            EXPECT_NEAR(copy.time - r.packets[0].time, orig.time - s.packets[subset[0]].time, 2e-6);
        }
        EXPECT_NEAR(r.epoch, s.epoch + s.packets[subset[0]].time, 2e-6) << "the absolute start time is kept";
        std::remove(path.c_str());
    }
}

TEST(ExportCapture, AllPacketsAndAnEmptySelection) {
    Sample s;
    std::vector<uint32_t> all(s.packets.size());
    std::iota(all.begin(), all.end(), 0u);
    const auto path = tempFile("all.pcapng");
    std::string error;
    ASSERT_TRUE(exporter::exportPackets(kSample, s.packets, all, s.epoch, exporter::Format::Pcapng, path, error)) << error;
    Reloaded r(path, true);
    ASSERT_EQ(r.packets.size(), s.packets.size());
    for (size_t i = 0; i < all.size(); ++i) {
        EXPECT_EQ(r.packets[i].protocol, s.packets[i].protocol) << i;
        EXPECT_EQ(r.packets[i].info, s.packets[i].info) << i;
    }
    std::remove(path.c_str());

    const auto emptyPath = tempFile("empty.pcap");
    ASSERT_TRUE(exporter::exportPackets(kSample, s.packets, {}, s.epoch, exporter::Format::Pcap, emptyPath, error)) << error;
    Reloaded e(emptyPath, false);
    EXPECT_TRUE(e.ok);
    EXPECT_TRUE(e.packets.empty());
    std::remove(emptyPath.c_str());
}

TEST(ExportCapture, MixedLinkTypesNeedPcapng) {
    Sample s;
    auto packets = s.packets;
    packets[2].link_type = 113;                           // pretend one packet came from another interface
    std::string error;
    const auto pcapPath = tempFile("mixed.pcap");
    EXPECT_FALSE(exporter::exportPackets(kSample, packets, {0, 2}, s.epoch, exporter::Format::Pcap, pcapPath, error));
    EXPECT_NE(error.find("link types"), std::string::npos);

    const auto ngPath = tempFile("mixed.pcapng");
    ASSERT_TRUE(exporter::exportPackets(kSample, packets, {0, 2, 1}, s.epoch, exporter::Format::Pcapng, ngPath, error)) << error;
    Reloaded r(ngPath, true);
    ASSERT_EQ(r.packets.size(), 3u);
    EXPECT_EQ(r.packets[0].link_type, 1u);
    EXPECT_EQ(r.packets[1].link_type, 113u);
    EXPECT_EQ(r.packets[2].link_type, 1u);
    std::remove(ngPath.c_str());
    std::remove(pcapPath.c_str());
}

TEST(ExportCapture, FailuresAndCancellation) {
    Sample s;
    std::string error;
    EXPECT_FALSE(exporter::exportPackets(kSample, s.packets, {0}, s.epoch, exporter::Format::Pcap, "/no/such/directory/out.pcap", error));
    EXPECT_NE(error.find("Cannot write"), std::string::npos);

    const auto path = tempFile("failed.pcap");
    EXPECT_FALSE(exporter::exportPackets("/no/such/capture.pcap", s.packets, {0, 1}, s.epoch, exporter::Format::Pcap, path, error));
    EXPECT_NE(error.find("could not be read"), std::string::npos);

    core::ScanControl control;
    control.cancelRequested = true;
    EXPECT_FALSE(exporter::exportPackets(kSample, s.packets, {0, 1}, s.epoch, exporter::Format::Pcap, path, error, &control));
    EXPECT_TRUE(error.empty()) << "a cancelled export is not an error";
    std::remove(path.c_str());

    // tables
    EXPECT_FALSE(exporter::exportPackets(kSample, s.packets, {0}, s.epoch, exporter::Format::Csv, "/no/such/directory/out.csv", error));
    const auto csv = tempFile("table.csv");
    ASSERT_TRUE(exporter::exportPackets(kSample, s.packets, {0, 1}, s.epoch, exporter::Format::Csv, csv, error)) << error;
    const std::string table = slurp(csv);
    EXPECT_EQ(std::count(table.begin(), table.end(), '\n'), 3);
    std::remove(csv.c_str());
}
