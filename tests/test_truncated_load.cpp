// A capture cut in the middle of its last record, but with earlier records read, must finish its load pass like a
// complete file: the packets that were read, their relative times, the frozen session tables and the Replay details
// equal those of the same file cut cleanly after the last complete record (B5 fix: the pcapng reader's early
// return used to skip freezing the tables and setting the capture start).
#include <gtest/gtest.h>

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>

#include <core.h>
#include "support.h"

namespace {
    std::vector<char> readFile(const std::string &name) {
        const std::string path = std::string(IMSHARK_TEST_DATA_DIR) + "/../corpus/" + name;
        std::ifstream f(path, std::ios::binary);
        return std::vector<char>((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    }

    struct Result {
        bool ok = false;
        std::string message;
        std::vector<packet::PacketInfo> packets;
        double startEpoch = 0;
        bool frozen = false;
        std::vector<std::string> details;   // per packet: protocol, info and every field text from Replay
    };

    void flatten(const packet::Field &f, std::string &out) {
        out += f.text + "@" + std::to_string(f.offset) + "+" + std::to_string(f.length) + "|";
        for (const auto &c: f.children) flatten(c, out);
    }

    Result load(const std::vector<char> &bytes) {
        Result r;
        const auto path = support::writeTemp("truncated_load.bin", bytes);
        core::FileProcessor fp;
        r.ok = fp.processFile(path, r.packets, r.message);
        r.startEpoch = static_cast<double>(fp.captureStartEpoch());
        r.frozen = fp.sessions().isFrozen();
        for (const auto &p: r.packets) {
            packet::PacketInfo d;
            std::string text;
            if (core::buildPacketDetails(path, p, d, &r.packets, &fp.captureInfo(), nullptr, &fp.sessions())) {
                text = d.protocol + "|" + d.info + "|";
                for (const auto &f: d.fields) flatten(f, text);
            } else {
                text = "<no details>";
            }
            r.details.push_back(text);
        }
        std::remove(path.c_str());
        return r;
    }

    // `chop` bytes are removed from the end of the complete file; the clean cut is the end of the last packet that
    // loaded (pcapng: plus padding to 4 and the 4 byte trailing length), or `cleanEnd` where records carry padding.
    void expectSameAsCleanCut(const std::string &name, size_t chop, bool pcapng, size_t cleanEnd = 0) {
        SCOPED_TRACE(name);
        auto bytes = readFile(name);
        ASSERT_GT(bytes.size(), chop);
        bytes.resize(bytes.size() - chop);
        const auto cut = load(bytes);
        ASSERT_TRUE(cut.ok) << cut.message;
        ASSERT_FALSE(cut.packets.empty());
        EXPECT_FALSE(cut.message.empty()) << "the truncation is still reported";

        const auto &last = cut.packets.back();
        size_t end = last.file_offset + last.captured_length;
        if (pcapng) end = ((end + 3) & ~size_t(3)) + 4;
        if (cleanEnd) end = cleanEnd;   // formats whose records are padded: the caller knows where the last complete one ends
        ASSERT_LE(end, bytes.size());
        const auto clean = load(std::vector<char>(bytes.begin(), bytes.begin() + end));
        ASSERT_TRUE(clean.ok);

        ASSERT_EQ(cut.packets.size(), clean.packets.size());
        for (size_t i = 0; i < cut.packets.size(); ++i) {
            EXPECT_EQ(cut.packets[i].file_offset, clean.packets[i].file_offset) << i;
            EXPECT_EQ(cut.packets[i].captured_length, clean.packets[i].captured_length) << i;
            EXPECT_EQ(cut.packets[i].time, clean.packets[i].time) << i << ": relative time";
            EXPECT_EQ(cut.packets[i].protocol, clean.packets[i].protocol) << i;
            EXPECT_EQ(cut.packets[i].info, clean.packets[i].info) << i;
        }
        EXPECT_EQ(cut.packets.front().time, 0.0) << "relative to the first packet";
        EXPECT_EQ(cut.startEpoch, clean.startEpoch);
        EXPECT_NE(cut.startEpoch, 0.0) << "capture start is the first packet's time";
        EXPECT_TRUE(cut.frozen) << "session tables are frozen after the load pass";
        EXPECT_EQ(cut.frozen, clean.frozen);
        EXPECT_EQ(cut.details, clean.details);
    }
}

TEST(TruncatedLoad, PcapngCutInTheLastBlock) {
    for (const size_t chop: {1u, 4u, 6u, 30u, 70u}) expectSameAsCleanCut("pcapng-two-interfaces-tsoffset.pcapng", chop, true);
}

TEST(TruncatedLoad, PcapCutInTheLastRecord) {
    expectSameAsCleanCut("truncated-last-record.pcap", 0, false);
    expectSameAsCleanCut("arp-little-endian.pcap", 7, false);
}

TEST(TruncatedLoad, SnoopCutInTheLastRecord) { expectSameAsCleanCut("snoop-truncated-last-record.snoop", 0, false); }
TEST(TruncatedLoad, IptraceCutInTheLastRecord) { expectSameAsCleanCut("iptrace-truncated-last-record.iptrace", 0, false); }
TEST(TruncatedLoad, ErfCutInTheLastRecord) { expectSameAsCleanCut("erf-mixed.erf", 5, false, 200); }

TEST(TruncatedLoad, PcapngWithoutAnyCompletePacketStillFails) {
    auto bytes = readFile("pcapng-two-interfaces-tsoffset.pcapng");
    bytes.resize(bytes.size() - 150);   // inside the first packet block
    const auto r = load(bytes);
    EXPECT_TRUE(r.packets.empty());
}
