// The readers for the legacy and vendor capture formats (ROADMAP v1.9) behind the B5 registry: Sun snoop, Microsoft
// Network Monitor 2.x, Endace ERF and AIX iptrace 2.0. The files are built here byte by byte from the published
// layouts (the same layouts the corpus generator tools/make_corpus.py implements separately in Python); every test
// that loads a file also checks that Replay (reading one packet again by its file offset) gives the bytes of the load pass.
#include <gtest/gtest.h>

#include <cstdio>
#include <sstream>

#include <core.h>
#include <io/format_registry.h>
#include "support.h"

namespace {
    using core::FileFormat;
    using namespace core::io;

    struct Loaded {
        bool ok = false;
        std::string message;
        std::vector<packet::PacketInfo> packets;
        core::CaptureInfo info;
        std::vector<CaptureRecord> records;   // what the reader handed over, for comparison with the packets
    };

    // Loads through the same entry point as the application and, independently, drains the reader for its records.
    Loaded load(const std::vector<char> &bytes) {
        Loaded out;
        const auto path = support::writeTemp("capture_readers.bin", bytes);
        core::FileProcessor fp;
        out.ok = fp.processFile(path, out.packets, out.message);
        out.info = fp.captureInfo();

        const auto fmt = core::detectFileFormat(path);
        if (auto reader = makeReader(fmt)) {
            std::istringstream in(std::string(bytes.begin(), bytes.end()), std::ios::binary);
            core::CaptureInfo info;
            dissect::SessionTables sessions;
            ReaderContext ctx{info, sessions, bytes.size()};
            std::string message;
            if (reader->open(in, ctx, message)) {
                CaptureRecord rec;
                ReadIssue issue;
                while (reader->next(rec, issue) == CaptureFileReader::Status::Record) out.records.push_back(rec);
            }
        }
        std::remove(path.c_str());
        return out;
    }

    // Every packet of a loaded file lies inside the file, Replay reads it back, and the details rebuild inside the frame.
    void expectReplayConsistent(const std::vector<char> &bytes, const Loaded &loaded) {
        const auto path = support::writeTemp("capture_readers_replay.bin", bytes);
        for (const auto &p: loaded.packets) {
            ASSERT_LE(p.file_offset + p.captured_length, bytes.size()) << "packet " << p.number;
            std::vector<char> replayed;
            ASSERT_TRUE(core::readPacketBytes(path, p, replayed)) << "packet " << p.number;
            EXPECT_EQ(replayed.size(), p.captured_length);
            if (p.number >= 1 && p.number <= loaded.records.size()) {
                const auto &rec = loaded.records[p.number - 1];
                EXPECT_EQ(replayed, rec.frame) << "packet " << p.number << ": Replay must see the bytes of the load pass";
                EXPECT_EQ(p.file_offset, rec.fileOffset);
            }
            packet::PacketInfo details;
            ASSERT_TRUE(core::buildPacketDetails(path, p, details, &loaded.packets, &loaded.info)) << "packet " << p.number;
            EXPECT_EQ(details.protocol, p.protocol) << "packet " << p.number;
            EXPECT_EQ(details.info, p.info) << "packet " << p.number;
            std::function<void(const packet::Field &)> inside = [&](const packet::Field &f) {
                EXPECT_LE(size_t(f.offset) + f.length, details.raw_data.size()) << f.text;
                for (const auto &c: f.children) inside(c);
            };
            for (const auto &f: details.fields) inside(f);
        }
        std::remove(path.c_str());
    }

    // Truncation at every byte and seeded mutation: whatever happens, no crash and everything that loads is in range.
    void sweep(const std::vector<char> &seedFile, uint32_t seed) {
        for (size_t n = 0; n <= seedFile.size(); ++n) {
            const std::vector<char> cut(seedFile.begin(), seedFile.begin() + n);
            const auto loaded = load(cut);
            SCOPED_TRACE("prefix " + std::to_string(n));
            for (const auto &p: loaded.packets) ASSERT_LE(p.file_offset + p.captured_length, n);
            if (n % 7 == 0 || n == seedFile.size()) expectReplayConsistent(cut, loaded);
        }
        uint32_t state = seed;
        auto next = [&state]() { state = state * 1664525u + 1013904223u; return state >> 8; };
        for (int round = 0; round < 400; ++round) {
            std::vector<char> b = seedFile;
            for (int i = 0, flips = 1 + int(next() % 4); i < flips; ++i) b[next() % b.size()] = static_cast<char>(next());
            if (next() % 4 == 0) b.resize(next() % (b.size() + 1));
            const auto loaded = load(b);
            SCOPED_TRACE("mutation round " + std::to_string(round));
            for (const auto &p: loaded.packets) ASSERT_LE(p.file_offset + p.captured_length, b.size());
            if (round % 5 == 0) expectReplayConsistent(b, loaded);
        }
    }

    std::vector<char> bytesFrom(const std::string &text) { return std::vector<char>(text.begin(), text.end()); }
    std::vector<char> cat(std::vector<char> a, const std::vector<char> &b) { a.insert(a.end(), b.begin(), b.end()); return a; }
    template<typename T> std::vector<char> be(T v) { std::vector<char> o; support::put<T>(o, v, true); return o; }
    template<typename T> std::vector<char> le(T v) { std::vector<char> o; support::put<T>(o, v, false); return o; }

    // frames used by the tests: an ARP request (42 bytes) and a UDP/DNS query in Ethernet (71 bytes)
    const std::vector<char> kArp = support::hex("ffffffffffff 001122334455 0806 0001 0800 06 04 0001 001122334455 0a000001 000000000000 0a000002");
    const std::vector<char> kUdp = support::hex(
        "001122334455 aabbccddeeff 0800 4500 0037 1234 4000 4011 0000 0a000001 0a000002 c350 0035 0023 0000"
        "1234 0100 0001 0000 0000 0000 076578616d706c6503636f6d00 0001 0001");

    // ---- Sun snoop (RFC 1761) ------------------------------------------------------------------------------
    std::vector<char> snoopHeader(uint32_t datalink, uint32_t version = 2) {
        return cat(cat(bytesFrom(std::string("snoop\0\0\0", 8)), be<uint32_t>(version)), be<uint32_t>(datalink));
    }

    // original length, included length, record length (24 + data + pad), drops, seconds, microseconds, data, padding
    std::vector<char> snoopRecord(const std::vector<char> &frame, uint32_t sec, uint32_t usec, uint32_t original = 0, uint32_t drops = 0) {
        const size_t pad = (4 - frame.size() % 4) % 4;
        std::vector<char> r = be<uint32_t>(original ? original : uint32_t(frame.size()));
        r = cat(r, be<uint32_t>(uint32_t(frame.size())));
        r = cat(r, be<uint32_t>(uint32_t(24 + frame.size() + pad)));
        r = cat(r, be<uint32_t>(drops));
        r = cat(r, be<uint32_t>(sec));
        r = cat(r, be<uint32_t>(usec));
        r = cat(r, frame);
        r.insert(r.end(), pad, 0);
        return r;
    }
} // namespace

TEST(SnoopReader, ReadsRecordsPaddingTimesAndLengths) {
    // RFC 1761 example layout: 16 byte header, records of 24 + data rounded up to 4
    const auto file = cat(cat(cat(snoopHeader(4), snoopRecord(kArp, 1700000000, 5)), snoopRecord(kUdp, 1700000001, 250000, 1514)),
                          snoopRecord(support::hex("aa bb"), 1700000002, 999999));
    ASSERT_EQ(file.size(), 16u + (24 + 44) + (24 + 72) + (24 + 4));
    const auto loaded = load(file);
    ASSERT_TRUE(loaded.ok) << loaded.message;
    EXPECT_TRUE(loaded.message.empty());
    ASSERT_EQ(loaded.packets.size(), 3u);
    ASSERT_EQ(loaded.records.size(), 3u);

    EXPECT_EQ(loaded.packets[0].file_offset, 16u + 24u);
    EXPECT_EQ(loaded.packets[1].file_offset, 16u + 68u + 24u);
    EXPECT_EQ(loaded.packets[2].file_offset, 16u + 68u + 96u + 24u);
    EXPECT_EQ(loaded.packets[0].captured_length, 42u);    // the padding is not part of the frame
    EXPECT_EQ(loaded.packets[1].captured_length, 71u);
    EXPECT_EQ(loaded.packets[1].frame_length, 1514u);     // original length of the record header
    EXPECT_EQ(loaded.packets[2].captured_length, 2u);
    EXPECT_EQ(loaded.records[1].seconds, 1700000001u);
    EXPECT_EQ(loaded.records[1].fraction, 250000u);
    EXPECT_EQ(loaded.records[1].ticksPerSecond, 1000000u);
    EXPECT_EQ(loaded.packets[0].protocol, "ARP");
    EXPECT_EQ(loaded.packets[1].protocol, "DNS");
    // times are relative to the first record (1700000000.000005): 1700000001.25 and 1700000002.999999
    EXPECT_NEAR(loaded.packets[1].time, 1.249995, 1e-7);
    EXPECT_NEAR(loaded.packets[2].time, 2.999994, 1e-7);
    EXPECT_NE(loaded.info.format.find("Sun snoop, version 2"), std::string::npos) << loaded.info.format;
    ASSERT_EQ(loaded.info.interfaces.size(), 1u);
    EXPECT_EQ(loaded.info.interfaces[0].packets, 3u);
    expectReplayConsistent(file, loaded);
}

TEST(SnoopReader, MapsDatalinkTypesToLinkTypes) {
    struct Case { uint32_t datalink, linkType; bool note; };
    // RFC 1761: 0 IEEE 802.3, 2 IEEE 802.5 (token ring), 4 Ethernet, 8 FDDI; 5 HDLC and 9 other have no mapping
    const Case cases[] = {{0, 1, false}, {4, 1, false}, {2, 6, false}, {8, 10, false}, {5, 147, true}, {9, 147, true}, {1000, 147, true}};
    for (const auto &c: cases) {
        const auto file = cat(snoopHeader(c.datalink), snoopRecord(kArp, 1, 0));
        const auto loaded = load(file);
        SCOPED_TRACE("datalink " + std::to_string(c.datalink));
        ASSERT_TRUE(loaded.ok) << loaded.message;
        ASSERT_EQ(loaded.packets.size(), 1u);
        EXPECT_EQ(loaded.packets[0].link_type, c.linkType);
        EXPECT_EQ(loaded.message.find("shown as raw data") != std::string::npos, c.note) << loaded.message;
        if (c.linkType != 1) EXPECT_EQ(loaded.packets[0].info, "Unsupported link type " + std::to_string(c.linkType));
        expectReplayConsistent(file, loaded);
    }
}

TEST(SnoopReader, RejectsOtherVersionsAndDamagedRecords) {
    auto loaded = load(cat(snoopHeader(4, 3), snoopRecord(kArp, 1, 0)));
    EXPECT_FALSE(loaded.ok);
    EXPECT_EQ(loaded.message, "Unsupported snoop version 3 (only version 2 is defined)");

    // header only: nothing to show, but a valid empty file
    loaded = load(snoopHeader(4));
    EXPECT_TRUE(loaded.ok);
    EXPECT_TRUE(loaded.packets.empty());

    // a record length smaller than header + data
    auto bad = cat(snoopHeader(4), snoopRecord(kArp, 1, 0));
    bad[16 + 11] = 30;
    loaded = load(bad);
    EXPECT_TRUE(loaded.ok);
    EXPECT_TRUE(loaded.packets.empty());
    EXPECT_EQ(loaded.message, "Truncated or corrupt packet 1");

    // an included length that runs past the end keeps the earlier record
    auto cut = cat(cat(snoopHeader(4), snoopRecord(kArp, 1, 0)), snoopRecord(kUdp, 2, 0));
    cut.resize(cut.size() - 10);
    loaded = load(cut);
    EXPECT_TRUE(loaded.ok);
    EXPECT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.message, "Truncated or corrupt packet 2");

    // a record header cut in two
    cut = cat(cat(snoopHeader(4), snoopRecord(kArp, 1, 0)), std::vector<char>(10, 0));
    loaded = load(cut);
    EXPECT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.message, "Truncated packet header after packet 1");
}

TEST(SnoopReader, TruncationAndMutationSweep) {
    sweep(cat(cat(cat(snoopHeader(4), snoopRecord(kArp, 1700000000, 5)), snoopRecord(kUdp, 1700000001, 250000)),
              snoopRecord(support::hex("aa bb cc"), 1700000002, 0)), 101);
}
