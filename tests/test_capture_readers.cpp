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

// ---- Microsoft Network Monitor 2.x ----------------------------------------------------------------------
namespace {
    struct NetMonFrame { std::vector<char> data; uint64_t delta; uint32_t original = 0; };

    // header (72 bytes), frame records, frame table; `table` lists the frames in capture order (default: physical order)
    std::vector<char> netmonFile(const std::vector<NetMonFrame> &frames, uint16_t macType = 1, uint8_t major = 2, uint8_t minor = 1,
                                 const std::vector<uint16_t> &systemTime = {2023, 11, 2, 14, 22, 13, 20, 500},
                                 const std::vector<size_t> &table = {}) {
        std::vector<char> body;
        std::vector<uint32_t> offsets;
        for (const auto &f: frames) {
            offsets.push_back(uint32_t(72 + body.size()));
            body = cat(body, le<uint64_t>(f.delta));
            body = cat(body, le<uint32_t>(f.original ? f.original : uint32_t(f.data.size())));
            body = cat(body, le<uint32_t>(uint32_t(f.data.size())));
            body = cat(body, f.data);
        }
        std::vector<char> tableBytes;
        if (table.empty()) for (auto o: offsets) tableBytes = cat(tableBytes, le<uint32_t>(o));
        else for (auto i: table) tableBytes = cat(tableBytes, le<uint32_t>(offsets[i]));
        std::vector<char> h = bytesFrom("GMBU");
        h.push_back(char(minor));
        h.push_back(char(major));
        h = cat(h, le<uint16_t>(macType));
        for (auto v: systemTime) h = cat(h, le<uint16_t>(v));
        h = cat(h, le<uint32_t>(uint32_t(72 + body.size())));   // frame table offset
        h = cat(h, le<uint32_t>(uint32_t(tableBytes.size())));
        for (int i = 0; i < 10; ++i) h = cat(h, le<uint32_t>(0)); // user data, comment, statistics, network info, conversations
        return cat(cat(h, body), tableBytes);
    }
} // namespace

TEST(NetMonReader, ReadsFramesThroughTheFrameTableWithTheStartTime) {
    // start 2023-11-14 22:13:20.500 (= 1700000000.5 UTC); frames 0, 1.25 s and 3 s after it
    const auto file = netmonFile({{kArp, 0}, {kUdp, 1250000, 1514}, {support::hex("aa bb"), 3000000}});
    const auto loaded = load(file);
    ASSERT_TRUE(loaded.ok) << loaded.message;
    EXPECT_TRUE(loaded.message.empty());
    ASSERT_EQ(loaded.packets.size(), 3u);
    ASSERT_EQ(loaded.records.size(), 3u);
    EXPECT_EQ(loaded.packets[0].file_offset, 72u + 16u);
    EXPECT_EQ(loaded.packets[1].file_offset, 72u + 58u + 16u);
    EXPECT_EQ(loaded.packets[1].frame_length, 1514u);
    EXPECT_EQ(loaded.packets[1].captured_length, 71u);
    EXPECT_EQ(loaded.records[0].seconds, 1700000000u);
    EXPECT_EQ(loaded.records[0].fraction, 500000u);
    EXPECT_EQ(loaded.records[1].seconds, 1700000001u);      // .5 + 1.25 = 1.75
    EXPECT_EQ(loaded.records[1].fraction, 750000u);
    EXPECT_EQ(loaded.records[2].seconds, 1700000003u);
    EXPECT_EQ(loaded.records[2].fraction, 500000u);
    EXPECT_NEAR(loaded.packets[1].time, 1.25, 1e-9);
    EXPECT_NEAR(loaded.packets[2].time, 3.0, 1e-9);
    EXPECT_EQ(loaded.packets[1].protocol, "DNS");
    EXPECT_NE(loaded.info.format.find("Microsoft Network Monitor, version 2.1, MAC type 1 (Ethernet)"), std::string::npos) << loaded.info.format;
    ASSERT_EQ(loaded.info.interfaces.size(), 1u);
    EXPECT_EQ(loaded.info.interfaces[0].packets, 3u);
    expectReplayConsistent(file, loaded);
}

TEST(NetMonReader, FrameTableOrderIsCaptureOrder) {
    const auto file = netmonFile({{kUdp, 5000000}, {kArp, 2000000}}, 1, 2, 0, {2023, 11, 2, 14, 22, 13, 20, 0}, {1, 0});
    const auto loaded = load(file);
    ASSERT_TRUE(loaded.ok) << loaded.message;
    ASSERT_EQ(loaded.packets.size(), 2u);
    EXPECT_EQ(loaded.packets[0].protocol, "ARP");
    EXPECT_EQ(loaded.packets[1].protocol, "DNS");
    EXPECT_NEAR(loaded.packets[1].time, 3.0, 1e-9);
    EXPECT_GT(loaded.packets[0].file_offset, loaded.packets[1].file_offset);   // stored the other way round
    expectReplayConsistent(file, loaded);
}

TEST(NetMonReader, MapsMacTypesToLinkTypes) {
    struct Case { uint16_t mac; uint32_t linkType; bool note; };
    const Case cases[] = {{1, 1, false}, {2, 6, false}, {3, 10, false}, {0, 147, true}, {4, 147, true}, {6, 147, true}, {200, 147, true}};
    for (const auto &c: cases) {
        const auto file = netmonFile({{kArp, 0}}, c.mac);
        const auto loaded = load(file);
        SCOPED_TRACE("MAC type " + std::to_string(c.mac));
        ASSERT_TRUE(loaded.ok) << loaded.message;
        ASSERT_EQ(loaded.packets.size(), 1u);
        EXPECT_EQ(loaded.packets[0].link_type, c.linkType);
        EXPECT_EQ(loaded.message.find("shown as raw data") != std::string::npos, c.note) << loaded.message;
        if (c.linkType != 1) EXPECT_EQ(loaded.packets[0].info, "Unsupported link type " + std::to_string(c.linkType));
        expectReplayConsistent(file, loaded);
    }
}

TEST(NetMonReader, RefusesVersion1AndDamagedTables) {
    auto loaded = load(netmonFile({{kArp, 0}}, 1, 1, 1));
    EXPECT_FALSE(loaded.ok);
    EXPECT_EQ(loaded.message, "Unsupported Network Monitor version 1.1 (only 2.x is read)");

    // the frame table is at the end: a file cut short has lost it
    auto cut = netmonFile({{kArp, 0}, {kArp, 1}});
    cut.resize(cut.size() - 3);
    loaded = load(cut);
    EXPECT_FALSE(loaded.ok);
    EXPECT_EQ(loaded.message, "Network Monitor frame table lies outside the file (the file is damaged or cut short)");

    // a table entry that points outside the file keeps the frames before it
    auto bad = netmonFile({{kArp, 0}, {kArp, 1}});
    bad[bad.size() - 1] = char(0x7f);   // second entry becomes 0x7f0000xx
    loaded = load(bad);
    EXPECT_TRUE(loaded.ok);
    EXPECT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.message, "Frame 2 lies outside the file");

    // a frame whose included length runs past the end of the file
    bad = netmonFile({{kArp, 0}, {kArp, 1}});
    bad[72 + 58 + 12] = char(0xff);
    bad[72 + 58 + 13] = char(0xff);
    loaded = load(bad);
    EXPECT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.message, "Truncated or corrupt frame 2");

    // an impossible date leaves the start at the epoch, the relative times are unaffected
    loaded = load(netmonFile({{kArp, 0}, {kArp, 2000000}}, 1, 2, 1, {2023, 13, 0, 99, 99, 99, 99, 9999}));
    ASSERT_EQ(loaded.packets.size(), 2u);
    EXPECT_EQ(loaded.records[0].seconds, 0u);
    EXPECT_NEAR(loaded.packets[1].time, 2.0, 1e-9);
}

TEST(NetMonReader, TruncationAndMutationSweep) {
    sweep(netmonFile({{kArp, 0}, {kUdp, 1250000}, {support::hex("aa bb cc"), 3000000}}), 202);
}

// ---- Endace ERF -------------------------------------------------------------------------------------------
namespace {
    // header: LE 32.32 timestamp, type, flags, BE rlen / lctr / wlen; extension headers (8 bytes) and the 2 byte Ethernet
    // pad come before the data; the record is padded to a multiple of 8 when `pad8`
    std::vector<char> erfRecord(uint8_t type, const std::vector<char> &data, uint32_t sec = 1700000000, uint32_t frac = 0, uint8_t flags = 0,
                                int wlen = -1, int extensions = 0, bool pad8 = true) {
        std::vector<char> body;
        for (int i = 0; i < extensions; ++i) body = cat(body, support::hex(i + 1 < extensions ? "80 00 00 00 00 00 00 00" : "00 00 00 00 00 00 00 00"));
        if (type == 2 || type == 11 || type == 16 || type == 20) body = cat(body, support::hex("00 00"));
        body = cat(body, data);
        if (pad8) body.insert(body.end(), (8 - (16 + body.size()) % 8) % 8, 0);
        std::vector<char> r = le<uint64_t>((uint64_t(sec) << 32) | frac);
        r.push_back(char(type | (extensions ? 0x80 : 0)));
        r.push_back(char(flags));
        r = cat(r, be<uint16_t>(uint16_t(16 + body.size())));
        r = cat(r, be<uint16_t>(0));
        r = cat(r, be<uint16_t>(uint16_t(wlen < 0 ? data.size() : size_t(wlen))));
        return cat(r, body);
    }
    const std::vector<char> kIpDns = support::hex("4500 0039 1234 4000 4011 0000 0a000001 0a000002 c350 0035 0025 0000 1234 0100 0001 0000 0000 0000 076578616d706c6503636f6d00 0001 0001");
} // namespace

TEST(ErfReader, ReadsLittleEndianFixedPointTimeAndBigEndianHeaderFields) {
    // record 1: Ethernet, padded to 8 (rlen 16 + 2 + 42 + 4 = 64), wire length 42
    // record 2: Ethernet with two extension headers on interface 2, 0.25 s later (fraction 0x40000000 of 2^32)
    const auto r1 = erfRecord(2, kArp);
    const auto r2 = erfRecord(2, kUdp, 1700000001, 0x40000000, 2, -1, 2);
    const auto file = cat(r1, r2);
    ASSERT_EQ(r1.size(), 64u);
    const auto loaded = load(file);
    ASSERT_TRUE(loaded.ok) << loaded.message;
    EXPECT_TRUE(loaded.message.empty());
    ASSERT_EQ(loaded.packets.size(), 2u);
    ASSERT_EQ(loaded.records.size(), 2u);
    EXPECT_EQ(loaded.packets[0].file_offset, 16u + 2u);                 // header + Ethernet pad
    EXPECT_EQ(loaded.packets[0].captured_length, 42u);                  // padding after the frame is dropped
    EXPECT_EQ(loaded.packets[1].file_offset, 64u + 16u + 16u + 2u);     // two extension headers
    EXPECT_EQ(loaded.packets[1].captured_length, 71u);
    EXPECT_EQ(loaded.records[0].seconds, 1700000000u);
    EXPECT_EQ(loaded.records[1].seconds, 1700000001u);
    EXPECT_EQ(loaded.records[1].fraction, 0x40000000u);
    EXPECT_EQ(loaded.records[1].ticksPerSecond, 1ull << 32);
    EXPECT_NEAR(loaded.packets[1].time, 1.25, 1e-9);
    EXPECT_EQ(loaded.packets[0].protocol, "ARP");
    EXPECT_EQ(loaded.packets[1].protocol, "DNS");
    EXPECT_EQ(loaded.info.format, "Endace ERF");
    ASSERT_EQ(loaded.info.interfaces.size(), 2u);                       // one per capture interface in the flags
    EXPECT_EQ(loaded.info.interfaces[0].packets, 1u);
    EXPECT_EQ(loaded.info.interfaces[1].name, "ERF interface 2");
    EXPECT_EQ(loaded.info.interfaces[1].ticksPerSecond, 1ull << 32);
    expectReplayConsistent(file, loaded);
}

TEST(ErfReader, WireLengthBoundsTheFrameAndTruncatedRecordsKeepTheirWireLength) {
    // varlen / snap: the record holds 20 bytes of a 1514 byte frame
    auto file = erfRecord(2, support::hex("ffffffffffff 001122334455 0806 0001 0800 06 04 0001"), 1700000000, 0, 0x08, 1514, 0, false);   // flags: truncated
    auto loaded = load(file);
    ASSERT_TRUE(loaded.ok) << loaded.message;
    ASSERT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.packets[0].captured_length, 22u);
    EXPECT_EQ(loaded.packets[0].frame_length, 1514u);

    // wire length 0 (not given): the record's own data is the frame
    file = erfRecord(2, kArp, 1700000000, 0, 0, 0, 0, false);
    loaded = load(file);
    ASSERT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.packets[0].captured_length, 42u);
}

TEST(ErfReader, MapsRecordTypesToLinkTypes) {
    struct Case { uint8_t type; std::vector<char> data; uint32_t linkType; bool note; };
    const Case cases[] = {
        {2, kArp, 1, false}, {11, kArp, 1, false}, {16, kArp, 1, false}, {20, kArp, 1, false},
        {22, kIpDns, 101, false}, {23, kIpDns, 101, false},                           // raw IPv4 / IPv6 (the nibble picks)
        {1, cat(support::hex("ff 03 00 21"), kIpDns), 9, false},                       // PoS with PPP-in-HDLC framing
        {10, cat(support::hex("ff 03 00 21"), kIpDns), 9, false},
        {1, cat(support::hex("0f 00 08 00"), kIpDns), 147, true},                      // Cisco HDLC
        {3, support::hex("00 11 22 33"), 147, true}, {4, support::hex("00 11 22 33"), 147, true},   // ATM, AAL5
        {5, support::hex("00 11 22 33"), 147, true}, {21, support::hex("00 11 22 33"), 147, true},  // multi-channel HDLC, InfiniBand
        {24, support::hex("00 11 22 33"), 147, true},
    };
    for (const auto &c: cases) {
        const auto file = erfRecord(c.type, c.data);
        const auto loaded = load(file);
        SCOPED_TRACE("record type " + std::to_string(c.type));
        ASSERT_TRUE(loaded.ok) << loaded.message;
        ASSERT_EQ(loaded.packets.size(), 1u);
        EXPECT_EQ(loaded.packets[0].link_type, c.linkType);
        EXPECT_EQ(loaded.message.find("shown as raw data") != std::string::npos, c.note) << loaded.message;
        if (c.linkType == 147) EXPECT_EQ(loaded.packets[0].info, "Unsupported link type 147");
        expectReplayConsistent(file, loaded);
    }
    // PoS: the two bytes ff 03 are not part of the frame, the packet decodes as PPP / IPv4 / DNS
    const auto pos = load(erfRecord(1, cat(support::hex("ff 03 00 21"), kIpDns), 1, 0, 0, -1, 0, false));
    ASSERT_EQ(pos.packets.size(), 1u);
    EXPECT_EQ(pos.packets[0].file_offset, 16u + 2u);
    EXPECT_EQ(pos.packets[0].captured_length, kIpDns.size() + 2);
    EXPECT_EQ(pos.packets[0].protocol, "DNS");
}

TEST(ErfReader, SkipsRecordsThatCarryNoPacket) {
    // IP counter (13), TCP flow counter (14) and META (26) records sit between packets
    const auto file = cat(cat(cat(cat(erfRecord(2, kArp), erfRecord(13, support::hex("01 02 03 04 05 06 07 08"))),
                                  erfRecord(14, support::hex("01 02 03 04 05 06 07 08 09 0a 0b 0c"))), erfRecord(26, support::hex("00 01 00 04 00 00 00 00"))),
                          erfRecord(2, kArp, 1700000002));
    const auto loaded = load(file);
    ASSERT_TRUE(loaded.ok) << loaded.message;
    EXPECT_EQ(loaded.packets.size(), 2u);
    EXPECT_TRUE(loaded.message.empty());
    EXPECT_NEAR(loaded.packets[1].time, 2.0, 1e-9);
    expectReplayConsistent(file, loaded);
    // a file of nothing but counters loads as an empty capture
    const auto empty = load(cat(erfRecord(13, support::hex("01 02 03 04 05 06 07 08")), erfRecord(26, support::hex("00 01 00 04 00 00 00 00"))));
    EXPECT_TRUE(empty.ok);
    EXPECT_TRUE(empty.packets.empty());
}

TEST(ErfReader, DamagedRecordsKeepTheEarlierOnes) {
    const auto good = cat(erfRecord(2, kArp), erfRecord(2, kArp, 1700000001));
    // record length below the 16 byte header
    auto bad = good;
    bad[64 + 11] = 8;
    auto loaded = load(bad);
    EXPECT_TRUE(loaded.ok);
    EXPECT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.message, "Corrupt record header after record 1");

    // record length that runs past the end of the file
    auto cut = good;
    cut.resize(cut.size() - 5);
    loaded = load(cut);
    EXPECT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.message, "Truncated or corrupt record 2");

    // a header cut in two
    cut = cat(erfRecord(2, kArp), std::vector<char>(9, 1));
    loaded = load(cut);
    EXPECT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.message, "Truncated record header after record 1");

    // extension headers that do not fit in the record: bit 7 of the type set on a record that is only a header
    auto ext = erfRecord(22, kIpDns);
    ext[8] = char(22 | 0x80);
    ext[16] = char(0x80);   // and the chain says there is one more
    for (int i = 0; i < 8; ++i) ext[16 + i] = char(i == 0 ? 0x80 : 0);
    ext.resize(16 + 8 + 4);
    ext[10] = 0; ext[11] = char(ext.size());
    loaded = load(cat(erfRecord(2, kArp), ext));
    EXPECT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.message, "Record 2 is shorter than its headers");
}

TEST(ErfReader, TruncationAndMutationSweep) {
    sweep(cat(cat(cat(erfRecord(2, kArp), erfRecord(2, kUdp, 1700000001, 0x40000000, 1, -1, 2)),
                  erfRecord(13, support::hex("01 02 03 04 05 06 07 08"))),
              cat(erfRecord(22, kIpDns, 1700000003), erfRecord(1, cat(support::hex("ff 03 00 21"), kIpDns), 1700000004))), 303);
}

// ---- AIX iptrace 2.0 ----------------------------------------------------------------------------------------
namespace {
    // 40 byte header: record length, 24 bytes not used, interface type at 28, direction at 29, seconds at 32, nanoseconds at 36
    std::vector<char> iptraceRecord(const std::vector<char> &frame, uint8_t ifType = 6, uint32_t sec = 1700000000, uint32_t nsec = 0) {
        std::vector<char> r = be<uint32_t>(uint32_t(40 + frame.size()));
        r.insert(r.end(), 24, 0);
        r.push_back(char(ifType));
        r.push_back(0);
        r.push_back(0);
        r.push_back(0);
        r = cat(r, be<uint32_t>(sec));
        r = cat(r, be<uint32_t>(nsec));
        return cat(r, frame);
    }
    std::vector<char> iptraceFile(const std::vector<std::vector<char>> &records, const std::string &magic = "iptrace 2.0") {
        std::vector<char> f = bytesFrom(magic);
        for (const auto &r: records) f = cat(f, r);
        return f;
    }
} // namespace

TEST(IptraceReader, ReadsRecordsNanosecondsAndInterfaceTypes) {
    const auto file = iptraceFile({iptraceRecord(kArp, 6, 1700000000, 5), iptraceRecord(kUdp, 7, 1700000001, 250000000),
                                   iptraceRecord(support::hex("aa bb"), 6, 1700000002, 999999999)});
    const auto loaded = load(file);
    ASSERT_TRUE(loaded.ok) << loaded.message;
    EXPECT_TRUE(loaded.message.empty());
    ASSERT_EQ(loaded.packets.size(), 3u);
    ASSERT_EQ(loaded.records.size(), 3u);
    EXPECT_EQ(loaded.packets[0].file_offset, 11u + 40u);
    EXPECT_EQ(loaded.packets[1].file_offset, 11u + 82u + 40u);
    EXPECT_EQ(loaded.packets[1].captured_length, 71u);
    EXPECT_EQ(loaded.packets[1].frame_length, 71u);                // iptrace stores no wire length
    EXPECT_EQ(loaded.records[1].seconds, 1700000001u);
    EXPECT_EQ(loaded.records[1].fraction, 250000000u);
    EXPECT_EQ(loaded.records[1].ticksPerSecond, 1000000000u);
    EXPECT_NEAR(loaded.packets[1].time, 1.249999995, 1e-9);
    EXPECT_NEAR(loaded.packets[2].time, 2.999999994, 1e-9);
    EXPECT_EQ(loaded.packets[0].protocol, "ARP");
    EXPECT_EQ(loaded.packets[1].protocol, "DNS");
    EXPECT_EQ(loaded.info.format, "AIX iptrace 2.0");
    ASSERT_EQ(loaded.info.interfaces.size(), 2u);                    // interface types 6 and 7
    EXPECT_EQ(loaded.info.interfaces[0].packets, 2u);
    EXPECT_EQ(loaded.info.interfaces[1].packets, 1u);
    EXPECT_EQ(loaded.info.interfaces[1].name, "interface type 0x07");
    expectReplayConsistent(file, loaded);
}

TEST(IptraceReader, MapsInterfaceTypesToLinkTypes) {
    struct Case { uint8_t ifType; uint32_t linkType; bool note; };
    // 6 Ethernet, 7 IEEE 802.3, 9 token ring, 0x0f FDDI; loopback (0x18), SLIP (0x1c) and the rest have no mapping
    const Case cases[] = {{6, 1, false}, {7, 1, false}, {9, 6, false}, {0x0f, 10, false}, {0x18, 147, true}, {0x1c, 147, true}, {0, 147, true}};
    for (const auto &c: cases) {
        const auto file = iptraceFile({iptraceRecord(kArp, c.ifType)});
        const auto loaded = load(file);
        SCOPED_TRACE("interface type " + std::to_string(c.ifType));
        ASSERT_TRUE(loaded.ok) << loaded.message;
        ASSERT_EQ(loaded.packets.size(), 1u);
        EXPECT_EQ(loaded.packets[0].link_type, c.linkType);
        EXPECT_EQ(loaded.message.find("shown as raw data") != std::string::npos, c.note) << loaded.message;
        if (c.linkType != 1) EXPECT_EQ(loaded.packets[0].info, "Unsupported link type " + std::to_string(c.linkType));
        expectReplayConsistent(file, loaded);
    }
}

TEST(IptraceReader, RefusesVersion1AndStopsAtDamagedRecords) {
    auto loaded = load(iptraceFile({iptraceRecord(kArp)}, "iptrace 1.0"));
    EXPECT_FALSE(loaded.ok);
    EXPECT_EQ(loaded.message, "Unsupported iptrace version 1.0 (only 2.0 is read)");

    // magic only: a valid empty capture
    loaded = load(iptraceFile({}));
    EXPECT_TRUE(loaded.ok);
    EXPECT_TRUE(loaded.packets.empty());

    // record length below the header size
    auto bad = iptraceFile({iptraceRecord(kArp), iptraceRecord(kArp)});
    bad[11 + 82 + 3] = 20;
    loaded = load(bad);
    EXPECT_TRUE(loaded.ok);
    EXPECT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.message, "Truncated or corrupt packet 2");

    // data that is not in the file
    auto cut = iptraceFile({iptraceRecord(kArp), iptraceRecord(kUdp)});
    cut.resize(cut.size() - 10);
    loaded = load(cut);
    EXPECT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.message, "Truncated or corrupt packet 2");

    // a header cut in two
    cut = cat(iptraceFile({iptraceRecord(kArp)}), std::vector<char>(12, 1));
    loaded = load(cut);
    EXPECT_EQ(loaded.packets.size(), 1u);
    EXPECT_EQ(loaded.message, "Truncated packet header after packet 1");
}

TEST(IptraceReader, TruncationAndMutationSweep) {
    sweep(iptraceFile({iptraceRecord(kArp, 6, 1700000000, 5), iptraceRecord(kUdp, 7, 1700000001, 250000000),
                       iptraceRecord(support::hex("aa bb cc"), 0x18, 1700000002, 0)}), 404);
}
