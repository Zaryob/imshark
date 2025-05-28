#include <gtest/gtest.h>

#include <algorithm>
#include <random>

#include <core.h>

#include "support.h"

using support::hex;
using support::put;

namespace {
    const std::vector<char> kFrame = hex(support::kArpRequest); // 42 bytes

    std::vector<char> pcapFile(bool bigEndian, uint32_t magic, const std::vector<std::pair<uint32_t, uint32_t>> &times,
                               uint32_t linkType = 1) {
        std::vector<char> f;
        put<uint32_t>(f, magic, bigEndian);
        put<uint16_t>(f, 2, bigEndian);
        put<uint16_t>(f, 4, bigEndian);
        put<int32_t>(f, 0, bigEndian);
        put<uint32_t>(f, 0, bigEndian);
        put<uint32_t>(f, 65535, bigEndian);
        put<uint32_t>(f, linkType, bigEndian);
        for (auto [sec, frac]: times) {
            put<uint32_t>(f, sec, bigEndian);
            put<uint32_t>(f, frac, bigEndian);
            put<uint32_t>(f, kFrame.size(), bigEndian);
            put<uint32_t>(f, kFrame.size(), bigEndian);
            f.insert(f.end(), kFrame.begin(), kFrame.end());
        }
        return f;
    }

    std::vector<char> block(bool be, uint32_t type, const std::vector<char> &body) {
        std::vector<char> b;
        const uint32_t total = 12 + body.size();
        put(b, type, be);
        put(b, total, be);
        b.insert(b.end(), body.begin(), body.end());
        put(b, total, be);
        return b;
    }

    // tsresol < 0: no option (default microseconds)
    std::vector<char> pcapngFile(bool be, int tsresol, const std::vector<uint64_t> &ticks, bool withSpb = true) {
        std::vector<char> shb;
        put<uint32_t>(shb, 0x1A2B3C4D, be);
        put<uint16_t>(shb, 1, be);
        put<uint16_t>(shb, 0, be);
        put<int64_t>(shb, -1, be);
        std::vector<char> idb;
        put<uint16_t>(idb, 1, be);
        put<uint16_t>(idb, 0, be);
        put<uint32_t>(idb, 0, be);
        if (tsresol >= 0) {
            put<uint16_t>(idb, 9, be);
            put<uint16_t>(idb, 1, be);
            idb.push_back(static_cast<char>(tsresol));
            idb.insert(idb.end(), 3, 0);
            put<uint32_t>(idb, 0, be); // opt_endofopt
        }
        std::vector<char> f = block(be, 0x0A0D0D0A, shb);
        auto b2 = block(be, 1, idb);
        f.insert(f.end(), b2.begin(), b2.end());
        for (uint64_t t: ticks) {
            std::vector<char> epb;
            put<uint32_t>(epb, 0, be);
            put<uint32_t>(epb, static_cast<uint32_t>(t >> 32), be);
            put<uint32_t>(epb, static_cast<uint32_t>(t & 0xffffffff), be);
            put<uint32_t>(epb, kFrame.size(), be);
            put<uint32_t>(epb, kFrame.size(), be);
            epb.insert(epb.end(), kFrame.begin(), kFrame.end());
            epb.insert(epb.end(), 2, 0);          // padding to 4 bytes
            put<uint32_t>(epb, 0, be);             // trailing option end (must not become packet data)
            auto b = block(be, 6, epb);
            f.insert(f.end(), b.begin(), b.end());
        }
        if (withSpb) {
            std::vector<char> spb;
            put<uint32_t>(spb, kFrame.size(), be);
            spb.insert(spb.end(), kFrame.begin(), kFrame.end());
            spb.insert(spb.end(), 2, 0);
            auto b = block(be, 3, spb);
            f.insert(f.end(), b.begin(), b.end());
        }
        return f;
    }

    struct Loaded {
        bool ok;
        std::vector<packet::PacketInfo> packets;
        std::string message;
    };

    Loaded load(const std::string &name, const std::vector<char> &bytes, bool pcapng) {
        Loaded r;
        core::FileProcessor fp;
        const auto path = support::writeTemp(name, bytes);
        r.ok = pcapng ? fp.processPcapngFile(path, r.packets, r.message) : fp.processPcapFile(path, r.packets, r.message);
        std::remove(path.c_str());
        return r;
    }
} // namespace

TEST(PcapReader, ByteOrderAndPrecision) {
    const std::vector<std::pair<uint32_t, uint32_t>> micro = {{1000, 0}, {1000, 500000}};
    for (bool be: {false, true}) {
        SCOPED_TRACE(be ? "big endian" : "little endian");
        auto r = load("a.pcap", pcapFile(be, 0xa1b2c3d4, micro), false);
        ASSERT_TRUE(r.ok);
        ASSERT_EQ(r.packets.size(), 2u);
        EXPECT_DOUBLE_EQ(r.packets[0].time, 0.0);
        EXPECT_NEAR(r.packets[1].time, 0.5, 1e-9);
        EXPECT_EQ(r.packets[0].protocol, "ARP");
        EXPECT_EQ(r.packets[0].captured_length, kFrame.size());
        EXPECT_TRUE(r.packets[0].raw_data.empty()) << "frame bytes stay in the file";
        EXPECT_TRUE(r.packets[0].fields.empty()) << "the field tree is built on demand";
    }
    auto nano = load("n.pcap", pcapFile(false, 0xa1b23c4d, {{1000, 0}, {1001, 500000000}}), false);
    ASSERT_EQ(nano.packets.size(), 2u);
    EXPECT_NEAR(nano.packets[1].time, 1.5, 1e-9);
}

TEST(PcapReader, KeepsTheOriginalFrameLength) {
    auto bytes = pcapFile(false, 0xa1b2c3d4, {{1, 0}});
    bytes[24 + 12] = 100; // orig_len of the first record: 100 on the wire, 42 captured
    auto r = load("o.pcap", bytes, false);
    ASSERT_EQ(r.packets.size(), 1u);
    EXPECT_EQ(r.packets[0].captured_length, 42u);
    EXPECT_EQ(r.packets[0].frame_length, 100u);

    auto ng = load("o.pcapng", pcapngFile(false, -1, {1}), true);
    ASSERT_EQ(ng.packets.size(), 2u);
    EXPECT_EQ(ng.packets[0].frame_length, kFrame.size()) << "EPB original length";
    EXPECT_EQ(ng.packets[1].frame_length, kFrame.size()) << "SPB original length";
}

TEST(PcapReader, RecordsLinkType) {
    auto r = load("l.pcap", pcapFile(false, 0xa1b2c3d4, {{1, 0}}, 113), false);
    ASSERT_EQ(r.packets.size(), 1u);
    EXPECT_EQ(r.packets[0].link_type, 113u);
}

TEST(PcapReader, RejectsGarbageWithMessage) {
    auto empty = load("e.pcap", {}, false);
    EXPECT_FALSE(empty.ok);
    EXPECT_FALSE(empty.message.empty());
    auto junk = load("j.pcap", std::vector<char>(100, 'x'), false);
    EXPECT_FALSE(junk.ok);
}

TEST(PcapReader, TruncatedTailKeepsEarlierPackets) {
    auto bytes = pcapFile(false, 0xa1b2c3d4, {{1, 0}, {2, 0}});
    bytes.resize(bytes.size() - 7);
    auto r = load("t.pcap", bytes, false);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.packets.size(), 1u);
    EXPECT_FALSE(r.message.empty());
}

TEST(PcapReader, HugeLengthIsRejectedNotAllocated) {
    auto bytes = pcapFile(false, 0xa1b2c3d4, {});
    put<uint32_t>(bytes, 0);
    put<uint32_t>(bytes, 0);
    put<uint32_t>(bytes, 0xFFFFFFF0u);
    put<uint32_t>(bytes, 0xFFFFFFF0u);
    auto r = load("h.pcap", bytes, false);
    EXPECT_TRUE(r.packets.empty());
    EXPECT_FALSE(r.message.empty());
}

TEST(PcapngReader, ByteOrderTimestampResolutionAndPadding) {
    struct Case { bool be; int tsresol; uint64_t perSecond; };
    for (auto c: {Case{false, -1, 1000000}, Case{true, 9, 1000000000}, Case{false, 3, 1000}}) {
        SCOPED_TRACE(std::string(c.be ? "BE" : "LE") + " tsresol=" + std::to_string(c.tsresol));
        auto r = load("a.pcapng", pcapngFile(c.be, c.tsresol, {5 * c.perSecond, 5 * c.perSecond + c.perSecond / 2}), true);
        ASSERT_TRUE(r.ok) << r.message;
        ASSERT_EQ(r.packets.size(), 3u) << "2 EPB + 1 SPB";
        EXPECT_NEAR(r.packets[1].time, 0.5, 1e-9);
        for (const auto &p: r.packets) {
            EXPECT_EQ(p.captured_length, kFrame.size()) << "padding/options must not be part of the packet";
            EXPECT_EQ(p.protocol, "ARP");
        }
    }
}

TEST(PcapngReader, NanosecondTimestampsKeepFullPrecisionAtEpochScale) {
    const uint64_t base = 1700000000ull * 1000000000ull; // a 2023 epoch time in nanoseconds
    auto r = load("p.pcapng", pcapngFile(false, 9, {base, base + 1, base + 1500000000ull}, false), true);
    ASSERT_EQ(r.packets.size(), 3u);
    EXPECT_NEAR(r.packets[1].time, 1e-9, 1e-12);
    EXPECT_NEAR(r.packets[2].time, 1.5, 1e-9);
}

TEST(PcapngReader, InvalidBlocksAreReported) {
    auto good = pcapngFile(false, -1, {1});
    {
        auto bad = good;
        bad[32] = 3; // IDB total length = 3 (not a multiple of 4)
        bad[33] = bad[34] = bad[35] = 0;
        auto r = load("b.pcapng", bad, true);
        EXPECT_FALSE(r.ok);
        EXPECT_FALSE(r.message.empty());
    }
    {
        auto cut = good;
        cut.resize(cut.size() - 30);
        auto r = load("c.pcapng", cut, true);
        EXPECT_TRUE(r.ok) << "packets before the damage are kept";
        EXPECT_FALSE(r.message.empty());
    }
    EXPECT_FALSE(load("n.pcapng", std::vector<char>(64, 1), true).ok);
}

TEST(Readers, CorruptedFilesNeverCrash) {
    std::mt19937 rng(7);
    const std::vector<std::vector<char>> seeds = {
        pcapFile(false, 0xa1b2c3d4, {{1, 0}, {2, 0}}), pcapFile(true, 0xa1b2c3d4, {{1, 0}}),
        pcapngFile(false, 6, {10, 20}), pcapngFile(true, -1, {10, 20}),
    };
    for (int i = 0; i < 1500; ++i) {
        const size_t s = rng() % seeds.size();
        auto data = seeds[s];
        for (unsigned flips = 1 + rng() % 6; flips > 0; --flips) data[rng() % data.size()] = static_cast<char>(rng());
        if (i % 3 == 0) data.resize(rng() % data.size());
        load("f.pcap", data, s >= 2);
    }
}

// ---- on-demand details ----------------------------------------------------------------------------

namespace {
    bool sameField(const packet::Field &a, const packet::Field &b) {
        if (a.text != b.text || a.offset != b.offset || a.length != b.length || a.children.size() != b.children.size()) return false;
        for (size_t i = 0; i < a.children.size(); ++i) {
            if (!sameField(a.children[i], b.children[i])) return false;
        }
        return true;
    }
} // namespace

TEST(Details, FrameBytesAreReadBackFromTheFileForBothFormats) {
    for (bool ng: {false, true}) {
        SCOPED_TRACE(ng ? "pcapng" : "pcap");
        const auto bytes = ng ? pcapngFile(true, 9, {100, 200}) : pcapFile(true, 0xa1b2c3d4, {{1, 0}, {2, 0}});
        const auto path = support::writeTemp("details.bin", bytes);
        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        ASSERT_TRUE(ng ? fp.processPcapngFile(path, packets, message) : fp.processPcapFile(path, packets, message));
        ASSERT_GE(packets.size(), 2u);
        for (const auto &summary: packets) {
            std::vector<char> frame;
            ASSERT_TRUE(core::readPacketBytes(path, summary, frame));
            EXPECT_EQ(frame, kFrame);
            packet::PacketInfo details;
            ASSERT_TRUE(core::buildPacketDetails(path, summary, details));
            EXPECT_EQ(details.raw_data, kFrame);
            EXPECT_FALSE(details.fields.empty());
            EXPECT_EQ(details.info, summary.info);
        }
        std::remove(path.c_str());
    }
}

TEST(Details, MissingFileIsReportedNotCrashed) {
    packet::PacketInfo summary(1), details;
    summary.captured_length = 10;
    EXPECT_FALSE(core::buildPacketDetails("/no/such/file.pcap", summary, details));
}

#ifdef IMSHARK_TEST_DATA_DIR
// Rebuilding one packet in isolation (Replay) must give exactly what a sequential full parse gives,
// including the relative TCP numbers that depend on the packets before it.
TEST(SampleCapture, OnDemandDetailsEqualASequentialFullParse) {
    const std::string path = IMSHARK_TEST_DATA_DIR "/sample.pcap";
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(fp.processPcapFile(path, packets, message));

    packet::PacketParser sequential;
    for (const auto &summary: packets) {
        std::vector<char> frame;
        ASSERT_TRUE(core::readPacketBytes(path, summary, frame));
        packet::PacketInfo full(summary.number);
        full.link_type = summary.link_type;
        sequential.parsePacket(full, frame); // Full mode, tracks TCP state

        packet::PacketInfo details;
        ASSERT_TRUE(core::buildPacketDetails(path, summary, details));
        EXPECT_EQ(details.protocol, full.protocol) << "packet " << summary.number;
        EXPECT_EQ(details.info, full.info) << "packet " << summary.number;
        ASSERT_EQ(details.fields.size(), full.fields.size()) << "packet " << summary.number;
        for (size_t i = 0; i < full.fields.size(); ++i) {
            EXPECT_TRUE(sameField(details.fields[i], full.fields[i])) << "packet " << summary.number << " layer " << full.fields[i].text;
        }
    }
    EXPECT_NE(packets[9].info.find("Seq=1"), std::string::npos) << "relative numbers are part of the summary";
}
#endif

#ifdef IMSHARK_TEST_DATA_DIR
TEST(SampleCapture, ParsesEverythingInTheSampleFile) {
    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(fp.processPcapFile(IMSHARK_TEST_DATA_DIR "/sample.pcap", packets, message)) << message;
    EXPECT_TRUE(message.empty());

    std::vector<std::string> protocols;
    for (const auto &p: packets) protocols.push_back(p.protocol);
    const std::vector<std::string> expected = {"ARP", "ARP", "ICMP", "ICMP", "DNS", "DNS", "TCP", "TCP", "TCP", "TCP",
                                               "TCP", "SMTP", "UDP", "UDP", "Ethernet", "TCP"};
    EXPECT_EQ(protocols, expected);
    EXPECT_EQ(packets[5].info, "Standard query response 0x1234 A example.com example.com A 93.184.216.34");
    EXPECT_EQ(packets[13].vlan_ids, std::vector<uint16_t>{100});
    EXPECT_NE(packets[15].info.find("Malformed"), std::string::npos);
}
#endif

TEST(Readers, ProgressAndCancellation) {
    // progress: totals and counters are published
    {
        core::LoadControl control;
        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        const auto bytes = pcapFile(false, 0xa1b2c3d4, {{1, 0}, {2, 0}, {3, 0}});
        const auto path = support::writeTemp("progress.pcap", bytes);
        ASSERT_TRUE(fp.processPcapFile(path, packets, message, &control));
        EXPECT_EQ(control.totalBytes, bytes.size());
        EXPECT_EQ(control.bytesProcessed, bytes.size());
        EXPECT_EQ(control.packetsLoaded, 3u);
        std::remove(path.c_str());
    }
    // cancellation requested up-front stops after the first packet / block, for both formats
    for (bool ng: {false, true}) {
        core::LoadControl control;
        control.cancelRequested = true;
        core::FileProcessor fp;
        std::vector<packet::PacketInfo> packets;
        std::string message;
        const auto bytes = ng ? pcapngFile(false, -1, {1, 2, 3}) : pcapFile(false, 0xa1b2c3d4, {{1, 0}, {2, 0}, {3, 0}});
        const auto path = support::writeTemp("cancel.bin", bytes);
        const bool ok = ng ? fp.processPcapngFile(path, packets, message, &control)
                           : fp.processPcapFile(path, packets, message, &control);
        EXPECT_FALSE(ok);
        EXPECT_EQ(message, "Cancelled");
        EXPECT_LT(packets.size(), 3u);
        std::remove(path.c_str());
    }
}
