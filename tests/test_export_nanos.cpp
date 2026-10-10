// Timestamp precision of the export: nanosecond captures stay nanosecond captures, microsecond ones stay as they were.

#include <gtest/gtest.h>

#include <cmath>
#include <cstdio>
#include <fstream>
#include <sstream>

#include <core.h>
#include <export/export.h>

#include "support.h"

namespace {
    using Bytes = std::vector<char>;

    struct Stamp { uint64_t seconds; uint32_t nanos; };

    Bytes frame(uint8_t tag) { return support::udpPacket("0a000001", "0a000002", "1000", "2000", std::string(1, static_cast<char>('a' + tag))); }

    void put32(Bytes &b, uint32_t v) { support::put(b, v); }
    void put16(Bytes &b, uint16_t v) { support::put(b, v); }

    // classic pcap, little endian, microsecond or nanosecond magic
    std::string writePcap(const std::vector<Stamp> &stamps, bool nano) {
        Bytes f;
        put32(f, nano ? 0xa1b23c4d : 0xa1b2c3d4);
        put16(f, 2); put16(f, 4); put32(f, 0); put32(f, 0); put32(f, 65535); put32(f, 1);
        uint8_t tag = 0;
        for (const auto &s: stamps) {
            const Bytes fr = frame(tag++);
            put32(f, static_cast<uint32_t>(s.seconds));
            put32(f, nano ? s.nanos : s.nanos / 1000);
            put32(f, static_cast<uint32_t>(fr.size())); put32(f, static_cast<uint32_t>(fr.size()));
            f.insert(f.end(), fr.begin(), fr.end());
        }
        return support::writeTemp("nanos.pcap", f);
    }

    void block(Bytes &out, uint32_t type, const Bytes &body) {
        put32(out, type); put32(out, static_cast<uint32_t>(body.size() + 12));
        out.insert(out.end(), body.begin(), body.end());
        put32(out, static_cast<uint32_t>(body.size() + 12));
    }

    struct Itf { int tsresol; };   // -1: no if_tsresol option (microseconds)
    struct NgPacket { int itf; Stamp stamp; };

    // pcapng, little endian; timestamps are given in nanoseconds and converted to each interface's resolution
    std::string writePcapng(const std::vector<Itf> &itfs, const std::vector<NgPacket> &packets) {
        Bytes f;
        Bytes shb;
        put32(shb, 0x1A2B3C4D); put16(shb, 1); put16(shb, 0); put32(shb, 0xffffffffu); put32(shb, 0xffffffffu);
        block(f, 0x0A0D0D0A, shb);
        for (const auto &i: itfs) {
            Bytes idb;
            put16(idb, 1); put16(idb, 0); put32(idb, 0);
            if (i.tsresol >= 0) {
                put16(idb, 9); put16(idb, 1); idb.push_back(static_cast<char>(i.tsresol)); idb.insert(idb.end(), 3, 0);
                put16(idb, 0); put16(idb, 0);
            }
            block(f, 1, idb);
        }
        uint8_t tag = 0;
        for (const auto &p: packets) {
            const int res = itfs[static_cast<size_t>(p.itf)].tsresol;
            const int exponent = res < 0 ? 6 : res;
            uint64_t ticks = p.stamp.seconds;
            for (int k = 0; k < exponent; ++k) ticks *= 10;
            uint64_t frac = p.stamp.nanos;
            for (int k = 9; k > exponent; --k) frac /= 10;
            for (int k = 9; k < exponent; ++k) frac *= 10;
            ticks += frac;
            const Bytes fr = frame(tag++);
            Bytes epb;
            put32(epb, static_cast<uint32_t>(p.itf)); put32(epb, static_cast<uint32_t>(ticks >> 32)); put32(epb, static_cast<uint32_t>(ticks));
            put32(epb, static_cast<uint32_t>(fr.size())); put32(epb, static_cast<uint32_t>(fr.size()));
            epb.insert(epb.end(), fr.begin(), fr.end());
            epb.insert(epb.end(), (4 - fr.size() % 4) % 4, 0);
            block(f, 6, epb);
        }
        return support::writeTemp("nanos.pcapng", f);
    }

    struct Loaded {
        std::vector<packet::PacketInfo> packets;
        core::CaptureInfo info;
        double epoch = 0;
        bool ok = false;
        std::string message;
        explicit Loaded(const std::string &path) {
            core::FileProcessor fp;
            ok = fp.processFile(path, packets, message);
            info = fp.captureInfo();
            epoch = fp.captureStartEpoch();
        }
        // exact instant of packet i in nanoseconds since the epoch
        long long ns(size_t i) const {
            return static_cast<long long>(info.startSeconds) * 1000000000LL + info.startNanos + std::llround(packets[i].time * 1e9);
        }
    };

    long long ns(const Stamp &s) { return static_cast<long long>(s.seconds) * 1000000000LL + s.nanos; }

    std::string slurp(const std::string &path) {
        std::ifstream f(path, std::ios::binary);
        std::stringstream ss;
        ss << f.rdbuf();
        return ss.str();
    }

    uint32_t u32(const std::string &s, size_t at) {
        uint32_t v = 0;
        for (int i = 3; i >= 0; --i) v = (v << 8) | static_cast<unsigned char>(s[at + static_cast<size_t>(i)]);
        return v;
    }

    const std::vector<Stamp> kStamps = {{1700000000, 123456789}, {1700000000, 123456790}, {1700000000, 999999999},
                                        {1700000001, 0},         {1700000001, 1},         {1700086400, 987654321}};

    std::vector<uint32_t> all(size_t n) {
        std::vector<uint32_t> v(n);
        for (size_t i = 0; i < n; ++i) v[i] = static_cast<uint32_t>(i);
        return v;
    }
} // namespace

TEST(ExportNanos, LoaderKeepsTheExactStart) {
    const auto path = writePcap(kStamps, true);
    Loaded in(path);
    ASSERT_TRUE(in.ok) << in.message;
    EXPECT_TRUE(in.info.nanosecondTimestamps());
    EXPECT_TRUE(in.info.hasStart);
    EXPECT_EQ(in.info.startSeconds, 1700000000);
    EXPECT_EQ(in.info.startNanos, 123456789u);
    for (size_t i = 0; i < kStamps.size(); ++i) EXPECT_EQ(in.ns(i), ns(kStamps[i])) << i;
    std::remove(path.c_str());
}

TEST(ExportNanos, NanosecondPcapRoundTripsThroughPcapAndPcapng) {
    const auto source = writePcap(kStamps, true);
    Loaded in(source);
    ASSERT_TRUE(in.ok) << in.message;
    for (auto format: {exporter::Format::Pcap, exporter::Format::Pcapng}) {
        const bool ng = format == exporter::Format::Pcapng;
        SCOPED_TRACE(exporter::formatName(format));
        const auto out = support::tempPath(ng ? "ns_out.pcapng" : "ns_out.pcap");
        std::string error;
        ASSERT_TRUE(exporter::exportPackets(source, in.packets, all(in.packets.size()), in.epoch, format, out, error, nullptr, nullptr, &in.info)) << error;

        const std::string raw = slurp(out);
        if (!ng) EXPECT_EQ(u32(raw, 0), 0xa1b23c4du) << "nanosecond magic";
        Loaded back(out);
        ASSERT_TRUE(back.ok) << back.message;
        EXPECT_TRUE(back.info.nanosecondTimestamps());
        if (ng) {
            ASSERT_EQ(back.info.interfaces.size(), 1u);
            EXPECT_EQ(back.info.interfaces[0].ticksPerSecond, 1000000000ull) << "if_tsresol = 9";
        }
        ASSERT_EQ(back.packets.size(), kStamps.size());
        for (size_t i = 0; i < kStamps.size(); ++i) EXPECT_EQ(back.ns(i), ns(kStamps[i])) << i;
        std::remove(out.c_str());
    }
    std::remove(source.c_str());
}

TEST(ExportNanos, SubsetKeepsTheOriginalInstants) {
    const auto source = writePcap(kStamps, true);
    Loaded in(source);
    ASSERT_TRUE(in.ok);
    const auto out = support::tempPath("ns_subset.pcapng");
    std::string error;
    ASSERT_TRUE(exporter::exportPackets(source, in.packets, {4, 1, 5}, in.epoch, exporter::Format::Pcapng, out, error, nullptr, nullptr, &in.info)) << error;
    Loaded back(out);
    ASSERT_TRUE(back.ok);
    ASSERT_EQ(back.packets.size(), 3u);
    EXPECT_EQ(back.ns(0), ns(kStamps[4]));
    EXPECT_EQ(back.ns(1), ns(kStamps[1]));
    EXPECT_EQ(back.ns(2), ns(kStamps[5]));
    std::remove(out.c_str());
    std::remove(source.c_str());
}

TEST(ExportNanos, MicrosecondCapturesAreWrittenAsBefore) {
    const std::vector<Stamp> us = {{1700000000, 123456000}, {1700000000, 123457000}, {1700000002, 5000}};
    const auto source = writePcap(us, false);
    Loaded in(source);
    ASSERT_TRUE(in.ok);
    EXPECT_FALSE(in.info.nanosecondTimestamps());
    for (auto format: {exporter::Format::Pcap, exporter::Format::Pcapng}) {
        const bool ng = format == exporter::Format::Pcapng;
        const auto out = support::tempPath(ng ? "us_out.pcapng" : "us_out.pcap");
        std::string error;
        ASSERT_TRUE(exporter::exportPackets(source, in.packets, all(in.packets.size()), in.epoch, format, out, error, nullptr, nullptr, &in.info)) << error;
        if (!ng) EXPECT_EQ(u32(slurp(out), 0), 0xa1b2c3d4u) << "microsecond magic";
        Loaded back(out);
        ASSERT_TRUE(back.ok);
        EXPECT_FALSE(back.info.nanosecondTimestamps());
        ASSERT_EQ(back.packets.size(), us.size());
        for (size_t i = 0; i < us.size(); ++i) EXPECT_EQ(back.ns(i), ns(us[i])) << i;
        std::remove(out.c_str());
    }
    std::remove(source.c_str());
}

TEST(ExportNanos, MixedResolutionInterfacesAreWrittenAtTheFinestOne) {
    // interface 0: microseconds (default), 1: nanoseconds, 2: milliseconds
    const std::vector<NgPacket> packets = {{0, {1700000000, 111111000}}, {1, {1700000000, 222222222}}, {2, {1700000000, 333000000}},
                                           {1, {1700000001, 1}},         {0, {1700000001, 5000}}};
    const auto source = writePcapng({{-1}, {9}, {3}}, packets);
    Loaded in(source);
    ASSERT_TRUE(in.ok) << in.message;
    ASSERT_EQ(in.info.interfaces.size(), 3u);
    ASSERT_TRUE(in.info.nanosecondTimestamps());
    for (size_t i = 0; i < packets.size(); ++i) ASSERT_EQ(in.ns(i), ns(packets[i].stamp)) << "reader " << i;

    for (auto format: {exporter::Format::Pcapng, exporter::Format::Pcap}) {
        const bool ng = format == exporter::Format::Pcapng;
        const auto out = support::tempPath(ng ? "mixed.pcapng" : "mixed.pcap");
        std::string error;
        ASSERT_TRUE(exporter::exportPackets(source, in.packets, all(in.packets.size()), in.epoch, format, out, error, nullptr, nullptr, &in.info)) << error;
        Loaded back(out);
        ASSERT_TRUE(back.ok) << back.message;
        for (const auto &itf: back.info.interfaces) EXPECT_EQ(itf.ticksPerSecond, 1000000000ull);
        ASSERT_EQ(back.packets.size(), packets.size());
        for (size_t i = 0; i < packets.size(); ++i) EXPECT_EQ(back.ns(i), ns(packets[i].stamp)) << i;
        std::remove(out.c_str());
    }
    std::remove(source.c_str());
}

TEST(ExportNanos, TablesCarryFullPrecisionTime) {
    const auto source = writePcap(kStamps, true);
    Loaded in(source);
    ASSERT_TRUE(in.ok);

    std::ostringstream csv;
    exporter::writeCsv(csv, in.packets, {1}, 9);
    EXPECT_NE(csv.str().find("\"0.000000001\""), std::string::npos) << csv.str();

    std::ostringstream json;
    exporter::writeJson(json, in.packets, {0, 5}, in.epoch, 9, &in.info);
    EXPECT_NE(json.str().find("\"time_epoch\": 1700000000.123456789"), std::string::npos) << json.str();
    EXPECT_NE(json.str().find("\"time_epoch\": 1700086400.987654321"), std::string::npos) << json.str();

    // through the exporter: nanosecond captures get nine decimals, microsecond ones keep six
    const auto out = support::tempPath("ns.csv");
    std::string error;
    ASSERT_TRUE(exporter::exportPackets(source, in.packets, {1}, in.epoch, exporter::Format::Csv, out, error, nullptr, nullptr, &in.info)) << error;
    EXPECT_NE(slurp(out).find("\"0.000000001\""), std::string::npos);
    ASSERT_TRUE(exporter::exportPackets(source, in.packets, {1}, in.epoch, exporter::Format::Csv, out, error)) << error;
    EXPECT_NE(slurp(out).find("\"0.000000\""), std::string::npos) << "without capture info: the old microsecond table";
    std::remove(out.c_str());
    std::remove(source.c_str());
}
