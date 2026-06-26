#include <gtest/gtest.h>

#include <numeric>

#include <core.h>
#include <ui/find.h>

namespace {
    struct Sample {
        std::vector<packet::PacketInfo> packets;
        std::vector<uint32_t> order;
        Sample() {
            core::FileProcessor fp;
            std::string message;
            fp.processPcapFile(IMSHARK_TEST_DATA_DIR "/sample.pcap", packets, message);
            order.resize(packets.size());
            std::iota(order.begin(), order.end(), 0u);
        }
        ui::FindResult find(ui::FindMode m, const std::string &q, int from, bool fwd = true) const {
            return ui::findPacket(packets, order, 0, m, q, from, fwd);
        }
    };
} // namespace

TEST(Find, TextSearchIsCaseInsensitiveAndWraps) {
    Sample s;
    EXPECT_EQ(s.find(ui::FindMode::Text, "example.com", -1).position, 4);
    EXPECT_EQ(s.find(ui::FindMode::Text, "EXAMPLE.COM", -1).position, 4);
    EXPECT_EQ(s.find(ui::FindMode::Text, "example.com", 4).position, 5);
    EXPECT_EQ(s.find(ui::FindMode::Text, "example.com", 5).position, 4) << "wraps to the first match";
    EXPECT_EQ(s.find(ui::FindMode::Text, "example.com", 4, false).position, 5) << "previous from the first match wraps to the last";
    EXPECT_EQ(s.find(ui::FindMode::Text, "example.com", 5, false).position, 4);
    EXPECT_EQ(s.find(ui::FindMode::Text, "example.com", -1, false).position, 5) << "backwards from nothing starts at the end";
    EXPECT_EQ(s.find(ui::FindMode::Text, "no-such-text", -1).position, -1);
}

TEST(Find, TextSearchCoversAllSummaryColumns) {
    Sample s;
    EXPECT_EQ(s.find(ui::FindMode::Text, "8.8.8.8", -1).position, 4) << "destination";
    EXPECT_EQ(s.find(ui::FindMode::Text, "smtp", -1).position, 11) << "protocol";
    EXPECT_EQ(s.find(ui::FindMode::Text, "ehlo", -1).position, 11) << "info";
    EXPECT_EQ(s.find(ui::FindMode::Text, "2001:db8::1", -1).position, 12) << "source";
}

TEST(Find, FilterSearchAndErrors) {
    Sample s;
    EXPECT_EQ(s.find(ui::FindMode::Filter, "tcp.flags.fin", -1).position, 10);
    EXPECT_EQ(s.find(ui::FindMode::Filter, "tcp.flags.syn", 6).position, 7);
    EXPECT_EQ(s.find(ui::FindMode::Filter, "frame.time_delta > 100", -1).position, -1);
    const auto bad = s.find(ui::FindMode::Filter, "tcp &&", -1);
    EXPECT_EQ(bad.position, -1);
    EXPECT_NE(bad.error.find("ends unexpectedly"), std::string::npos);
    EXPECT_NE(bad.error.find("position 7"), std::string::npos);
    EXPECT_TRUE(s.find(ui::FindMode::Filter, "arp", -1).error.empty());
}

TEST(Find, RespectsTheDisplayedOrder) {
    Sample s;
    s.order = {15, 11, 4, 9};                  // a filtered, sorted view
    EXPECT_EQ(s.find(ui::FindMode::Filter, "tcp", -1).position, 0);
    EXPECT_EQ(s.find(ui::FindMode::Filter, "tcp", 0).position, 1);
    EXPECT_EQ(s.find(ui::FindMode::Filter, "tcp", 1).position, 3) << "row 2 is DNS";
    EXPECT_EQ(s.find(ui::FindMode::Filter, "dns", -1).position, 2);
    s.order.clear();
    EXPECT_EQ(s.find(ui::FindMode::Text, "x", -1).position, -1) << "nothing displayed, nothing found";
    s.order = {0};
    EXPECT_EQ(s.find(ui::FindMode::Text, "", -1).position, -1) << "an empty query finds nothing";
}

// ---- searching inside the frame bytes -------------------------------------------------------------------

#include <capture_reader.h>

namespace {
    const char *kSample = IMSHARK_TEST_DATA_DIR "/sample.pcap";
}

TEST(ByteSearch, HexNeedleParsing) {
    std::string error;
    EXPECT_EQ(ui::parseHexNeedle("de ad be ef", error)->bytes, (std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef}));
    EXPECT_EQ(ui::parseHexNeedle("DEADBEEF", error)->bytes, (std::vector<uint8_t>{0xde, 0xad, 0xbe, 0xef}));
    EXPECT_EQ(ui::parseHexNeedle("0xde 0xAD", error)->bytes, (std::vector<uint8_t>{0xde, 0xad}));
    EXPECT_EQ(ui::parseHexNeedle("de:ad-be", error)->bytes, (std::vector<uint8_t>{0xde, 0xad, 0xbe}));
    EXPECT_FALSE(ui::parseHexNeedle("", error));
    EXPECT_FALSE(ui::parseHexNeedle("abc", error));
    EXPECT_NE(error.find("Odd number"), std::string::npos);
    EXPECT_FALSE(ui::parseHexNeedle("zz", error));
    EXPECT_NE(error.find("not a hex digit"), std::string::npos);
    EXPECT_FALSE(ui::parseHexNeedle("0x", error));
}

TEST(ByteSearch, FrameContains) {
    const std::vector<char> frame = {'a', 'B', 'c', 'D', 'e', 0, 1};
    EXPECT_TRUE(ui::frameContains(frame, ui::ByteNeedle{{'B', 'c'}, false}));
    EXPECT_FALSE(ui::frameContains(frame, ui::ByteNeedle{{'b', 'C'}, false}));
    EXPECT_TRUE(ui::frameContains(frame, ui::textNeedle("bCd"))) << "text search ignores ASCII case";
    EXPECT_TRUE(ui::frameContains(frame, ui::ByteNeedle{{0, 1}, false}));
    EXPECT_FALSE(ui::frameContains(frame, ui::ByteNeedle{{1, 0}, false}));
    EXPECT_FALSE(ui::frameContains(frame, ui::ByteNeedle{}));
    EXPECT_FALSE(ui::frameContains({}, ui::textNeedle("x")));
    EXPECT_FALSE(ui::frameContains(frame, ui::textNeedle("abcde__too_long")));
}

TEST(ByteSearch, FindsPayloadsInTheSampleCapture) {
    Sample s;
    std::string error;
    auto find = [&](const ui::ByteNeedle &n, int from, bool fwd = true) {
        return ui::findBytes(kSample, s.packets, s.order, n, from, fwd, nullptr);
    };
    EXPECT_EQ(find(*ui::parseHexNeedle("47 45 54 20", error), -1).position, 9) << "'GET ' in the TCP payload";
    EXPECT_EQ(find(ui::textNeedle("get / http"), -1).position, 9);
    EXPECT_EQ(find(ui::textNeedle("EHLO imshark"), -1).position, 11);
    EXPECT_EQ(find(ui::textNeedle("vlan tagged"), -1).position, 13);
    // "example" is in the DNS query (4), its answer (5) and the HTTP Host header (9)
    EXPECT_EQ(find(ui::textNeedle("example"), -1).position, 4);
    EXPECT_EQ(find(ui::textNeedle("example"), 4).position, 5);
    EXPECT_EQ(find(ui::textNeedle("example"), 5).position, 9);
    EXPECT_EQ(find(ui::textNeedle("example"), 9).position, 4) << "wraps around";
    EXPECT_EQ(find(ui::textNeedle("example"), 4, false).position, 9) << "backwards wraps to the last match";
    EXPECT_EQ(find(ui::textNeedle("example"), 9, false).position, 5);
    EXPECT_EQ(find(ui::textNeedle("definitely not in there"), -1).position, -1);
    EXPECT_TRUE(find(ui::textNeedle("definitely not in there"), -1).error.empty());
    EXPECT_EQ(find(ui::ByteNeedle{{0x88, 0xcc}, false}, -1).position, 14) << "the unknown EtherType frame";
}

TEST(ByteSearch, UsesTheDisplayedOrderAndReportsProblems) {
    Sample s;
    s.order = {15, 11, 9};
    EXPECT_EQ(ui::findBytes(kSample, s.packets, s.order, ui::textNeedle("ehlo"), -1, true, nullptr).position, 1);
    EXPECT_EQ(ui::findBytes(kSample, s.packets, s.order, ui::textNeedle("get"), 1, true, nullptr).position, 2);
    s.order = {4, 5};
    EXPECT_EQ(ui::findBytes(kSample, s.packets, s.order, ui::textNeedle("ehlo"), -1, true, nullptr).position, -1) << "hidden packets are not searched";

    const auto missing = ui::findBytes("/no/such/file.pcap", s.packets, s.order, ui::textNeedle("x"), -1, true, nullptr);
    EXPECT_EQ(missing.position, -1);
    EXPECT_FALSE(missing.error.empty());
    EXPECT_EQ(ui::findBytes(kSample, s.packets, {}, ui::textNeedle("x"), -1, true, nullptr).position, -1);
}

TEST(ByteSearch, CanBeCancelled) {
    Sample s;
    core::ScanControl control;
    control.cancelRequested = true;
    bool cancelled = false;
    const auto r = ui::findBytes(kSample, s.packets, s.order, ui::textNeedle("zzz"), -1, true, &control, &cancelled);
    EXPECT_TRUE(cancelled);
    EXPECT_EQ(r.position, -1);
    EXPECT_TRUE(r.error.empty());
}

TEST(Scan, VisitsFramesInTheGivenOrderWithProgressAndStopsEarly) {
    Sample s;
    std::vector<uint32_t> visited;
    core::ScanControl control;
    std::vector<uint32_t> order = {5, 1, 9, 3};
    ASSERT_TRUE(core::scanPackets(kSample, s.packets, order, [&](const packet::PacketInfo &p, const std::vector<char> &frame) {
        visited.push_back(static_cast<uint32_t>(p.number - 1));
        EXPECT_EQ(frame.size(), p.captured_length);
        return true;
    }, &control));
    EXPECT_EQ(visited, order);
    EXPECT_EQ(control.total, 4u);
    EXPECT_EQ(control.done, 4u);

    visited.clear();
    EXPECT_TRUE(core::scanPackets(kSample, s.packets, order, [&](const packet::PacketInfo &p, const std::vector<char> &) {
        visited.push_back(static_cast<uint32_t>(p.number - 1));
        return visited.size() < 2;
    })) << "stopping from the callback is not a failure";
    EXPECT_EQ(visited.size(), 2u);

    EXPECT_FALSE(core::scanPackets("/no/such/file", s.packets, order, [](const packet::PacketInfo &, const std::vector<char> &) { return true; }));
    std::vector<uint32_t> stale = {9999, 0};
    int count = 0;
    EXPECT_TRUE(core::scanPackets(kSample, s.packets, stale, [&](const packet::PacketInfo &, const std::vector<char> &) { ++count; return true; }));
    EXPECT_EQ(count, 1) << "out-of-range indices are skipped";
}
