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
