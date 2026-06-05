#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>

#include <ui/settings.h>

namespace {
    std::string tempPath(const std::string &name) {
        return (std::filesystem::temp_directory_path() / ("imshark_settings_test_" + name + "/settings.ini")).string();
    }
} // namespace

TEST(Settings, RoundTrip) {
    const auto path = tempPath("roundtrip");
    ui::Settings s;
    s.darkTheme = false;
    s.listHeight = 412.5f;
    ui::addRecentFile(s, "/a/one.pcap");
    ui::addRecentFile(s, "/b/two dir/two.pcapng");
    ASSERT_TRUE(ui::saveSettings(s, path)); // also creates the directory

    const auto loaded = ui::loadSettings(path);
    EXPECT_FALSE(loaded.darkTheme);
    EXPECT_FLOAT_EQ(loaded.listHeight, 412.5f);
    EXPECT_EQ(loaded.recentFiles, (std::vector<std::string>{"/b/two dir/two.pcapng", "/a/one.pcap"}));
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(Settings, MissingOrDamagedFilesGiveDefaults) {
    const ui::Settings defaults;
    const auto missing = ui::loadSettings("/no/such/dir/settings.ini");
    EXPECT_TRUE(missing.darkTheme);
    EXPECT_FLOAT_EQ(missing.listHeight, defaults.listHeight);
    EXPECT_TRUE(missing.recentFiles.empty());

    const auto path = tempPath("damaged");
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    {
        std::ofstream f(path);
        f << "garbage without equals\nlist_height=not-a-number\nlist_height=99999\ntheme=light\nunknown=1\nrecent=\nrecent=/ok.pcap\r\n";
    }
    const auto s = ui::loadSettings(path);
    EXPECT_FALSE(s.darkTheme);
    EXPECT_FLOAT_EQ(s.listHeight, defaults.listHeight) << "invalid / out-of-range heights are ignored";
    EXPECT_EQ(s.recentFiles, std::vector<std::string>{"/ok.pcap"});
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(Settings, RecentFilesAreDeduplicatedAndCapped) {
    ui::Settings s;
    for (int i = 0; i < 15; ++i) ui::addRecentFile(s, "/f" + std::to_string(i));
    EXPECT_EQ(s.recentFiles.size(), ui::Settings::kMaxRecentFiles);
    EXPECT_EQ(s.recentFiles.front(), "/f14");
    ui::addRecentFile(s, "/f10"); // moves to the front instead of duplicating
    EXPECT_EQ(s.recentFiles.front(), "/f10");
    EXPECT_EQ(std::count(s.recentFiles.begin(), s.recentFiles.end(), "/f10"), 1);
    EXPECT_EQ(s.recentFiles.size(), ui::Settings::kMaxRecentFiles);
}

TEST(Settings, DefaultPathIsInsideAnImsharkDirectory) {
    const auto p = ui::defaultSettingsPath();
    EXPECT_NE(p.find("imshark"), std::string::npos);
    EXPECT_EQ(std::filesystem::path(p).filename(), "settings.ini");
}

TEST(Settings, FilterHistoryRoundTripsAndIsCapped) {
    ui::Settings s;
    for (int i = 0; i < 20; ++i) ui::addFilterHistory(s, "tcp.port == " + std::to_string(i));
    ui::addFilterHistory(s, "");                       // empty filters are not remembered
    ui::addFilterHistory(s, "a\nb");                   // nor are ones that would break the file format
    EXPECT_EQ(s.filterHistory.size(), ui::Settings::kMaxFilterHistory);
    EXPECT_EQ(s.filterHistory.front(), "tcp.port == 19");

    const auto path = tempPath("filters");
    ASSERT_TRUE(ui::saveSettings(s, path));
    const auto loaded = ui::loadSettings(path);
    EXPECT_EQ(loaded.filterHistory, s.filterHistory);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(Settings, ColorRulesAndColorizeRoundTrip) {
    ui::Settings s;
    s.colorize = false;
    s.colorRules = {{true, "A", "tcp", 0x112233, 0x445566}, {false, "B", "udp && ip.ttl < 5", 0xFFFFFF, 0x000000}};
    const auto path = tempPath("colors");
    ASSERT_TRUE(ui::saveSettings(s, path));
    const auto loaded = ui::loadSettings(path);
    EXPECT_FALSE(loaded.colorize);
    EXPECT_EQ(loaded.colorRules, s.colorRules);

    EXPECT_TRUE(ui::loadSettings("/no/such/file").colorRules.empty()) << "empty = built-in defaults";
    EXPECT_TRUE(ui::loadSettings("/no/such/file").colorize);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(Settings, TimeFormatRoundTrips) {
    ui::Settings s;
    EXPECT_EQ(s.timeFormat, ui::TimeFormat::SinceCaptureStart);
    s.timeFormat = ui::TimeFormat::UtcDateTime;
    const auto path = tempPath("timefmt");
    ASSERT_TRUE(ui::saveSettings(s, path));
    EXPECT_EQ(ui::loadSettings(path).timeFormat, ui::TimeFormat::UtcDateTime);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}
