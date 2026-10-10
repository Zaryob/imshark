#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>

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

TEST(Settings, CaptureOptionsRoundTripAndDefaults) {
    const ui::Settings defaults;
    EXPECT_TRUE(defaults.captureInterface.empty());
    EXPECT_TRUE(defaults.captureFilter.empty());
    EXPECT_EQ(defaults.captureSnaplen, 262144u);
    EXPECT_TRUE(defaults.capturePromiscuous);

    const auto path = tempPath("capture");
    ui::Settings s;
    s.captureInterface = "en0";
    s.captureFilter = "tcp port 80 and host 10.0.0.1";
    s.captureSnaplen = 1500;
    s.capturePromiscuous = false;
    ASSERT_TRUE(ui::saveSettings(s, path));
    const auto loaded = ui::loadSettings(path);
    EXPECT_EQ(loaded.captureInterface, "en0");
    EXPECT_EQ(loaded.captureFilter, "tcp port 80 and host 10.0.0.1");
    EXPECT_EQ(loaded.captureSnaplen, 1500u);
    EXPECT_FALSE(loaded.capturePromiscuous);

    // a line break in the filter must not corrupt the file (it is flattened); out-of-range snaplens are ignored
    s.captureFilter = "udp\nport 53";
    s.captureSnaplen = 1500;
    ASSERT_TRUE(ui::saveSettings(s, path));
    EXPECT_EQ(ui::loadSettings(path).captureFilter, "udp port 53");
    {
        std::ofstream f(path);
        f << "capture_snaplen=10\ncapture_snaplen=abc\ncapture_snaplen=999999999\n";
    }
    EXPECT_EQ(ui::loadSettings(path).captureSnaplen, 262144u);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(Settings, NumericValuesMustBeComplete) {
    const auto path = tempPath("numeric_suffix");
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    {
        std::ofstream file(path);
        file << "list_height=450px\ncapture_snaplen=1500bytes\ncapture_snaplen=-18446744073709550116\n";
    }
    const auto settings = ui::loadSettings(path);
    const ui::Settings defaults;
    EXPECT_FLOAT_EQ(settings.listHeight, defaults.listHeight);
    EXPECT_EQ(settings.captureSnaplen, defaults.captureSnaplen);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(Settings, HistoryCannotInjectOtherSettings) {
    const auto path = tempPath("history_lines");
    ui::Settings settings;
    settings.recentFiles = {"/a.pcap\ntheme=light"};
    settings.filterHistory = {"tcp\rcapture_snaplen=64"};
    ASSERT_TRUE(ui::saveSettings(settings, path));
    const auto loaded = ui::loadSettings(path);
    EXPECT_TRUE(loaded.darkTheme);
    EXPECT_EQ(loaded.captureSnaplen, ui::Settings::kMaxSnaplen);
    EXPECT_EQ(loaded.recentFiles, std::vector<std::string>{"/a.pcap theme=light"});
    EXPECT_EQ(loaded.filterHistory, std::vector<std::string>{"tcp capture_snaplen=64"});

    settings.filterHistory.clear();
    ui::addFilterHistory(settings, "tcp\rudp");
    EXPECT_TRUE(settings.filterHistory.empty());
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(Settings, ToolbarAndWindowGeometryRoundTrip) {
    const auto path = tempPath("geometry");
    const ui::Settings defaults;
    EXPECT_TRUE(defaults.showToolbar);
    EXPECT_FALSE(defaults.hasWindowPos);
    EXPECT_EQ(defaults.windowWidth, 0);

    ui::Settings s;
    s.showToolbar = false;
    s.windowWidth = 1500;
    s.windowHeight = 900;
    s.windowX = -1200; // a monitor to the left of the primary one
    s.windowY = 40;
    s.hasWindowPos = true;
    ASSERT_TRUE(ui::saveSettings(s, path));
    const auto loaded = ui::loadSettings(path);
    EXPECT_FALSE(loaded.showToolbar);
    EXPECT_EQ(loaded.windowWidth, 1500);
    EXPECT_EQ(loaded.windowHeight, 900);
    EXPECT_EQ(loaded.windowX, -1200);
    EXPECT_EQ(loaded.windowY, 40);
    EXPECT_TRUE(loaded.hasWindowPos);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(Settings, InvalidWindowGeometryIsIgnored) {
    const auto path = tempPath("badgeometry");
    std::filesystem::create_directories(std::filesystem::path(path).parent_path());
    {
        std::ofstream f(path);
        f << "window_size=0x0\nwindow_size=abc\nwindow_size=-5x300\nwindow_pos=1;2\nwindow_pos=x,y\nwindow_size=800x600junk\n";
    }
    const auto s = ui::loadSettings(path);
    EXPECT_EQ(s.windowWidth, 0);
    EXPECT_EQ(s.windowHeight, 0);
    EXPECT_FALSE(s.hasWindowPos);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(Settings, RestoredWindowIsClampedToTheWorkArea) {
    const ui::WindowRect area{0, 25, 1920, 1055};
    ui::Settings s;
    ui::WindowRect out;
    bool hasPos = true;
    EXPECT_FALSE(ui::restoreWindowRect(s, area, 640, 400, out, hasPos)) << "nothing saved";
    EXPECT_FALSE(hasPos);

    s.windowWidth = 1000;
    s.windowHeight = 700;
    EXPECT_TRUE(ui::restoreWindowRect(s, area, 640, 400, out, hasPos));
    EXPECT_FALSE(hasPos) << "size only";
    EXPECT_EQ(out.w, 1000);
    EXPECT_EQ(out.h, 700);

    s.hasWindowPos = true;
    s.windowX = 5000; // monitor that is gone
    s.windowY = -300;
    EXPECT_TRUE(ui::restoreWindowRect(s, area, 640, 400, out, hasPos));
    EXPECT_TRUE(hasPos);
    EXPECT_EQ(out.x, 920);
    EXPECT_EQ(out.y, 25);

    s.windowWidth = 9000; // larger than the screen
    s.windowHeight = 10;  // smaller than the minimum
    EXPECT_TRUE(ui::restoreWindowRect(s, area, 640, 400, out, hasPos));
    EXPECT_EQ(out.w, 1920);
    EXPECT_EQ(out.h, 400);
    EXPECT_EQ(out.x, 0);
}

namespace {
    std::string readAll(const std::filesystem::path &p) {
        std::ifstream f(p, std::ios::binary);
        return {std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
    }

    void writeAll(const std::string &path, const std::string &content) {
        std::filesystem::create_directories(std::filesystem::path(path).parent_path());
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        f << content;
    }

    std::vector<std::filesystem::path> backupsOf(const std::string &path) {
        std::vector<std::filesystem::path> found;
        const std::filesystem::path p(path);
        for (const auto &e: std::filesystem::directory_iterator(p.parent_path())) {
            if (e.path().filename().string().rfind(p.filename().string() + ".bak-", 0) == 0) found.push_back(e.path());
        }
        return found;
    }

    std::size_t fileCount(const std::string &path) {
        return static_cast<std::size_t>(std::distance(std::filesystem::directory_iterator(std::filesystem::path(path).parent_path()),
                                                      std::filesystem::directory_iterator()));
    }
} // namespace

TEST(SettingsVersion, SaveWritesTheVersionAsTheFirstLineAndLoadReportsIt) {
    const auto path = tempPath("version_roundtrip");
    ASSERT_TRUE(ui::saveSettings(ui::Settings(), path));
    const std::string text = readAll(path);
    // text mode: the line ends in "\r\n" on Windows, which the reader accepts too
    const std::string firstLine = text.substr(0, text.find('\n'));
    EXPECT_EQ(firstLine.substr(0, firstLine.find('\r')), "settings_version=" + std::to_string(ui::kSettingsVersion));
    const auto loaded = ui::loadSettings(path);
    EXPECT_EQ(loaded.loadedVersion, ui::kSettingsVersion);
    EXPECT_FALSE(loaded.fromNewerVersion);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(SettingsVersion, LegacyFileWithoutVersionMigratesToCurrent) {
    const auto path = tempPath("version_legacy");
    writeAll(path, "theme=light\nlist_height=320\nrecent=/a.pcap\nfilter=tcp\n");
    const auto legacy = ui::loadSettings(path);
    EXPECT_EQ(legacy.loadedVersion, 0);
    EXPECT_FALSE(legacy.fromNewerVersion);
    EXPECT_FALSE(legacy.darkTheme);
    EXPECT_FLOAT_EQ(legacy.listHeight, 320.0f);

    ASSERT_TRUE(ui::saveSettings(legacy, path)); // the migration is the identity plus the version key
    EXPECT_TRUE(backupsOf(path).empty()) << "a legacy file is valid, not corrupt";
    const auto migrated = ui::loadSettings(path);
    EXPECT_EQ(migrated.loadedVersion, ui::kSettingsVersion);
    EXPECT_FALSE(migrated.darkTheme);
    EXPECT_FLOAT_EQ(migrated.listHeight, 320.0f);
    EXPECT_EQ(migrated.recentFiles, std::vector<std::string>{"/a.pcap"});
    EXPECT_EQ(migrated.filterHistory, std::vector<std::string>{"tcp"});
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(SettingsVersion, FutureVersionIsReadButNeverOverwritten) {
    const auto path = tempPath("version_future");
    const std::string original = "settings_version=99\ntheme=light\nnew_future_key=keep me\nlist_height=333\n";
    writeAll(path, original);
    const auto loaded = ui::loadSettings(path);
    EXPECT_TRUE(loaded.fromNewerVersion);
    EXPECT_EQ(loaded.loadedVersion, 99);
    EXPECT_FALSE(loaded.darkTheme) << "known keys are still read";
    EXPECT_FLOAT_EQ(loaded.listHeight, 333.0f);

    ui::Settings changed = loaded;
    changed.darkTheme = true;
    EXPECT_TRUE(ui::saveSettings(changed, path)) << "reported as handled so the UI does not retry every frame";
    EXPECT_EQ(readAll(path), original);
    EXPECT_TRUE(backupsOf(path).empty());
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(SettingsVersion, UnknownKeysAreDroppedOnSaveOfAnOlderOrCurrentFile) {
    const auto path = tempPath("version_unknown_keys");
    writeAll(path, "settings_version=1\ntheme=light\nmystery=1\n");
    ASSERT_TRUE(ui::saveSettings(ui::loadSettings(path), path));
    const std::string text = readAll(path);
    EXPECT_EQ(text.find("mystery"), std::string::npos);
    EXPECT_NE(text.find("theme=light"), std::string::npos);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(SettingsVersion, CorruptFileIsBackedUpBeforeItIsReplaced) {
    const auto path = tempPath("version_corrupt");
    const std::string garbage = std::string("\x01\x02 not a settings file\0\xff", 25);
    writeAll(path, garbage);
    const auto loaded = ui::loadSettings(path);
    EXPECT_TRUE(loaded.darkTheme) << "defaults";
    EXPECT_EQ(loaded.loadedVersion, 0);

    ASSERT_TRUE(ui::saveSettings(loaded, path));
    const auto backups = backupsOf(path);
    ASSERT_EQ(backups.size(), 1u);
    EXPECT_EQ(readAll(backups[0]), garbage);
    EXPECT_EQ(ui::loadSettings(path).loadedVersion, ui::kSettingsVersion);

    // a second save of the now-valid file makes no further backup
    ASSERT_TRUE(ui::saveSettings(loaded, path));
    EXPECT_EQ(backupsOf(path).size(), 1u);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(SettingsVersion, TextWithoutAnyKnownKeyAndMalformedVersionCountAsCorrupt) {
    for (const std::string content: {std::string("hello world\nthis is prose\n"), std::string("settings_version=abc\ntheme=light\n")}) {
        const auto path = tempPath("version_corrupt_text");
        writeAll(path, content);
        ASSERT_TRUE(ui::saveSettings(ui::Settings(), path));
        const auto backups = backupsOf(path);
        ASSERT_EQ(backups.size(), 1u) << content;
        EXPECT_EQ(readAll(backups[0]), content);
        std::filesystem::remove_all(std::filesystem::path(path).parent_path());
    }
}

TEST(SettingsVersion, EmptyFileIsNotBackedUp) {
    const auto path = tempPath("version_empty");
    writeAll(path, "");
    ASSERT_TRUE(ui::saveSettings(ui::Settings(), path));
    EXPECT_TRUE(backupsOf(path).empty());
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(SettingsVersion, SaveLeavesNoTemporaryFilesBehind) {
    const auto path = tempPath("version_notemp");
    ASSERT_TRUE(ui::saveSettings(ui::Settings(), path));
    ASSERT_TRUE(ui::saveSettings(ui::Settings(), path));
    EXPECT_EQ(fileCount(path), 1u);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST(SettingsVersion, FailedSaveLeavesTheOldFileIntact) {
    const auto path = tempPath("version_atomic");
    ui::Settings first;
    first.darkTheme = false;
    ASSERT_TRUE(ui::saveSettings(first, path));
    const std::string before = readAll(path);

    // a directory in place of the file cannot be replaced
    const auto dirPath = tempPath("version_atomic_dir");
    std::filesystem::create_directories(dirPath);
    EXPECT_FALSE(ui::saveSettings(first, dirPath));
    std::filesystem::remove_all(std::filesystem::path(dirPath).parent_path());

#ifndef _WIN32
    // a read-only directory cannot take the temporary file, so the old file must survive untouched
    namespace fs = std::filesystem;
    const fs::path dir = fs::path(path).parent_path();
    fs::permissions(dir, fs::perms::owner_read | fs::perms::owner_exec, fs::perm_options::replace);
    ui::Settings second = first;
    second.darkTheme = true;
    const bool wrote = ui::saveSettings(second, path);
    fs::permissions(dir, fs::perms::owner_all, fs::perm_options::replace);
    if (wrote) GTEST_SKIP() << "directory permissions are not enforced here (running as root?)";
    EXPECT_EQ(readAll(path), before);
    EXPECT_FALSE(ui::loadSettings(path).darkTheme);
    EXPECT_EQ(fileCount(path), 1u);
#endif
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}
