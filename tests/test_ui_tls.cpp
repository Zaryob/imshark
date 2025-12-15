// The TLS key log setting and the Follow Stream "TLS (decrypted)" view, through the real UI code paths (headless ImGui).
//
// Oracles: the fixtures of tests/data/tls (real handshakes, plaintext known by construction, see tools/make_tls_fixtures.py).
#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <thread>

#include <imgui.h>

#include <core.h>
#include <tls/crypto.h>
#include <ui/settings.h>
#include <ui/ui.h>

#include "tls_support.h"

namespace {
    using tlstest::kDir;

    class UiTls : public ::testing::Test {
    protected:
        void SetUp() override {
            IMGUI_CHECKVERSION();
            ctx = ImGui::CreateContext();
            ImGuiIO &io = ImGui::GetIO();
            io.IniFilename = nullptr;
            io.DisplaySize = ImVec2(1280, 720);
            unsigned char *pixels;
            int w, h;
            io.Fonts->GetTexDataAsRGBA32(&pixels, &w, &h);
            // a classic pcap of the TLS 1.3 fixture: it holds no secrets, so what decrypts is decided by the user's key log
            tlstest::Loaded loaded(kDir + "tls13.pcapng");
            std::vector<std::vector<char>> frames;
            for (const auto &p: loaded.packets) {
                std::vector<char> bytes;
                core::readPacketBytes(loaded.path, p, bytes);
                frames.push_back(std::move(bytes));
            }
            // a name of its own: tests run as separate processes at the same time
            capture = support::writeTemp(std::string("ui_tls13_") + ::testing::UnitTest::GetInstance()->current_test_info()->name() + ".pcap", support::pcapBytes(frames));
            keyLog = kDir + "tls13.keys";
        }
        void TearDown() override {
            std::remove(capture.c_str());
            ImGui::DestroyContext(ctx);
        }

        void frame(ui::AppState &state) {
            ImGui::GetIO().DeltaTime = 1.0f / 60.0f;
            ImGui::NewFrame();
            ui::pollLoad(state);
            ui::pollCapture(state);
            ui::drawMenuAndDialogs(state);
            ui::drawMainWindow(state);
            ui::drawStatusBar(state);
            ui::drawLoadErrorPopup(state);
            ImGui::Render();
        }
        void waitLoaded(ui::AppState &state) {
            for (int i = 0; i < 5000 && state.loading(); ++i) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
            ASSERT_FALSE(state.loading());
        }
        static size_t httpPackets(const ui::AppState &state) {
            size_t n = 0;
            for (const auto &p: state.packets) if (p.protocol == "HTTP") ++n;
            return n;
        }
        std::string tempFile(const std::string &name, const std::string &text) {
            const std::string path = support::writeTemp(name, std::vector<char>(text.begin(), text.end()));
            temps.push_back(path);
            return path;
        }
        ~UiTls() override { for (const auto &t: temps) std::remove(t.c_str()); }

        ImGuiContext *ctx = nullptr;
        std::string capture, keyLog;
        std::vector<std::string> temps;
    };
}

TEST_F(UiTls, TheKeyLogPathIsASettingThatSurvivesARestart) {
    const auto dir = std::filesystem::temp_directory_path() / "imshark_ui_tls_settings";
    const std::string path = (dir / "settings.ini").string();
    ui::Settings s;
    EXPECT_TRUE(s.tlsKeyLogFile.empty());
    s.tlsKeyLogFile = "/home/me/tls keys.log";
    ASSERT_TRUE(ui::saveSettings(s, path));
    EXPECT_EQ(ui::loadSettings(path).tlsKeyLogFile, "/home/me/tls keys.log");
    s.tlsKeyLogFile.clear();
    ASSERT_TRUE(ui::saveSettings(s, path));
    EXPECT_TRUE(ui::loadSettings(path).tlsKeyLogFile.empty()) << "nothing is written for an empty setting";
    std::filesystem::remove_all(dir);

    // start-up reads the file of the setting
    const std::string settings = tempFile("ui_tls_start.ini", "tls_keylog=" + keyLog + "\n");
    ui::AppState state;
    ui::initSettings(state, settings);
    EXPECT_EQ(state.settings.tlsKeyLogFile, keyLog);
    EXPECT_FALSE(state.tlsKeys.empty());
    EXPECT_FALSE(state.tlsKeyStatusIsError);
}

TEST_F(UiTls, ChangingTheKeyLogReloadsTheOpenCaptureWithTheNewKeys) {
    if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
    ui::AppState state;
    ui::loadCapture(state, capture);
    ASSERT_EQ(state.packets.size(), 18u);
    EXPECT_EQ(httpPackets(state), 0u) << "no secrets: nothing is decrypted";

    EXPECT_TRUE(ui::setTlsKeyLogFile(state, keyLog));
    EXPECT_TRUE(state.loading()) << "the open capture is loaded again";
    EXPECT_TRUE(state.settingsDirty);
    EXPECT_EQ(state.settings.tlsKeyLogFile, keyLog);
    EXPECT_NE(state.tlsKeyStatus.find("5 secret(s) for 1 connection(s)"), std::string::npos) << state.tlsKeyStatus;
    waitLoaded(state);
    EXPECT_EQ(httpPackets(state), 2u);
    EXPECT_EQ(state.sessions.tlsExternalKeys().entryCount(), 1u) << "the load worked on its own copy of the keys";

    // details of a decrypted packet come from the same session tables
    const auto request = std::find_if(state.packets.begin(), state.packets.end(), [](const auto &p) { return p.info == "GET /index.html HTTP/1.1"; });
    ASSERT_NE(request, state.packets.end());
    state.selectedPacket = static_cast<int>(request - state.packets.begin());
    frame(state);
    ASSERT_TRUE(state.detailOk);
    EXPECT_NE(tlstest::find(state.detail.fields, "Decrypted TLS ("), nullptr);

    // clearing the setting decrypts nothing again
    EXPECT_TRUE(ui::setTlsKeyLogFile(state, ""));
    waitLoaded(state);
    EXPECT_EQ(httpPackets(state), 0u);
    EXPECT_TRUE(state.tlsKeys.empty());
    EXPECT_TRUE(state.sessions.tlsExternalKeys().empty());
}

TEST_F(UiTls, AFileThatCannotBeReadIsReportedAndLeavesNoKeys) {
    ui::AppState state;
    ui::loadCapture(state, capture);
    EXPECT_FALSE(ui::setTlsKeyLogFile(state, "/definitely/not/a/key/log"));
    EXPECT_TRUE(state.tlsKeyStatusIsError);
    EXPECT_NE(state.tlsKeyStatus.find("could not be read"), std::string::npos) << state.tlsKeyStatus;
    EXPECT_TRUE(state.tlsKeys.empty());
    EXPECT_EQ(state.settings.tlsKeyLogFile, "/definitely/not/a/key/log") << "the path stays: the file may appear later (reload)";
    waitLoaded(state);
    EXPECT_EQ(httpPackets(state), 0u);
    frame(state);   // the status line is drawn by the preferences window
    state.preferences.open = true;
    frame(state);
    EXPECT_EQ(state.preferences.tlsKeyLogEdit, "/definitely/not/a/key/log");
}

TEST_F(UiTls, MalformedLinesAreCountedAndNotFatal) {
    if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
    const std::string mixed = "this is not a key log line\nCLIENT_RANDOM zz 12\n" + tlstest::slurp(keyLog) + "# a comment\nCLIENT_RANDOM 00 00\n";
    const std::string path = tempFile("ui_tls_mixed.keys", mixed);
    ui::AppState state;
    ui::loadCapture(state, capture);
    EXPECT_TRUE(ui::setTlsKeyLogFile(state, path));
    EXPECT_FALSE(state.tlsKeyStatusIsError);
    EXPECT_NE(state.tlsKeyStatus.find("malformed line(s) ignored"), std::string::npos) << state.tlsKeyStatus;
    waitLoaded(state);
    EXPECT_EQ(httpPackets(state), 2u) << "the valid lines still decrypt the connection";
}

TEST_F(UiTls, KeysChangedWhileALoadRunsAreNotMixedIntoIt) {
    if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
    ui::AppState state;
    ui::loadCapture(state, capture);
    // a load starts with the keys of the moment; replacing them starts the next one, which cancels the first
    ASSERT_TRUE(ui::setTlsKeyLogFile(state, keyLog));
    ui::startLoad(state, capture);
    EXPECT_TRUE(ui::setTlsKeyLogFile(state, ""));
    waitLoaded(state);
    EXPECT_EQ(httpPackets(state), 0u) << "the last change wins and the capture on screen matches it";
    EXPECT_TRUE(state.sessions.tlsExternalKeys().empty());
    ASSERT_TRUE(ui::setTlsKeyLogFile(state, keyLog));
    waitLoaded(state);
    EXPECT_EQ(httpPackets(state), 2u);
    EXPECT_EQ(state.sessions.tlsExternalKeys().entryCount(), 1u);
}

TEST_F(UiTls, ALiveCaptureGetsTheKeysThatAreKnownAndTheOnesThatComeLater) {
    ui::AppState state;
    ASSERT_TRUE(ui::setTlsKeyLogFile(state, keyLog));
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    ASSERT_NE(state.live.processor, nullptr);
    EXPECT_EQ(state.live.processor->sessions().tlsExternalKeys().entryCount(), 1u);
    EXPECT_TRUE(ui::setTlsKeyLogFile(state, ""));
    EXPECT_FALSE(state.loading()) << "a live capture is not reloaded";
    EXPECT_TRUE(state.live.processor->sessions().tlsExternalKeys().empty());
    ui::discardLiveCapture(state);
}

TEST_F(UiTls, FollowStreamOffersTheDecryptedStream) {
    if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
    ui::AppState state;
    ASSERT_TRUE(ui::setTlsKeyLogFile(state, keyLog));
    ui::loadCapture(state, capture);
    ASSERT_EQ(httpPackets(state), 2u);
    const auto request = std::find_if(state.packets.begin(), state.packets.end(), [](const auto &p) { return p.info == "GET /index.html HTTP/1.1"; });
    ASSERT_NE(request, state.packets.end());
    ASSERT_TRUE(ui::startFollow(state, static_cast<int>(request - state.packets.begin())));
    for (int i = 0; i < 3000 && state.follow.job; ++i) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    ASSERT_TRUE(state.follow.valid);
    EXPECT_EQ(state.follow.mode, ui::FollowStreamMode::Tcp) << "the stream as captured is the default";
    EXPECT_TRUE(state.follow.tlsOk);
    EXPECT_EQ(state.follow.plain.bytesAtoB, std::string("GET /index.html HTTP/1.1\r\nHost: imshark.test\r\n\r\n").size());
    frame(state);
    ASSERT_FALSE(state.follow.lines.empty());
    EXPECT_NE(state.follow.lines[0].text, "GET /index.html HTTP/1.1") << "the raw stream starts with the encrypted ClientHello";

    state.follow.mode = ui::FollowStreamMode::TlsDecrypted;
    state.follow.linesDirty = true;
    frame(state);
    ASSERT_GE(state.follow.lines.size(), 3u);
    EXPECT_EQ(state.follow.lines[0].text, "GET /index.html HTTP/1.1");
    EXPECT_EQ(state.follow.lines[1].text, "Host: imshark.test");
    EXPECT_EQ(ui::followRawBytes(state.follow.plain, ui::FollowDirection::BtoA), "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello");
    state.follow.direction = ui::FollowDirection::BtoA;
    state.follow.view = ui::FollowView::HexDump;
    state.follow.linesDirty = true;
    frame(state);
    EXPECT_FALSE(state.follow.lines.empty());
}

TEST_F(UiTls, FollowStreamSaysWhyTheTlsViewIsEmpty) {
    ui::AppState state;
    ui::loadCapture(state, capture);   // no key log
    ASSERT_TRUE(ui::startFollow(state, 3));
    for (int i = 0; i < 3000 && state.follow.job; ++i) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    ASSERT_TRUE(state.follow.valid);
    EXPECT_FALSE(state.follow.tlsOk);
    EXPECT_NE(state.follow.tls.note.find("no key material"), std::string::npos) << state.follow.tls.note;
    state.follow.mode = ui::FollowStreamMode::TlsDecrypted;
    state.follow.linesDirty = true;
    frame(state);
    EXPECT_TRUE(state.follow.lines.empty());
}

TEST_F(UiTls, PreferencesWindowAndEditMenuDraw) {
    ui::AppState state;
    ui::loadCapture(state, capture);
    state.preferences.open = true;
    for (int i = 0; i < 3; ++i) frame(state);
    EXPECT_EQ(state.preferences.tlsKeyLogEdit, state.settings.tlsKeyLogFile);
    state.preferences.open = false;
    frame(state);
}

TEST_F(UiTls, KeysChangedWhileAnotherFileLoadsRestartThatLoad) {
    if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
    const std::string other = tempFile("ui_tls_other.pcap", tlstest::slurp(capture));
    ui::AppState state;
    ui::loadCapture(state, capture);
    const std::string shown = state.displayName;
    ui::startLoad(state, other);                       // B loads while A is displayed
    ASSERT_TRUE(state.loading());
    EXPECT_TRUE(ui::setTlsKeyLogFile(state, keyLog));
    waitLoaded(state);
    EXPECT_NE(state.displayName, shown) << "B was restarted, A was not reloaded in its place";
    EXPECT_EQ(std::filesystem::path(state.displayName).filename(), std::filesystem::path(other).filename());
    EXPECT_EQ(httpPackets(state), 2u) << "and it ran with the new keys";
}

TEST_F(UiTls, KeysChangedDuringTheFirstLoadReachThatLoad) {
    if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
    ui::AppState state;
    ui::startLoad(state, capture);                     // nothing is displayed yet
    ASSERT_TRUE(state.loading());
    EXPECT_TRUE(state.displayName.empty());
    EXPECT_TRUE(ui::setTlsKeyLogFile(state, keyLog));
    EXPECT_TRUE(state.loading());
    waitLoaded(state);
    EXPECT_EQ(httpPackets(state), 2u) << "the status line and the capture agree";
}

TEST_F(UiTls, LiveCaptureKeepsWhatItDecryptedWhenTheKeysAreCleared) {
    if (!tls::crypto::available()) GTEST_SKIP() << tls::crypto::backendName();
    tlstest::Loaded loaded(kDir + "tls13.pcapng");
    ui::AppState state;
    ASSERT_TRUE(ui::setTlsKeyLogFile(state, keyLog));
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    for (size_t i = 0; i < loaded.packets.size(); ++i) {
        std::vector<char> bytes;
        ASSERT_TRUE(core::readPacketBytes(loaded.path, loaded.packets[i], bytes));
        ASSERT_TRUE(state.live.device->injectPacket(1700000000 + i, static_cast<uint32_t>(i * 1000), bytes));
    }
    frame(state);
    frame(state);
    ASSERT_EQ(state.packets.size(), loaded.packets.size());
    ASSERT_EQ(httpPackets(state), 2u);
    const auto request = std::find_if(state.packets.begin(), state.packets.end(), [](const auto &p) { return p.info == "GET /index.html HTTP/1.1"; });
    ASSERT_NE(request, state.packets.end());
    const int index = static_cast<int>(request - state.packets.begin());

    state.selectedPacket = index;
    frame(state);
    ASSERT_TRUE(state.detailOk);
    const std::string before = tlstest::find(state.detail.fields, "Decrypted TLS (") ? tlstest::find(state.detail.fields, "Decrypted TLS (")->text : "";
    EXPECT_FALSE(before.empty());

    EXPECT_TRUE(ui::setTlsKeyLogFile(state, ""));      // the keys go away while the capture runs
    state.detailIndex = -1;                            // build the details again
    frame(state);
    ASSERT_TRUE(state.detailOk);
    EXPECT_EQ(state.packets[index].info, "GET /index.html HTTP/1.1") << "the list still says what it decoded";
    const auto *layer = tlstest::find(state.detail.fields, "Decrypted TLS (");
    ASSERT_NE(layer, nullptr) << "the details agree with the list";
    EXPECT_EQ(layer->text, before);
    EXPECT_EQ(state.detail.protocol, "HTTP");
    EXPECT_EQ(state.detail.info, state.packets[index].info);
    EXPECT_NE(tlstest::find(state.detail.fields, "Request Method: GET"), nullptr);
    ui::discardLiveCapture(state);
}
