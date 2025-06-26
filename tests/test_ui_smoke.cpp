// Runs the real ImGui drawing code headless (no window, no OpenGL). ImGui's own assertions catch
// unbalanced Begin/End, Push/Pop and similar mistakes; the checks below cover the selection logic.
#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include <filesystem>

#include <imgui.h>

#include <ui/ui.h>

namespace {
    class UiSmoke : public ::testing::Test {
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
        }

        void TearDown() override { ImGui::DestroyContext(ctx); }

        void frame(ui::AppState &state) {
            ImGui::GetIO().DeltaTime = 1.0f / 60.0f;
            ImGui::NewFrame();
            ui::pollLoad(state);
            ui::drawMenuAndDialogs(state);
            ui::drawMainWindow(state);
            ui::drawStatusBar(state);
            ui::drawLoadErrorPopup(state);
            ui::drawLoadProgressPopup(state);
            ImGui::Render();
        }

        void frames(ui::AppState &state, int n = 3) {
            for (int i = 0; i < n; ++i) frame(state);
        }

        ImGuiContext *ctx = nullptr;
    };

    void load(ui::AppState &state) { ui::loadCapture(state, IMSHARK_TEST_DATA_DIR "/sample.pcap"); }
} // namespace

TEST_F(UiSmoke, EmptyState) {
    ui::AppState state;
    frames(state);
}

TEST_F(UiSmoke, LoadFailureShowsPopupWithoutCrashing) {
    ui::AppState state;
    ui::loadCapture(state, "/definitely/not/a/file.pcap");
    EXPECT_TRUE(state.loadFailed);
    EXPECT_TRUE(state.openLoadError);
    frames(state);
    EXPECT_FALSE(state.openLoadError) << "the popup request is consumed";
}

TEST_F(UiSmoke, EveryPacketCanBeSelectedAndDrawn) {
    ui::AppState state;
    load(state);
    ASSERT_EQ(state.packets.size(), 16u);
    frames(state);
    for (int i = 0; i < static_cast<int>(state.packets.size()); ++i) {
        state.selectedPacket = i;
        frames(state, 2);
    }
}

TEST_F(UiSmoke, SelectingAFieldHighlightsItsBytes) {
    ui::AppState state;
    load(state);
    state.selectedPacket = 6; // TCP SYN with options
    frames(state);

    ASSERT_TRUE(state.detailOk);
    EXPECT_EQ(state.detailIndex, 6);
    EXPECT_TRUE(state.packets[6].fields.empty()) << "the list keeps summaries only";
    const auto &packet = state.detail;
    // Find the "Source Port" field of the TCP layer
    const packet::Field *tcp = nullptr;
    for (const auto &l: packet.fields) {
        if (l.text.rfind("Transmission Control Protocol", 0) == 0) tcp = &l;
    }
    ASSERT_NE(tcp, nullptr);
    state.selectedField = &tcp->children[0];
    state.selectionStart = tcp->children[0].offset;
    state.selectionEnd = tcp->children[0].offset + tcp->children[0].length - 1;
    state.revealSelectedField = true;
    frames(state);

    EXPECT_TRUE(state.isSelected(static_cast<int>(tcp->offset)));
    EXPECT_TRUE(state.isSelected(static_cast<int>(tcp->offset) + 1));
    EXPECT_FALSE(state.isSelected(static_cast<int>(tcp->offset) + 2));
    EXPECT_FALSE(state.revealSelectedField) << "reveal request is consumed after one frame";
}

TEST_F(UiSmoke, CloseAndReloadResetsSelection) {
    ui::AppState state;
    load(state);
    state.selectedPacket = 3;
    frames(state);
    load(state);
    EXPECT_EQ(state.selectedPacket, -1);
    EXPECT_EQ(state.selectedField, nullptr);
    EXPECT_FALSE(state.hasSelection());
    frames(state);
}

TEST_F(UiSmoke, BackgroundLoadPublishesWhenFinishedAndKeepsOldCaptureOnFailure) {
    ui::AppState state;
    ui::startLoad(state, IMSHARK_TEST_DATA_DIR "/sample.pcap");
    EXPECT_TRUE(state.loading());
    for (int i = 0; i < 2000 && state.loading(); ++i) {
        frame(state); // pollLoad + progress popup run every frame
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_FALSE(state.loading());
    EXPECT_EQ(state.packets.size(), 16u);
    EXPECT_FALSE(state.loadFailed);

    state.selectedPacket = 2;
    ui::loadCapture(state, "/no/such/file.pcap"); // fails, the open capture must stay
    EXPECT_TRUE(state.loadFailed);
    EXPECT_EQ(state.packets.size(), 16u);
    EXPECT_EQ(state.selectedPacket, 2);
    EXPECT_EQ(state.currentFile, IMSHARK_TEST_DATA_DIR "/sample.pcap");
}

TEST_F(UiSmoke, CancelledLoadIsNotAnError) {
    ui::AppState state;
    ui::startLoad(state, IMSHARK_TEST_DATA_DIR "/sample.pcap");
    ui::cancelLoad(state);
    while (state.loading()) {
        ui::pollLoad(state);
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    // Depending on timing the tiny sample file may finish before the cancel is noticed; both are fine,
    // but a cancel must never raise the error popup.
    if (state.loadFailed) {
        EXPECT_EQ(state.loadMessage, "Cancelled");
        EXPECT_FALSE(state.openLoadError);
    }
}

TEST_F(UiSmoke, SortingOrdersPacketsStably) {
    ui::AppState state;
    load(state);
    std::vector<uint32_t> order;

    ui::sortPacketOrder(order, state.packets, ui::SortColumn::Length, true);
    ASSERT_EQ(order.size(), state.packets.size());
    for (size_t i = 1; i < order.size(); ++i) {
        const auto &a = state.packets[order[i - 1]], &b = state.packets[order[i]];
        ASSERT_LE(a.length, b.length);
        if (a.length == b.length) ASSERT_LT(order[i - 1], order[i]) << "ties keep capture order";
    }
    ui::sortPacketOrder(order, state.packets, ui::SortColumn::Protocol, false);
    EXPECT_EQ(state.packets[order.front()].protocol, "UDP");   // largest protocol name first
    EXPECT_EQ(state.packets[order.back()].protocol, "ARP");
    ui::sortPacketOrder(order, state.packets, ui::SortColumn::Number, false);
    EXPECT_EQ(order.front(), state.packets.size() - 1);
}

TEST_F(UiSmoke, KeyboardNavigationMovesTheSelection) {
    ui::AppState state;
    load(state);
    frames(state);                        // builds the displayed order
    auto press = [&](ImGuiKey key) {
        ImGui::GetIO().AddKeyEvent(key, true);
        frame(state);
        ImGui::GetIO().AddKeyEvent(key, false);
        frame(state);
    };
    EXPECT_EQ(state.selectedPacket, -1);
    press(ImGuiKey_DownArrow);
    EXPECT_EQ(state.selectedPacket, 0);
    press(ImGuiKey_DownArrow);
    EXPECT_EQ(state.selectedPacket, 1);
    press(ImGuiKey_UpArrow);
    EXPECT_EQ(state.selectedPacket, 0);
    press(ImGuiKey_End);
    EXPECT_EQ(state.selectedPacket, 15);
    press(ImGuiKey_DownArrow);            // clamps at the last packet
    EXPECT_EQ(state.selectedPacket, 15);
    press(ImGuiKey_Home);
    EXPECT_EQ(state.selectedPacket, 0);
    press(ImGuiKey_PageDown);
    EXPECT_EQ(state.selectedPacket, 15);
}

TEST_F(UiSmoke, SuccessfulLoadsAreRememberedAndPersisted) {
    const auto path = (std::filesystem::temp_directory_path() / "imshark_smoke_settings/settings.ini").string();
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
    {
        ui::AppState state;
        ui::initSettings(state, path);
        load(state);
        EXPECT_TRUE(state.settingsDirty);
        state.listHeight = 333.0f;
        frames(state);
        ui::saveSettingsIfDirty(state);
        EXPECT_FALSE(state.settingsDirty);
    }
    ui::AppState again;
    ui::initSettings(again, path);
    ASSERT_EQ(again.settings.recentFiles.size(), 1u);
    EXPECT_EQ(again.settings.recentFiles[0], IMSHARK_TEST_DATA_DIR "/sample.pcap");
    EXPECT_FLOAT_EQ(again.listHeight, 333.0f);
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}

TEST_F(UiSmoke, ThemesCanBeSwitched) {
    ui::applyTheme(false);
    ui::AppState state;
    frames(state);
    ui::applyTheme(true);
    frames(state);
}

// ---- display filter integration ---------------------------------------------------------------------

TEST_F(UiSmoke, AppliedFilterRestrictsTheDisplayedPackets) {
    ui::AppState state;
    load(state);
    frames(state);
    EXPECT_EQ(state.displayedCount(), 16u);

    ASSERT_TRUE(ui::applyFilter(state, "tcp"));
    EXPECT_TRUE(state.filter.active);
    EXPECT_EQ(state.displayedCount(), 7u);
    frames(state);
    EXPECT_EQ(state.order, (std::vector<uint32_t>{6, 7, 8, 9, 10, 11, 15}));

    ASSERT_TRUE(ui::applyFilter(state, "tcp.flags.syn && !tcp.flags.ack"));
    frames(state);
    EXPECT_EQ(state.order, (std::vector<uint32_t>{6}));

    ASSERT_TRUE(ui::applyFilter(state, "frame.number > 100"));
    frames(state);
    EXPECT_TRUE(state.order.empty()) << "no match: an empty list, not the full one";
    EXPECT_EQ(state.displayedCount(), 0u);

    ASSERT_TRUE(ui::applyFilter(state, ""));
    EXPECT_FALSE(state.filter.active);
    frames(state);
    EXPECT_EQ(state.order.size(), 16u);
}

TEST_F(UiSmoke, InvalidFilterKeepsThePreviousOneAndReportsTheError) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(ui::applyFilter(state, "udp"));
    EXPECT_FALSE(ui::applyFilter(state, "udp &&"));
    EXPECT_FALSE(state.filter.previewOk);
    EXPECT_NE(state.filter.previewError.message.find("ends unexpectedly"), std::string::npos);
    EXPECT_EQ(state.filter.appliedText, "udp");
    EXPECT_EQ(state.displayedCount(), 4u);
    frames(state);                      // the red bar and the message are drawn without problems

    state.filter.text = "tcp.port ==";
    frames(state);                      // live validation of what is being typed
    EXPECT_FALSE(state.filter.previewOk);
    state.filter.text = "tcp";
    frames(state);
    EXPECT_TRUE(state.filter.previewOk);
}

TEST_F(UiSmoke, FilterSurvivesReloadAndDropsHiddenSelection) {
    ui::AppState state;
    load(state);
    state.selectedPacket = 0;                        // ARP
    frames(state);
    ASSERT_TRUE(ui::applyFilter(state, "tcp"));
    EXPECT_EQ(state.selectedPacket, -1) << "the selected packet is no longer displayed";

    state.selectedPacket = 6;                        // a TCP packet stays selected
    ASSERT_TRUE(ui::applyFilter(state, "tcp.port == 80"));
    EXPECT_EQ(state.selectedPacket, 6);

    load(state);                                     // open the capture again
    EXPECT_TRUE(state.filter.active) << "a display filter stays active on a new capture";
    EXPECT_EQ(state.displayedCount(), 5u);
    frames(state);
}

TEST_F(UiSmoke, FilterHistoryIsRememberedAndHelpIsDrawn) {
    ui::AppState state;
    load(state);
    ui::applyFilter(state, "tcp");
    ui::applyFilter(state, "udp");
    ui::applyFilter(state, "tcp");
    EXPECT_EQ(state.settings.filterHistory, (std::vector<std::string>{"tcp", "udp"}));
    state.filter.showHelp = true;
    frames(state);
    state.filter.helpSearch = "flags";
    frames(state);
    state.filter.showHelp = false;
}

TEST_F(UiSmoke, FilterAndSortingCombine) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(ui::applyFilter(state, "tcp"));
    frames(state);
    ui::sortOrder(state.order, state.packets, ui::SortColumn::Length, false);
    ASSERT_EQ(state.order.size(), 7u);
    for (size_t i = 1; i < state.order.size(); ++i) {
        EXPECT_GE(state.packets[state.order[i - 1]].length, state.packets[state.order[i]].length);
    }
}

TEST_F(UiSmoke, ColoringRulesDrawAndCanBeEdited) {
    ui::AppState state;
    ui::initSettings(state, "");      // defaults, nothing persisted
    load(state);
    EXPECT_TRUE(state.settings.colorize);
    frames(state);                    // rows are drawn with their colors

    state.showColorRules = true;
    frames(state);                    // the editor window
    ASSERT_EQ(state.colorRuleEdit, ui::defaultColorRules());

    state.settings.colorRules = {{true, "only", "arp", 0x00FF00, 0x000000}, {true, "bad", "arp &&", 0, 0}};
    ui::recompileColorRules(state);
    EXPECT_EQ(state.colors.problems().size(), 1u);
    frames(state);

    state.settings.colorize = false;  // "Colorize Packet List" off
    frames(state);
    state.showColorRules = false;
    frames(state);
}

TEST_F(UiSmoke, FindSelectsMatchesAndWraps) {
    ui::AppState state;
    load(state);
    frames(state);
    state.find.text = "example.com";
    EXPECT_TRUE(ui::findAndSelect(state, true));
    EXPECT_EQ(state.selectedPacket, 4);
    EXPECT_TRUE(ui::findAndSelect(state, true));
    EXPECT_EQ(state.selectedPacket, 5);
    EXPECT_TRUE(ui::findAndSelect(state, true));
    EXPECT_EQ(state.selectedPacket, 4) << "wrapped";
    EXPECT_TRUE(ui::findAndSelect(state, false));
    EXPECT_EQ(state.selectedPacket, 5);
    EXPECT_FALSE(state.find.messageIsError);

    state.find.text = "zzz-not-there";
    EXPECT_FALSE(ui::findAndSelect(state, true));
    EXPECT_EQ(state.selectedPacket, 5) << "the selection stays when nothing matches";
    EXPECT_EQ(state.find.message, "No match");
    EXPECT_TRUE(state.find.messageIsError);

    state.find.mode = ui::FindMode::Filter;
    state.find.text = "tcp.flags.fin";
    EXPECT_TRUE(ui::findAndSelect(state, true));
    EXPECT_EQ(state.selectedPacket, 10);
    state.find.text = "tcp &&";
    EXPECT_FALSE(ui::findAndSelect(state, true));
    EXPECT_TRUE(state.find.messageIsError);
}

TEST_F(UiSmoke, FindOnlySearchesDisplayedPackets) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(ui::applyFilter(state, "udp"));       // packets 4, 5, 12, 13
    state.find.text = "SMTP";                          // packet 11 is hidden by the filter
    EXPECT_FALSE(ui::findAndSelect(state, true));
    state.find.text = "example";
    EXPECT_TRUE(ui::findAndSelect(state, true));
    EXPECT_EQ(state.selectedPacket, 4);
}

TEST_F(UiSmoke, FindBarIsDrawnAndKeysWork) {
    ui::AppState state;
    load(state);
    frames(state);
    state.find.open = true;
    state.find.focusRequested = true;
    state.find.text = "example";
    frames(state);                                    // bar with the text field, combo and buttons
    state.find.message = "No match";
    state.find.messageIsError = true;
    frames(state);
    // F3 repeats the search even with the bar closed
    state.find.open = false;
    ImGui::GetIO().AddKeyEvent(ImGuiKey_F3, true);
    frame(state);
    ImGui::GetIO().AddKeyEvent(ImGuiKey_F3, false);
    frame(state);
    EXPECT_EQ(state.selectedPacket, 4);
}

TEST_F(UiSmoke, EveryTimeFormatIsDrawn) {
    ui::AppState state;
    load(state);
    for (auto f: {ui::TimeFormat::SincePrevious, ui::TimeFormat::UtcDateTime, ui::TimeFormat::EpochSeconds, ui::TimeFormat::SinceCaptureStart}) {
        state.settings.timeFormat = f;
        frames(state, 2);
    }
    EXPECT_GT(state.captureStartEpoch, 1.6e9) << "the readers report the capture start";
}

// ---- statistics windows -------------------------------------------------------------------------------

TEST_F(UiSmoke, StatisticsWindowsDrawAndFollowTheFilter) {
    ui::AppState state;
    load(state);
    state.stats.showHierarchy = state.stats.showConversations = state.stats.showEndpoints = true;
    frames(state);
    ASSERT_TRUE(state.stats.hierarchyValid);
    EXPECT_EQ(state.stats.hierarchy.packets, 16u);

    EXPECT_TRUE(state.stats.conversationsValid[0]);
    EXPECT_FALSE(state.stats.conversationsValid[2]) << "only the visible tab is computed";
    for (int tab = 0; tab < 4; ++tab) {     // every tab's data can be computed and drawn
        state.stats.selectTab = tab;
        frames(state);
        EXPECT_EQ(state.stats.tab, tab);
        EXPECT_TRUE(state.stats.conversationsValid[tab]);
        EXPECT_TRUE(state.stats.endpointsValid[tab]);
    }

    ASSERT_TRUE(ui::applyFilter(state, "tcp"));
    EXPECT_TRUE(state.stats.dirty);
    frames(state);
    EXPECT_EQ(state.stats.hierarchy.packets, 7u) << "limited to the displayed packets";

    state.stats.limitToDisplayed = false;   // the checkbox
    state.stats.dirty = true;
    frames(state);
    EXPECT_EQ(state.stats.hierarchy.packets, 16u);

    state.stats.showHierarchy = state.stats.showConversations = state.stats.showEndpoints = false;
    frames(state);
}

TEST_F(UiSmoke, StatisticsOnAnEmptyCaptureDrawNothingBroken) {
    ui::AppState state;
    state.stats.showHierarchy = state.stats.showConversations = state.stats.showEndpoints = true;
    frames(state);
    EXPECT_EQ(state.stats.hierarchy.packets, 0u);
}

TEST_F(UiSmoke, ExpertInformationWindow) {
    ui::AppState state;
    load(state);
    state.stats.showExpert = true;
    frames(state);
    ASSERT_TRUE(state.stats.expertValid);
    EXPECT_FALSE(state.stats.expert.empty());
    ASSERT_TRUE(ui::applyFilter(state, "udp"));
    frames(state);
    EXPECT_TRUE(state.stats.expert.empty()) << "limited to the displayed (UDP) packets nothing is noteworthy";
    state.stats.showExpert = false;
    frames(state);
}
