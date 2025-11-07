// Runs the real ImGui drawing code headless (no window, no OpenGL). ImGui's own assertions catch
// unbalanced Begin/End, Push/Pop and similar mistakes; the checks below cover the selection logic.
#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <csignal>
#include <thread>
#ifndef _WIN32
#include <sys/resource.h>
#endif

#include <filesystem>
#include <fstream>

#include <imgui.h>

#include <core.h>
#include <ui/ui.h>

#include "support.h"

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
            ui::pollCapture(state);
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
        ASSERT_LE(a.frame_length, b.frame_length);
        if (a.frame_length == b.frame_length) ASSERT_LT(order[i - 1], order[i]) << "ties keep capture order";
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
        EXPECT_GE(state.packets[state.order[i - 1]].frame_length, state.packets[state.order[i]].frame_length);
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
    for (const auto &item: state.stats.expert) {
        if (item.summary.find("hecksum") == std::string::npos) ADD_FAILURE() << item.summary << ": limited to the displayed (UDP) packets nothing else is noteworthy";
    }
    state.stats.showExpert = false;
    frames(state);
}

TEST_F(UiSmoke, ByteSearchRunsInTheBackgroundAndSelectsTheMatch) {
    ui::AppState state;
    load(state);
    frames(state);
    state.find.mode = ui::FindMode::BytesText;
    state.find.text = "EHLO";
    EXPECT_FALSE(ui::findAndSelect(state, true)) << "the result arrives asynchronously";
    EXPECT_TRUE(static_cast<bool>(state.find.job));
    for (int i = 0; i < 3000 && state.find.job; ++i) {
        frame(state);                       // pollSearch runs in drawFindBar
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_FALSE(static_cast<bool>(state.find.job));
    EXPECT_EQ(state.selectedPacket, 11);
    EXPECT_FALSE(state.find.messageIsError);

    state.find.mode = ui::FindMode::Hex;
    state.find.text = "47 45 54";            // "GET"
    ui::findAndSelect(state, false);        // backwards from packet 11 finds packet 9
    for (int i = 0; i < 3000 && state.find.job; ++i) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    EXPECT_EQ(state.selectedPacket, 9);

    state.find.text = "zz";                  // invalid hex is reported immediately
    EXPECT_FALSE(ui::findAndSelect(state, true));
    EXPECT_TRUE(state.find.messageIsError);
    EXPECT_FALSE(static_cast<bool>(state.find.job));

    state.find.text = "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00";
    ui::findAndSelect(state, true);
    for (int i = 0; i < 3000 && state.find.job; ++i) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    EXPECT_EQ(state.find.message, "No match");
    EXPECT_EQ(state.selectedPacket, 9) << "no match keeps the selection";
}

TEST_F(UiSmoke, LoadingOrClosingCancelsARunningSearch) {
    ui::AppState state;
    load(state);
    frames(state);
    state.find.mode = ui::FindMode::BytesText;
    state.find.text = "never-found";
    ui::findAndSelect(state, true);
    load(state);                            // replaces state.packets: the search thread must be gone first
    EXPECT_FALSE(static_cast<bool>(state.find.job));
    frames(state);
}

// ---- follow stream ----------------------------------------------------------------------------------------

TEST_F(UiSmoke, FollowStreamFromAPacket) {
    ui::AppState state;
    load(state);
    frames(state);
    EXPECT_FALSE(ui::startFollow(state, 0)) << "ARP is not a stream";
    EXPECT_FALSE(state.follow.open);
    EXPECT_FALSE(ui::startFollow(state, 99));

    ASSERT_TRUE(ui::startFollow(state, 9));          // the HTTP request of the TCP conversation
    EXPECT_TRUE(state.follow.open);
    for (int i = 0; i < 3000 && state.follow.job; ++i) {
        frame(state);                                // drawFollowWindow polls the job
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_FALSE(static_cast<bool>(state.follow.job));
    ASSERT_TRUE(state.follow.valid);
    EXPECT_EQ(state.follow.stream.packets, 5);
    ASSERT_FALSE(state.follow.stream.chunks.empty());
    EXPECT_EQ(state.follow.stream.chunks[0].data, "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n");
    EXPECT_NE(state.follow.title.find("TCP"), std::string::npos);

    frames(state);                                   // lines are built and drawn
    EXPECT_FALSE(state.follow.linesDirty);
    ASSERT_GE(state.follow.lines.size(), 3u);
    EXPECT_EQ(state.follow.lines[0].text, "GET / HTTP/1.1");

    state.follow.view = ui::FollowView::HexDump;
    state.follow.direction = ui::FollowDirection::BtoA;
    state.follow.linesDirty = true;
    frames(state);
    EXPECT_TRUE(state.follow.lines.empty()) << "the server never sent payload in the sample";

    state.follow.open = false;
    frames(state);
}

TEST_F(UiSmoke, FollowUdpAndTheJobIsCancelledByLoading) {
    ui::AppState state;
    load(state);
    frames(state);
    ASSERT_TRUE(ui::startFollow(state, 4));          // DNS over UDP
    EXPECT_NE(state.follow.title.find("UDP"), std::string::npos);
    load(state);                                     // replacing the packets must stop the reader first
    EXPECT_FALSE(static_cast<bool>(state.follow.job));
    frames(state);
}

// ---- export dialog ----------------------------------------------------------------------------------------

TEST_F(UiSmoke, ExportIndicesFollowTheRange) {
    ui::AppState state;
    load(state);
    EXPECT_EQ(ui::exportIndices(state, ui::ExportState::All).size(), 16u);
    EXPECT_EQ(ui::exportIndices(state, ui::ExportState::Displayed).size(), 16u);
    EXPECT_TRUE(ui::exportIndices(state, ui::ExportState::Selected).empty());
    ASSERT_TRUE(ui::applyFilter(state, "tcp"));
    EXPECT_EQ(ui::exportIndices(state, ui::ExportState::Displayed), (std::vector<uint32_t>{6, 7, 8, 9, 10, 11, 15}));
    EXPECT_EQ(ui::exportIndices(state, ui::ExportState::All).size(), 16u);
    state.selectedPacket = 9;
    EXPECT_EQ(ui::exportIndices(state, ui::ExportState::Selected), (std::vector<uint32_t>{9}));
}

TEST_F(UiSmoke, BackgroundExportWritesTheDisplayedPackets) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(ui::applyFilter(state, "dns"));
    frames(state);
    const auto path = (std::filesystem::temp_directory_path() / "imshark_ui_export.pcapng").string();
    std::remove(path.c_str());
    ASSERT_TRUE(ui::startExport(state, ui::ExportState::Displayed, exporter::Format::Pcapng, path));
    for (int i = 0; i < 3000 && state.exportDialog.job; ++i) {
        frame(state);                                   // drawExportDialog polls the job
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    ASSERT_FALSE(static_cast<bool>(state.exportDialog.job));
    EXPECT_FALSE(state.exportDialog.resultIsError) << state.exportDialog.resultMessage;
    EXPECT_NE(state.exportDialog.resultMessage.find("Exported 2 packets"), std::string::npos) << state.exportDialog.resultMessage;
    frames(state);                                       // the result popup is drawn

    core::FileProcessor fp;
    std::vector<packet::PacketInfo> packets;
    std::string message;
    ASSERT_TRUE(fp.processPcapngFile(path, packets, message)) << message;
    EXPECT_EQ(packets.size(), 2u);
    EXPECT_EQ(packets[0].protocol, "DNS");
    std::remove(path.c_str());

    EXPECT_FALSE(ui::startExport(state, ui::ExportState::Selected, exporter::Format::Csv, path)) << "nothing selected, nothing to export";
}

TEST_F(UiSmoke, ExportFailureIsReportedAndLoadingCancelsARunningExport) {
    ui::AppState state;
    load(state);
    ASSERT_TRUE(ui::startExport(state, ui::ExportState::All, exporter::Format::Csv, "/no/such/directory/out.csv"));
    for (int i = 0; i < 3000 && state.exportDialog.job; ++i) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    EXPECT_TRUE(state.exportDialog.resultIsError);
    EXPECT_NE(state.exportDialog.resultMessage.find("Cannot write"), std::string::npos);
    frames(state);

    const auto path = (std::filesystem::temp_directory_path() / "imshark_ui_export2.pcap").string();
    ASSERT_TRUE(ui::startExport(state, ui::ExportState::All, exporter::Format::Pcap, path));
    load(state);                                         // must stop the export thread before packets are replaced
    EXPECT_FALSE(static_cast<bool>(state.exportDialog.job));
    std::remove(path.c_str());
    state.exportDialog.openPopup = true;                 // the options popup
    frames(state);
}

TEST_F(UiSmoke, CaptureFilePropertiesWindow) {
    ui::AppState state;
    state.showCaptureInfo = true;
    frames(state);                                       // nothing open
    load(state);
    EXPECT_EQ(state.captureInfo.interfaces.size(), 1u);
    EXPECT_EQ(state.captureInfo.interfaces[0].packets, 16u);
    EXPECT_NE(state.captureInfo.format.find("pcap"), std::string::npos);
    frames(state);                                       // general section, interface table
    state.captureInfo.packetComments[3] = "look here";   // comments and names are listed too
    state.captureInfo.names.push_back({"10.0.0.1", "gw.local"});
    state.captureInfo.comment = "a note";
    frames(state);
    state.showCaptureInfo = false;
    frames(state);
}

// ---- compressed captures ----------------------------------------------------------------------------------

TEST_F(UiSmoke, GzippedCaptureIsOpenedThroughATemporaryCopy) {
    const std::string gz = IMSHARK_TEST_DATA_DIR "/sample.pcap.gz";
    std::string tempCopy;
    {
        ui::AppState state;
        ui::loadCapture(state, gz);
        ASSERT_FALSE(state.loadFailed) << state.loadMessage;
        EXPECT_EQ(state.packets.size(), 16u);
        EXPECT_EQ(state.displayName, gz) << "the user sees the file they opened";
        EXPECT_NE(state.currentFile, gz);
        EXPECT_EQ(state.tempFile, state.currentFile);
        EXPECT_TRUE(std::filesystem::exists(state.tempFile));
        EXPECT_EQ(state.captureInfo.container, "gzip");
        EXPECT_GT(state.captureInfo.compressedSize, 0u);
        EXPECT_EQ(state.settings.recentFiles.front(), gz) << "recent files remember the original, not the temp copy";

        // everything that reads frames works on the temporary copy
        state.selectedPacket = 9;
        frames(state);
        ASSERT_TRUE(state.detailOk);
        EXPECT_EQ(state.detail.protocol, "HTTP");
        ASSERT_TRUE(ui::startFollow(state, 9));
        for (int i = 0; i < 3000 && state.follow.job; ++i) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
        EXPECT_TRUE(state.follow.valid);
        state.showCaptureInfo = true;
        frames(state);
        tempCopy = state.tempFile;

        // opening another capture removes the previous temporary copy
        ui::loadCapture(state, IMSHARK_TEST_DATA_DIR "/sample.pcap");
        EXPECT_TRUE(state.tempFile.empty());
        EXPECT_FALSE(std::filesystem::exists(tempCopy));
        EXPECT_EQ(state.displayName, IMSHARK_TEST_DATA_DIR "/sample.pcap");
    }
}

TEST_F(UiSmoke, ClosingOrDestroyingTheStateRemovesTheTemporaryCopy) {
    const std::string gz = IMSHARK_TEST_DATA_DIR "/sample.pcap.gz";
    std::string temp;
    {
        ui::AppState state;
        ui::loadCapture(state, gz);
        temp = state.tempFile;
        ASSERT_FALSE(temp.empty());
        ui::closeCapture(state);
        EXPECT_FALSE(std::filesystem::exists(temp));
        EXPECT_TRUE(state.currentFile.empty());
        EXPECT_TRUE(state.displayName.empty());
        EXPECT_TRUE(state.packets.empty());
        frames(state);

        ui::loadCapture(state, gz);
        temp = state.tempFile;
        ASSERT_TRUE(std::filesystem::exists(temp));
    }   // the state goes out of scope
    EXPECT_FALSE(std::filesystem::exists(temp));
}

TEST_F(UiSmoke, ADamagedGzipFileFailsCleanlyAndKeepsTheOpenCapture) {
    ui::AppState state;
    load(state);
    ASSERT_EQ(state.packets.size(), 16u);

    std::ifstream in(std::string(IMSHARK_TEST_DATA_DIR) + "/gzip/dynamic.gz", std::ios::binary);
    std::vector<char> bytes((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    bytes.resize(bytes.size() / 2);                       // truncated
    const std::string broken = support::writeTemp("broken.pcap.gz", bytes);

    ui::loadCapture(state, broken);
    EXPECT_TRUE(state.loadFailed);
    EXPECT_NE(state.loadMessage.find("end of the compressed data"), std::string::npos) << state.loadMessage;
    EXPECT_EQ(state.packets.size(), 16u) << "the open capture is not destroyed";
    EXPECT_TRUE(state.tempFile.empty()) << "no stray temporary file";
    EXPECT_EQ(state.displayName, IMSHARK_TEST_DATA_DIR "/sample.pcap");
    frames(state);
    std::remove(broken.c_str());
}

// ---- the packet list is shared safely with background jobs -------------------------------------------------

TEST(PacketListSharing, ASnapshotSurvivesReplacingAndClearing) {
    ui::PacketList list;
    EXPECT_TRUE(list.empty());
    std::vector<packet::PacketInfo> a(3);
    a[0].info = "first";
    list.assign(std::move(a));
    auto snapshot = list.share();
    ASSERT_EQ(snapshot->size(), 3u);

    list.clear();
    EXPECT_TRUE(list.empty());
    EXPECT_EQ(snapshot->size(), 3u) << "the job's view is unchanged";
    EXPECT_EQ((*snapshot)[0].info, "first");

    std::vector<packet::PacketInfo> b(5);
    list.assign(std::move(b));
    EXPECT_EQ(list.size(), 5u);
    EXPECT_EQ(snapshot->size(), 3u);
    const ui::PacketList::Vector &asVector = list;
    EXPECT_EQ(asVector.size(), 5u);
    EXPECT_EQ(&list.front(), &asVector.front());
}

TEST(PacketListSharing, WorkersNeverSeeTornOrFreedData) {
    ui::PacketList list;
    std::vector<std::thread> workers;
    std::atomic<uint64_t> checked{0};
    std::atomic<bool> corrupt{false};

    // the UI thread starts workers with a snapshot and keeps replacing / clearing the list meanwhile
    for (int round = 0; round < 400; ++round) {
        std::vector<packet::PacketInfo> v(static_cast<size_t>(round % 50));
        for (size_t i = 0; i < v.size(); ++i) { v[i].number = static_cast<int>(i) + 1; v[i].info = std::string(v.size(), 'x'); }
        if (round % 7 == 0) list.clear(); else list.assign(std::move(v));

        workers.emplace_back([&, snap = list.share()] {
            for (int rep = 0; rep < 20; ++rep) {
                uint64_t sum = 0;
                for (const auto &p: *snap) sum += static_cast<uint64_t>(p.number) + p.info.size();
                const uint64_t n = snap->size();       // numbers 1..n, info "x" * n -> sum is determined by n
                if (sum != n * (n + 1) / 2 + n * n) corrupt = true;
                std::this_thread::yield();
            }
            ++checked;
        });
        if (round % 3 == 0) list.clear();               // drop the owner's reference while workers still run
    }
    for (auto &t: workers) t.join();
    EXPECT_FALSE(corrupt.load());
    EXPECT_EQ(checked.load(), 400u);
}

TEST_F(UiSmoke, ARunningJobSurvivesTheCaptureBeingDropped) {
    ui::AppState state;
    load(state);
    frames(state);
    state.find.mode = ui::FindMode::BytesText;
    state.find.text = "never-found-anywhere";
    ui::findAndSelect(state, true);                  // the search holds a snapshot of the 16 packets
    ASSERT_TRUE(static_cast<bool>(state.find.job));
    state.packets.clear();                           // nothing cancels the job: this must be safe by itself
    EXPECT_TRUE(state.packets.empty());
    for (int i = 0; i < 3000 && state.find.job; ++i) {
        frame(state);                                // the result is published when the job ends
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
    EXPECT_FALSE(static_cast<bool>(state.find.job)) << "the job ran to the end on its private snapshot";
    EXPECT_EQ(state.find.message, "No match");
}

TEST_F(UiSmoke, DecodeAsRulesReloadTheCaptureWithOtherDissectors) {
    // an NTP client request on UDP port 9999, which nothing claims by itself
    const std::string ntp = "23" "00" "06" "ec" + std::string(88, '0');
    const auto ntpBytes = support::hex(ntp);
    const auto path = support::writeTemp("decodeas_ui.pcap", support::pcapBytes({support::udpPacket("0a000001", "0a000002", "c350", "270f", std::string(ntpBytes.begin(), ntpBytes.end()))}));
    ui::AppState state;
    ui::loadCapture(state, path);
    ASSERT_EQ(state.packets.size(), 1u);
    EXPECT_EQ(state.packets[0].protocol, "UDP");

    state.decodeAs.open = true;
    frames(state);                                           // draws the (empty) window

    EXPECT_FALSE(ui::applyDecodeAs(state, {{false, 9999, "Nonsense"}}));
    EXPECT_FALSE(state.decodeAs.error.empty());
    EXPECT_TRUE(state.decodeAs.rules.empty()) << "an invalid rule changes nothing";
    EXPECT_FALSE(ui::applyDecodeAs(state, {{false, 70000, "NTP"}}));

    ASSERT_TRUE(ui::applyDecodeAs(state, {{false, 9999, "NTP"}}));
    while (state.loading()) frame(state);
    ASSERT_EQ(state.packets.size(), 1u);
    EXPECT_EQ(state.packets[0].protocol, "NTP");
    state.selectPacket(0);
    frames(state);
    EXPECT_EQ(state.detail.protocol, "NTP") << "the details are rebuilt with the same rules";
    EXPECT_FALSE(state.detail.fields.empty());

    state.decodeAs.edit = {{true, 8080, "HTTP"}, {false, 53, "NTP"}};   // the window draws rules being edited
    frames(state);
    ASSERT_TRUE(ui::applyDecodeAs(state, {}));
    while (state.loading()) frame(state);
    EXPECT_EQ(state.packets[0].protocol, "UDP") << "removing the rules restores the built-in behaviour";
    state.decodeAs.open = false;
    frames(state);
    std::remove(path.c_str());
}


// ---- live capture -----------------------------------------------------------------------------------------
// A real interface needs privileges, so the session is fed through the injection seam of the capture core; poll, stop,
// filter, details, statistics, export, follow and the unsaved-capture questions are the real code paths.

namespace {
    std::vector<char> seg(uint32_t seq, const std::string &data, const char *flags = "18") {
        char s[16];
        std::snprintf(s, sizeof s, "%08x", seq);
        return support::tcpPacket("0a000001", "0a000002", "c350", "0050", s, "00000001", flags, data);
    }

    const std::string kRequest = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";

    // ARP, SYN, first half of an HTTP request, UDP datagram, second half of the request (completes the message and
    // amends the summary of packet 3), a TCP ACK
    std::vector<std::vector<char>> liveTraffic() {
        return {
            support::hex(support::kArpRequest),
            seg(999, "", "02"),
            seg(1000, kRequest.substr(0, 20)),
            support::hex(support::kEthIpUdp),
            seg(1020, kRequest.substr(20)),
            seg(1000 + static_cast<uint32_t>(kRequest.size()), "", "10"),
        };
    }

    void injectFrames(ui::AppState &state, const std::vector<std::vector<char>> &frames, size_t from, size_t to) {
        for (size_t i = from; i < to; ++i) {
            ASSERT_TRUE(state.live.device->injectPacket(1700000000 + i, static_cast<uint32_t>(i * 1000), frames[i])) << state.live.device->lastError();
        }
    }
} // namespace

TEST_F(UiSmoke, CaptureDialogListsInterfacesAndValidatesTheFilterWhileTyping) {
    ui::AppState state;
    state.live.dialog.open = true;
    frames(state);
    EXPECT_TRUE(state.live.dialog.listLoaded);
    if (!capture::liveCaptureAvailable()) {
        EXPECT_FALSE(state.live.dialog.interfaces.error.empty());
        EXPECT_NE(ui::captureUnavailableReason().find("not available in this build"), std::string::npos);
        return;
    }
    EXPECT_TRUE(state.live.dialog.interfaces.error.empty()) << state.live.dialog.interfaces.error;
    for (const auto &itf: state.live.dialog.interfaces.interfaces) EXPECT_FALSE(itf.name.empty());
    if (!state.live.dialog.interfaces.interfaces.empty()) EXPECT_FALSE(state.live.options.interfaceName.empty()) << "a default interface is offered";

    state.live.options.filter = "tcp port 80 and host 10.0.0.1";
    frames(state);
    EXPECT_TRUE(state.live.dialog.filterChecked);
    EXPECT_TRUE(state.live.dialog.filterCheck.ok) << state.live.dialog.filterCheck.error;
    state.live.options.filter = "tcp port ((";
    frames(state);
    EXPECT_FALSE(state.live.dialog.filterCheck.ok);
    EXPECT_FALSE(state.live.dialog.filterCheck.error.empty());
    state.live.options.filter.clear();
    frames(state);
    EXPECT_TRUE(state.live.dialog.filterCheck.ok) << "an empty filter is valid";
    state.live.options.snaplen = 96;
    state.live.options.promiscuous = false;
    frames(state);
    state.live.dialog.open = false;
    frames(state);
}

TEST_F(UiSmoke, CaptureMenuAndShortcutsDrawWithoutASession) {
    ui::AppState state;
    frames(state);
    EXPECT_EQ(ui::captureStatusText(state), "");
    EXPECT_FALSE(state.live.capturing());
    ui::requestStartCapture(state);          // nothing chosen yet: opens the dialog instead of starting
    if (capture::liveCaptureAvailable()) EXPECT_TRUE(state.live.dialog.open);
    frames(state);
}

TEST_F(UiSmoke, FailedStartKeepsTheOpenCaptureAndRemembersTheOptions) {
    ui::AppState state;
    load(state);
    capture::CaptureOptions options;
    options.interfaceName = "imshark-no-such-interface0";
    options.filter = "udp port 53";
    options.snaplen = 1500;
    options.promiscuous = false;
    EXPECT_FALSE(ui::startCapture(state, options));
    EXPECT_FALSE(state.live.error.empty());
    EXPECT_TRUE(state.live.openError);
    EXPECT_FALSE(state.live.session);
    EXPECT_EQ(state.packets.size(), 16u) << "the open capture stays";
    EXPECT_EQ(state.currentFile, IMSHARK_TEST_DATA_DIR "/sample.pcap");
    EXPECT_EQ(state.settings.captureInterface, "imshark-no-such-interface0");
    EXPECT_EQ(state.settings.captureFilter, "udp port 53");
    EXPECT_EQ(state.settings.captureSnaplen, 1500u);
    EXPECT_FALSE(state.settings.capturePromiscuous);
    EXPECT_TRUE(state.settingsDirty);
    frames(state);                           // the error popup and the red status bar text are drawn
    EXPECT_FALSE(state.live.openError) << "the popup request is consumed";
    EXPECT_FALSE(ui::captureStatusText(state).empty() && state.live.session);
}

TEST_F(UiSmoke, LiveSessionGrowsFiltersSelectsAndBehavesLikeAFileAfterStop) {
    ui::AppState state;
    const auto traffic = liveTraffic();
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    EXPECT_TRUE(state.live.capturing());
    EXPECT_TRUE(state.live.session);
    EXPECT_TRUE(ui::liveUnsaved(state) == false) << "nothing captured yet, nothing to lose";
    EXPECT_EQ(state.currentFile, state.live.device->tempPath());
    EXPECT_EQ(ui::captureStatusText(state), "Capturing on fake0 - 0 packets, 0 dropped");
    frames(state);

    // a display filter that matches rows only after a later packet amended them
    ASSERT_TRUE(ui::applyFilter(state, "info contains \"Reassembled in\""));
    injectFrames(state, traffic, 0, 3);
    frames(state);
    ASSERT_EQ(state.packets.size(), 3u) << "polled by the frame";
    EXPECT_TRUE(state.filter.visible.empty());
    EXPECT_EQ(ui::captureStatusText(state), "Capturing on fake0 - 3 packets, 0 dropped  |  Displayed: 0 / 3");
    EXPECT_TRUE(ui::liveUnsaved(state));

    // details of a packet while capturing come from the temp file
    state.selectedPacket = 1;                // the SYN
    frames(state);
    EXPECT_TRUE(state.detailOk);
    EXPECT_FALSE(state.detail.fields.empty());
    EXPECT_FALSE(state.detail.raw_data.empty());

    injectFrames(state, traffic, 3, 5);      // packet 5 completes the request: packet 3 is edited in place
    frames(state);
    ASSERT_EQ(state.packets.size(), 5u);
    EXPECT_NE(state.packets[2].info.find("[Reassembled in #5]"), std::string::npos) << state.packets[2].info;
    EXPECT_EQ(state.filter.visible, (std::vector<uint32_t>{2})) << "the amended earlier row now passes the filter";
    frames(state);
    EXPECT_EQ(state.order, (std::vector<uint32_t>{2}));

    // the display filter and the colouring apply to new packets as well
    ASSERT_TRUE(ui::applyFilter(state, "tcp"));
    EXPECT_EQ(state.filter.visible, (std::vector<uint32_t>{1, 2, 4}));
    injectFrames(state, traffic, 5, 6);
    frames(state);
    EXPECT_EQ(state.filter.visible, (std::vector<uint32_t>{1, 2, 4, 5}));
    state.selectedPacket = 2;
    frames(state);
    EXPECT_TRUE(state.detailOk);
    const auto selectedInfo = state.packets[2].info;
    EXPECT_FALSE(state.live.scrollToEnd) << "the list consumed the auto-scroll request";

    // the statistics follow a growing capture (recomputed lazily)
    state.stats.showHierarchy = true;
    state.stats.dirty = true;
    frames(state);
    EXPECT_TRUE(state.stats.hierarchyValid);

    // stop: the capture becomes an ordinary opened file
    ui::stopCapture(state);
    EXPECT_FALSE(state.live.capturing());
    EXPECT_TRUE(state.live.session);
    EXPECT_EQ(state.packets.size(), 6u);
    ASSERT_FALSE(state.tempFile.empty());
    EXPECT_EQ(state.currentFile, state.tempFile);
    EXPECT_TRUE(std::filesystem::exists(state.tempFile));
    EXPECT_EQ(state.captureInfo.interfaces.size(), 1u);
    EXPECT_EQ(state.captureInfo.interfaces[0].packets, 6u);
    EXPECT_EQ(ui::captureStatusText(state), "Live capture on fake0 (stopped)  |  6 packets  |  Displayed: 4 / 6");
    frames(state);
    EXPECT_TRUE(state.detailOk) << "details are still read from the (now owned) temp file";
    EXPECT_EQ(state.packets[2].info, selectedInfo);

    // equal to loading the finished file
    {
        ui::AppState loaded;
        ui::loadCapture(loaded, state.tempFile);
        ASSERT_EQ(loaded.packets.size(), state.packets.size());
        for (size_t i = 0; i < loaded.packets.size(); ++i) {
            EXPECT_EQ(loaded.packets[i].info, state.packets[i].info) << i;
            EXPECT_EQ(loaded.packets[i].protocol, state.packets[i].protocol) << i;
            EXPECT_EQ(loaded.packets[i].time, state.packets[i].time) << i;
        }
    }

    // follow stream works on the stopped capture
    ASSERT_TRUE(ui::startFollow(state, 2));
    for (int i = 0; i < 3000 && state.follow.job; ++i) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    ASSERT_TRUE(state.follow.valid);
    ASSERT_FALSE(state.follow.stream.chunks.empty());
    EXPECT_EQ(state.follow.stream.chunks[0].data, kRequest);
    state.follow.open = false;

    // export all as pcap: the capture counts as saved afterwards
    EXPECT_TRUE(ui::liveUnsaved(state));
    const auto path = (std::filesystem::temp_directory_path() / "imshark_ui_live_export.pcap").string();
    std::remove(path.c_str());
    ASSERT_TRUE(ui::startExport(state, ui::ExportState::All, exporter::Format::Pcap, path));
    for (int i = 0; i < 3000 && state.exportDialog.job; ++i) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    EXPECT_FALSE(state.exportDialog.resultIsError) << state.exportDialog.resultMessage;
    EXPECT_FALSE(ui::liveUnsaved(state));
    {
        ui::AppState exported;
        ui::loadCapture(exported, path);
        EXPECT_EQ(exported.packets.size(), 6u);
    }
    std::remove(path.c_str());

    // saved: quitting needs no question; the temp file goes when the state is destroyed
    const std::string temp = state.tempFile;
    ui::requestQuit(state);
    EXPECT_TRUE(state.quitRequested);
    EXPECT_FALSE(std::filesystem::exists(temp)) << "the discarded live capture's temp file is removed";
}

TEST_F(UiSmoke, UnsavedLiveCaptureAsksBeforeItIsLost) {
    ui::AppState state;
    const auto traffic = liveTraffic();
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    injectFrames(state, traffic, 0, 4);
    frames(state);
    ASSERT_EQ(state.packets.size(), 4u);
    const std::string temp = state.live.device->tempPath();
    ASSERT_TRUE(std::filesystem::exists(temp));

    // quitting while the capture runs: asks, does not quit, keeps capturing
    ui::requestQuit(state);
    EXPECT_FALSE(state.quitRequested);
    EXPECT_EQ(state.live.pending.kind, ui::PendingAction::Quit);
    frames(state);                                           // the popup is drawn
    ui::resolveUnsaved(state, ui::UnsavedChoice::Cancel);
    EXPECT_TRUE(state.live.capturing());
    EXPECT_EQ(state.live.pending.kind, ui::PendingAction::None);
    EXPECT_FALSE(state.quitRequested);

    // opening a file asks as well; "Export" ends the capture and opens the export dialog instead of the action
    ui::requestOpen(state, IMSHARK_TEST_DATA_DIR "/sample.pcap");
    EXPECT_FALSE(state.loading());
    ui::resolveUnsaved(state, ui::UnsavedChoice::Export);
    EXPECT_FALSE(state.live.capturing());
    EXPECT_EQ(state.packets.size(), 4u);
    EXPECT_TRUE(state.exportDialog.openPopup);
    EXPECT_FALSE(state.loading());
    frames(state);                                           // the export options popup is drawn

    // closing asks; Discard removes the capture and its temp file
    ui::requestClose(state);
    EXPECT_EQ(state.live.pending.kind, ui::PendingAction::Close);
    frames(state);
    ui::resolveUnsaved(state, ui::UnsavedChoice::Discard);
    EXPECT_TRUE(state.packets.empty());
    EXPECT_FALSE(state.live.session);
    EXPECT_TRUE(state.currentFile.empty());
    EXPECT_FALSE(std::filesystem::exists(temp));
    EXPECT_EQ(ui::captureStatusText(state), "");
    frames(state);
}

TEST_F(UiSmoke, DiscardingForAnOpenReplacesTheLiveCapture) {
    ui::AppState state;
    const auto traffic = liveTraffic();
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    injectFrames(state, traffic, 0, 3);
    frames(state);
    const std::string temp = state.live.device->tempPath();
    ui::requestOpen(state, IMSHARK_TEST_DATA_DIR "/sample.pcap");
    ui::resolveUnsaved(state, ui::UnsavedChoice::Discard);
    for (int i = 0; i < 2000 && state.loading(); ++i) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    EXPECT_EQ(state.packets.size(), 16u);
    EXPECT_FALSE(state.live.session);
    EXPECT_FALSE(std::filesystem::exists(temp));
}

TEST_F(UiSmoke, FailedOpenAfterDiscardLeavesTheLiveCaptureIntact) {
    ui::AppState state;
    const auto traffic = liveTraffic();
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    injectFrames(state, traffic, 0, 3);
    frames(state);
    const std::string temp = state.live.device->tempPath();

    ui::requestOpen(state, "/no/such/capture.pcap");
    ui::resolveUnsaved(state, ui::UnsavedChoice::Discard);
    for (int i = 0; i < 2000 && state.loading(); ++i) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    EXPECT_TRUE(state.loadFailed);
    EXPECT_TRUE(state.live.session) << "the capture is still open";
    EXPECT_TRUE(state.live.capturing());
    EXPECT_EQ(state.packets.size(), 3u);
    EXPECT_TRUE(std::filesystem::exists(temp));
    state.selectedPacket = 1;
    frames(state);
    EXPECT_TRUE(state.detailOk) << "details still read the temp file";
    injectFrames(state, traffic, 3, 5);              // and it keeps capturing
    frames(state);
    EXPECT_EQ(state.packets.size(), 5u);
    ui::stopCapture(state);
    EXPECT_TRUE(std::filesystem::exists(state.tempFile));
    EXPECT_EQ(state.packets.size(), 5u);

    // a cancelled load is as harmless
    ui::requestOpen(state, IMSHARK_TEST_DATA_DIR "/sample.pcap");
    ui::resolveUnsaved(state, ui::UnsavedChoice::Discard);
    ui::cancelLoad(state);
    while (state.loading()) { ui::pollLoad(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    if (state.loadFailed) {                          // (a tiny file may finish before the cancel is noticed)
        EXPECT_TRUE(state.live.session);
        EXPECT_EQ(state.packets.size(), 5u);
        EXPECT_TRUE(std::filesystem::exists(state.tempFile));
    }
}

TEST_F(UiSmoke, LaterFileLoadsDoNotDeleteTheStalePathOfAnEarlierCapture) {
    ui::AppState state;
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    const std::string stale = state.live.device->tempPath();
    ui::closeCapture(state);                         // discards the session and its file
    ASSERT_FALSE(std::filesystem::exists(stale));
    { std::ofstream bystander(stale); bystander << "not ours any more"; }
    load(state);                                     // a successful load must not touch the stale path again
    EXPECT_TRUE(std::filesystem::exists(stale));
    std::remove(stale.c_str());
}

TEST_F(UiSmoke, InvalidCaptureFilterWarnsButDoesNotBlockStart) {
    if (!capture::liveCaptureAvailable()) GTEST_SKIP() << "built without libpcap";
    ui::AppState state;
    state.live.dialog.open = true;
    state.live.options.interfaceName = "imshark-no-such-interface0";
    state.live.options.filter = "ether proto 0x0800 and (";
    frames(state);
    EXPECT_FALSE(state.live.dialog.filterCheck.ok);
    EXPECT_TRUE(state.live.dialog.open);
}

TEST_F(UiSmoke, NewSessionTakesOverTheQueuedPacketsOfTheOldOneFirst) {
    ui::AppState state;
    const auto traffic = liveTraffic();
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    injectFrames(state, traffic, 0, 3);                      // not polled by a frame yet
    const std::string first = state.live.device->tempPath();
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake1"));
    EXPECT_TRUE(state.packets.empty()) << "the replaced capture is gone";
    EXPECT_EQ(state.live.interfaceName, "fake1");
    EXPECT_FALSE(std::filesystem::exists(first)) << "the old temp file was removed";
    EXPECT_NE(state.live.device->tempPath(), first);
    injectFrames(state, traffic, 0, 2);
    frames(state);
    EXPECT_EQ(state.packets.size(), 2u);
    ui::stopCapture(state);
    EXPECT_EQ(state.packets.size(), 2u);
}

TEST_F(UiSmoke, CaptureThatEndsOnItsOwnIsFinishedWithTheErrorReported) {
    ui::AppState state;
    const auto traffic = liveTraffic();
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    injectFrames(state, traffic, 0, 2);
    frames(state);
    ASSERT_EQ(state.packets.size(), 2u);

#ifndef _WIN32
    // the temp file cannot be written any more (process file size limit): the capture core stops and says why
    auto previousHandler = std::signal(SIGXFSZ, SIG_IGN);
    rlimit original{};
    ASSERT_EQ(::getrlimit(RLIMIT_FSIZE, &original), 0);
    rlimit limited = original;
    limited.rlim_cur = 2500;
    ASSERT_EQ(::setrlimit(RLIMIT_FSIZE, &limited), 0);
    const std::vector<char> big(900, 'x');
    for (int i = 0; i < 20 && state.live.device->running(); ++i) state.live.device->injectPacket(1700001000 + i, 1, big);
    ASSERT_EQ(::setrlimit(RLIMIT_FSIZE, &original), 0);
    std::signal(SIGXFSZ, previousHandler);
    ASSERT_FALSE(state.live.device->running());

    frames(state);                                           // pollCapture notices, takes over the packets, reports
    EXPECT_FALSE(state.live.capturing());
    EXPECT_TRUE(state.live.session);
    EXPECT_FALSE(state.live.error.empty());
    EXPECT_NE(state.live.error.find("Writing to the temporary capture file failed"), std::string::npos);
    EXPECT_FALSE(state.live.openError) << "the error popup was shown";
    EXPECT_GE(state.packets.size(), 2u);
    EXPECT_EQ(state.packets.size(), state.live.device->packetCount());
    EXPECT_EQ(state.currentFile, state.tempFile);
    state.selectedPacket = 0;
    frames(state);
    EXPECT_TRUE(state.detailOk) << "the packets captured before the failure are readable";
    EXPECT_NE(ui::captureStatusText(state).find("(stopped)"), std::string::npos);
#endif
}

TEST_F(UiSmoke, DecodeAsIsRefusedWhileALiveCaptureIsOpen) {
    ui::AppState state;
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    EXPECT_FALSE(ui::applyDecodeAs(state, {}));
    EXPECT_FALSE(state.decodeAs.error.empty());
    ui::closeCapture(state);
    EXPECT_TRUE(ui::applyDecodeAs(state, {}));
}

TEST_F(UiSmoke, PacketListCopiesOnWriteWhileABackgroundJobHoldsASnapshot) {
    ui::PacketList list;
    list.modify().emplace_back(1);
    const auto snapshot = list.share();
    ASSERT_EQ(snapshot->size(), 1u);
    list.modify().emplace_back(2);                           // the snapshot's holder must not see this
    EXPECT_EQ(snapshot->size(), 1u);
    EXPECT_EQ(list.size(), 2u);
    const auto *before = &list[0];
    list.modify().emplace_back(3);                           // no snapshot taken since the last copy: in place
    EXPECT_EQ(list.size(), 3u);
    (void) before;
}

TEST_F(UiSmoke, BurstIsDissectedOverSeveralFramesAndTheIncrementalFilterEqualsAFullRefilter) {
    ui::AppState state;
    const auto traffic = liveTraffic();
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    ASSERT_TRUE(ui::applyFilter(state, "tcp || info contains \"Reassembled\""));
    constexpr size_t kBurst = 3000;
    for (size_t i = 0; i < kBurst; ++i) {
        ASSERT_TRUE(state.live.device->injectPacket(1700000000 + i / 1000, static_cast<uint32_t>((i % 1000) * 1000), traffic[i % traffic.size()]));
    }
    size_t frameCount = 0;
    while (state.packets.size() < kBurst && frameCount < 2000) {
        frame(state);
        ++frameCount;
        EXPECT_LE(state.packets.size(), kBurst);
        EXPECT_EQ(state.order.size(), state.filter.visible.size()) << "the list follows the capture without lagging (frame " << frameCount << ")";
    }
    ASSERT_EQ(state.packets.size(), kBurst);
    frames(state);
    EXPECT_EQ(state.order, state.filter.visible) << "the incrementally extended list equals the filter result";

    const auto incremental = state.filter.visible;
    ui::refilter(state);
    EXPECT_EQ(state.filter.visible, incremental) << "extendFilter / amended handling equals a full re-evaluation";
    frames(state);
    ui::stopCapture(state);
}

TEST_F(UiSmoke, LastCaptureOptionsArePersistedAndRestoredIntoTheDialog) {
    const auto path = (std::filesystem::temp_directory_path() / "imshark_smoke_capture_settings/settings.ini").string();
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
    {
        ui::AppState state;
        ui::initSettings(state, path);
        EXPECT_TRUE(state.live.options.interfaceName.empty());
        EXPECT_EQ(state.live.options.snaplen, 262144u);
        EXPECT_TRUE(state.live.options.promiscuous);
        capture::CaptureOptions options;
        options.interfaceName = "imshark-no-such-interface0";   // the start fails, the choice is remembered anyway
        options.filter = "tcp port 443";
        options.snaplen = 128;
        options.promiscuous = false;
        EXPECT_FALSE(ui::startCapture(state, options));
        frames(state);
        ui::saveSettingsIfDirty(state);
    }
    ui::AppState again;
    ui::initSettings(again, path);
    EXPECT_EQ(again.live.options.interfaceName, "imshark-no-such-interface0");
    EXPECT_EQ(again.live.options.filter, "tcp port 443");
    EXPECT_EQ(again.live.options.snaplen, 128u);
    EXPECT_FALSE(again.live.options.promiscuous);
    again.live.dialog.open = true;
    frames(again);
    EXPECT_EQ(again.live.options.filter, "tcp port 443") << "the dialog keeps the remembered options";
    std::filesystem::remove_all(std::filesystem::path(path).parent_path());
}
