// Runs the real ImGui drawing code headless (no window, no OpenGL). ImGui's own assertions catch
// unbalanced Begin/End, Push/Pop and similar mistakes; the checks below cover the selection logic.
#include <gtest/gtest.h>

#include <chrono>
#include <thread>

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
