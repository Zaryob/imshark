// Display filters run on a worker thread: the frame loop keeps going, a new filter or closing the file cancels the
// running one, and the published result equals a synchronous evaluation.

#include <gtest/gtest.h>

#include <chrono>
#include <cstdlib>
#include <cstdio>
#include <thread>

#include <imgui.h>

#include <core.h>

#include "../src/ui/filter_job.h"
#include "../src/ui/ui.h"
#include "support.h"

namespace {
    using Clock = std::chrono::steady_clock;

    // Regex-heavy on purpose: std::regex backtracks, so every packet costs real time.
    const char *kHeavy = "info matches \"^(.*[0-9])+.*(Len|Win|Seq)=.*[0-9]+$\" || info matches \"^[0-9]+ .*[0-9]+ .*(Len|Win)=[0-9]+$\"";
    const char *kLight = "udp && ip.dst == 10.0.0.2";

    class FilterBackground : public ::testing::Test {
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
            ImGui::Render();
        }

        /// Draws frames until the filter job has been published; returns how many frames were drawn while it ran
        /// and the longest frame in milliseconds.
        struct Run { int frames = 0; double longestMs = 0; };
        Run runFrames(ui::AppState &state) {
            Run run;
            const auto deadline = Clock::now() + std::chrono::seconds(120);
            while (state.filter.job && Clock::now() < deadline) {
                const auto t0 = Clock::now();
                frame(state);
                const double ms = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
                run.longestMs = std::max(run.longestMs, ms);   // including the frame that publishes the result
                if (state.filter.job) ++run.frames;
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            return run;
        }

        ImGuiContext *ctx = nullptr;
    };

    // a classic pcap with `count` alternating UDP and TCP packets
    std::string writeCapture(size_t count) {
        std::vector<char> f;
        support::put<uint32_t>(f, 0xa1b2c3d4);
        support::put<uint16_t>(f, 2); support::put<uint16_t>(f, 4);
        support::put<uint32_t>(f, 0); support::put<uint32_t>(f, 0); support::put<uint32_t>(f, 65535); support::put<uint32_t>(f, 1);
        for (size_t i = 0; i < count; ++i) {
            char a[9], b[9];
            std::snprintf(a, sizeof a, "0a00%02x%02x", static_cast<unsigned>((i >> 8) & 0xff), static_cast<unsigned>(i & 0xff));
            std::snprintf(b, sizeof b, "0a000002");
            const auto fr = i % 2 ? support::udpPacket(a, b, "1000", "2000", std::string(20 + i % 30, 'x'))
                                  : support::tcpPacket(a, b, "1000", "0050", "00000001", "00000000", "02");
            support::put<uint32_t>(f, static_cast<uint32_t>(1700000000 + i / 1000));
            support::put<uint32_t>(f, static_cast<uint32_t>((i % 1000) * 1000));
            support::put<uint32_t>(f, static_cast<uint32_t>(fr.size())); support::put<uint32_t>(f, static_cast<uint32_t>(fr.size()));
            f.insert(f.end(), fr.begin(), fr.end());
        }
        return support::writeTemp("filter_bg.pcap", f);
    }

    // the answer a plain loop gives
    std::vector<uint32_t> synchronous(ui::AppState &state, const std::string &text) {
        const auto compiled = filter::Filter::compile(text);
        EXPECT_TRUE(compiled.ok);
        filter::Context context;
        context.captureStartEpoch = state.captureStartEpoch;
        context.ethernet = state.ethernetAddresses();
        context.ipsec = state.ipsecHeaders();
        std::vector<uint32_t> out;
        for (size_t i = 0; i < state.packets.size(); ++i) {
            context.previous = i ? &state.packets[i - 1] : nullptr;
            if (compiled.filter.matches(state.packets[i], context)) out.push_back(static_cast<uint32_t>(i));
        }
        return out;
    }

    constexpr size_t kPackets = 30000;
} // namespace

TEST_F(FilterBackground, ApplyReturnsAtOnceKeepsThePreviousResultAndMatchesTheSynchronousAnswer) {
    const auto path = writeCapture(kPackets);
    ui::AppState state;
    ui::loadCapture(state, path);
    ASSERT_EQ(state.packets.size(), kPackets);
    frame(state);

    ASSERT_TRUE(ui::applyFilterNow(state, kLight));
    const auto previous = state.filter.visible;
    ASSERT_FALSE(previous.empty());

    ASSERT_TRUE(ui::applyFilter(state, kHeavy));
    ASSERT_TRUE(state.filter.job) << "evaluated in the background";
    EXPECT_EQ(state.filter.visible, previous) << "the previous result stays displayed meanwhile";
    EXPECT_EQ(state.filter.appliedText, kLight);
    EXPECT_GE(ui::filterProgress(state), 0.0f);

    const Run run = runFrames(state);
    EXPECT_GE(run.frames, 1) << "frames were drawn while the filter ran";
    EXPECT_LT(run.longestMs, 1000.0) << "no frame waited for the filter";
    ASSERT_FALSE(state.filter.job);
    EXPECT_EQ(state.filter.appliedText, kHeavy);
    EXPECT_TRUE(state.filter.active);
    EXPECT_EQ(state.filter.visible, synchronous(state, kHeavy));
    EXPECT_LT(ui::filterProgress(state), 0.0f);
    frame(state);
    EXPECT_EQ(state.order, state.filter.visible) << "the list swapped to the new result";
    std::remove(path.c_str());
}

TEST_F(FilterBackground, ProgressIsShownInTheFilterBarAndStatusBar) {
    const auto path = writeCapture(kPackets);
    ui::AppState state;
    ui::loadCapture(state, path);
    ASSERT_TRUE(ui::applyFilter(state, kHeavy));
    ASSERT_TRUE(state.filter.job);
    EXPECT_EQ(ui::statusSegments(state).filter.rfind("Filtering... ", 0), 0u);
    frame(state);   // the bar draws its progress bar and Stop button
    runFrames(state);
    EXPECT_EQ(ui::statusSegments(state).filter, kHeavy);
    std::remove(path.c_str());
}

TEST_F(FilterBackground, ANewFilterCancelsTheRunningOne) {
    const auto path = writeCapture(kPackets);
    ui::AppState state;
    ui::loadCapture(state, path);

    ASSERT_TRUE(ui::applyFilter(state, kHeavy));
    const auto first = state.filter.job;
    ASSERT_TRUE(first);
    const auto t0 = Clock::now();
    ASSERT_TRUE(ui::applyFilter(state, kLight));     // replaces it
    const double applyMs = std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
    EXPECT_LT(applyMs, 500.0) << "cancelling does not wait for the old job";
    ASSERT_TRUE(state.filter.job);
    EXPECT_NE(state.filter.job, first);
    EXPECT_TRUE(first->cancelRequested);

    runFrames(state);
    EXPECT_EQ(state.filter.appliedText, kLight) << "the cancelled filter never replaces the newer one";
    EXPECT_EQ(state.filter.visible, synchronous(state, kLight));
    std::remove(path.c_str());
}

TEST_F(FilterBackground, ClearingTheFilterCancelsAndShowsEverythingAtOnce) {
    const auto path = writeCapture(kPackets);
    ui::AppState state;
    ui::loadCapture(state, path);
    ASSERT_TRUE(ui::applyFilterNow(state, kLight));
    ASSERT_TRUE(ui::applyFilter(state, kHeavy));
    ASSERT_TRUE(state.filter.job);
    ASSERT_TRUE(ui::applyFilter(state, ""));
    EXPECT_FALSE(state.filter.job);
    EXPECT_FALSE(state.filter.active);
    EXPECT_EQ(state.displayedCount(), kPackets);
    frame(state);
    EXPECT_EQ(state.order.size(), kPackets);
    std::remove(path.c_str());
}

TEST_F(FilterBackground, StopKeepsThePreviousResult) {
    const auto path = writeCapture(kPackets);
    ui::AppState state;
    ui::loadCapture(state, path);
    ASSERT_TRUE(ui::applyFilterNow(state, kLight));
    const auto previous = state.filter.visible;
    ASSERT_TRUE(ui::applyFilter(state, kHeavy));
    ui::cancelFilter(state);
    EXPECT_FALSE(state.filter.job);
    EXPECT_EQ(state.filter.appliedText, kLight);
    EXPECT_EQ(state.filter.visible, previous);
    for (int i = 0; i < 3; ++i) frame(state);
    EXPECT_EQ(state.filter.visible, previous) << "the cancelled job never publishes";
    std::remove(path.c_str());
}

TEST_F(FilterBackground, ClosingTheFileMidFilterIsSafe) {
    const auto path = writeCapture(kPackets);
    {
        ui::AppState state;
        ui::loadCapture(state, path);
        ASSERT_TRUE(ui::applyFilter(state, kHeavy));
        ASSERT_TRUE(state.filter.job);
        ui::closeCapture(state);
        EXPECT_FALSE(state.filter.job);
        EXPECT_TRUE(state.packets.empty());
        for (int i = 0; i < 3; ++i) frame(state);
        EXPECT_TRUE(state.filter.visible.empty());
        EXPECT_EQ(state.order.size(), 0u);
        // the cancelled job may still be winding down; the state can go away at any moment
    }
    {
        // loading another capture replaces the rows the old job was reading
        ui::AppState state;
        ui::loadCapture(state, path);
        ASSERT_TRUE(ui::applyFilterNow(state, kLight));
        ASSERT_TRUE(ui::applyFilter(state, kHeavy));
        ui::loadCapture(state, IMSHARK_TEST_DATA_DIR "/sample.pcap");
        ASSERT_EQ(state.packets.size(), 16u);
        EXPECT_EQ(state.filter.appliedText, kHeavy) << "the applied filter is kept for the new capture";
        EXPECT_EQ(state.filter.visible, synchronous(state, kHeavy));
    }
    {
        // destroying the state while a job runs joins it
        ui::AppState state;
        ui::loadCapture(state, path);
        ASSERT_TRUE(ui::applyFilter(state, kHeavy));
    }
    std::remove(path.c_str());
}

TEST_F(FilterBackground, AppliedFilterIsReevaluatedInTheBackgroundForANewCapture) {
    const auto path = writeCapture(kPackets);
    ui::AppState state;
    ui::loadCapture(state, path);
    ASSERT_TRUE(ui::applyFilterNow(state, kLight));

    ui::startLoad(state, path);
    while (state.loading()) { frame(state); std::this_thread::sleep_for(std::chrono::milliseconds(1)); }
    ASSERT_EQ(state.packets.size(), kPackets);
    // the load published its packets and started the filter; the list does not show rows of the old capture
    if (state.filter.job) EXPECT_TRUE(state.filter.visible.empty());
    runFrames(state);
    EXPECT_EQ(state.filter.visible, synchronous(state, kLight));
    std::remove(path.c_str());
}

TEST_F(FilterBackground, SelectionOutsideTheNewResultIsDropped) {
    const auto path = writeCapture(2000);
    ui::AppState state;
    ui::loadCapture(state, path);
    state.selectedPacket = 0;   // a TCP packet
    ASSERT_TRUE(ui::applyFilterNow(state, "udp"));
    EXPECT_EQ(state.selectedPacket, -1);
    state.selectedPacket = 1;   // a UDP packet
    ASSERT_TRUE(ui::applyFilterNow(state, "udp && frame.number > 0"));
    EXPECT_EQ(state.selectedPacket, 1);
    std::remove(path.c_str());
}

TEST_F(FilterBackground, LiveCaptureRowsAddedWhileTheFilterRunsAreCaughtUp) {
    ui::AppState state;
    ASSERT_TRUE(ui::startInjectedCapture(state, 1, 262144, "fake0"));
    auto inject = [&](size_t from, size_t to) {
        for (size_t i = from; i < to; ++i) {
            const auto fr = i % 2 ? support::udpPacket("0a000001", "0a000002", "1000", "2000", "hello")
                                  : support::tcpPacket("0a000001", "0a000002", "1000", "0050", "00000001", "00000000", "02");
            ASSERT_TRUE(state.live.device->injectPacket(1700000000 + i, static_cast<uint32_t>(i * 1000), fr));
        }
    };
    inject(0, 400);
    frame(state);
    ASSERT_EQ(state.packets.size(), 400u);

    ASSERT_TRUE(ui::applyFilter(state, "udp"));
    ASSERT_TRUE(state.filter.job);
    inject(400, 600);          // arrive while the job runs on its snapshot
    frame(state);
    runFrames(state);
    ASSERT_EQ(state.packets.size(), 600u);
    EXPECT_EQ(state.filter.visible, synchronous(state, "udp"));
    frame(state);
    EXPECT_EQ(state.order, state.filter.visible);
    ui::stopCapture(state);
}

TEST(FilterRegex, LongValuesAreBoundedAndNeverThrow) {
    packet::PacketInfo p;
    p.info = std::string(200000, 'a') + "b";
    const auto anchored = filter::Filter::compile("info matches \"^a*b$\"");
    ASSERT_TRUE(anchored.ok);
    // only the first 4096 bytes are searched: the 'b' lies beyond them
    EXPECT_FALSE(anchored.filter.matches(p));
    const auto prefix = filter::Filter::compile("info matches \"^a+\"");
    ASSERT_TRUE(prefix.ok);
    EXPECT_TRUE(prefix.filter.matches(p));
    p.info = "GET /abcb HTTP/1.1";
    const auto mid = filter::Filter::compile("info matches \"^GET /a.*b \"");
    ASSERT_TRUE(mid.ok);
    EXPECT_TRUE(mid.filter.matches(p));
}

// Measurement, not a regression test: IMSHARK_BENCH_PCAP=<capture> IMSHARK_BENCH_FILTER=<expression> imshark_tests
// --gtest_filter=FilterBackground.MeasureUiThreadCost prints how long the UI thread is held by applying a filter
// (one blocking pass, as before, and through the background job) and the longest frame while the job runs.
TEST_F(FilterBackground, MeasureUiThreadCost) {
    const char *pcap = std::getenv("IMSHARK_BENCH_PCAP");
    const char *expression = std::getenv("IMSHARK_BENCH_FILTER");
    if (!pcap || !expression) GTEST_SKIP() << "set IMSHARK_BENCH_PCAP and IMSHARK_BENCH_FILTER to measure";
    auto ms = [](Clock::time_point a, Clock::time_point b) { return std::chrono::duration<double, std::milli>(b - a).count(); };

    ui::AppState state;
    ui::loadCapture(state, pcap);
    frame(state);

    const auto s0 = Clock::now();
    const auto sync = synchronous(state, expression);   // what the UI thread did before: one blocking pass
    const double syncMs = ms(s0, Clock::now());

    const auto a0 = Clock::now();
    ASSERT_TRUE(ui::applyFilter(state, expression));
    const double applyMs = ms(a0, Clock::now());
    const auto run = runFrames(state);
    const double totalMs = ms(a0, Clock::now());
    EXPECT_EQ(state.filter.visible, sync);
    std::printf("MEASURE packets=%zu matched=%zu blocking_pass_ms=%.1f background: apply_call_ms=%.2f frames_while_running=%d "
                "longest_frame_ms=%.1f total_to_publish_ms=%.1f\n",
                state.packets.size(), sync.size(), syncMs, applyMs, run.frames, run.longestMs, totalMs);
}
