#include "ui.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <thread>

#include <imgui.h>

#include <core.h>

namespace ui {
    /// One background load. Owned by AppState::loadJob; destroying it cancels and joins the thread.
    struct LoadJob {
        std::string path;
        core::LoadControl control;
        std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();

        // written by the worker, read after `finished` is set
        std::vector<packet::PacketInfo> packets;
        std::string message;
        bool ok = false;

        std::atomic<bool> finished{false};
        std::thread thread;

        ~LoadJob() {
            control.cancelRequested = true;
            if (thread.joinable()) thread.join();
        }
    };
} // namespace ui

namespace {
    bool isPcapng(const std::string &filepath) {
        std::ifstream file(core::pathFromUtf8(filepath), std::ios::binary);
        uint32_t magic = 0;
        return file.read(reinterpret_cast<char *>(&magic), sizeof(magic)) && magic == 0x0A0D0D0A;
    }

    void runJob(ui::LoadJob &job) {
        core::FileProcessor processor;
        if (!std::filesystem::is_regular_file(core::pathFromUtf8(job.path))) {
            job.message = "Not a regular file: " + job.path;
        } else {
            job.ok = isPcapng(job.path) ? processor.processPcapngFile(job.path, job.packets, job.message, &job.control)
                                        : processor.processPcapFile(job.path, job.packets, job.message, &job.control);
        }
        job.finished = true;
    }
} // namespace

void ui::startLoad(AppState &state, const std::string &path) {
    state.loadJob.reset(); // cancels and joins a load that is still running

    auto job = std::make_shared<LoadJob>();
    job->path = path;
    job->thread = std::thread([raw = job.get()] { runJob(*raw); });
    state.loadJob = std::move(job);
}

std::string ui::loadingPath(const AppState &state) { return state.loadJob ? state.loadJob->path : std::string(); }

void ui::cancelLoad(AppState &state) {
    if (state.loadJob) state.loadJob->control.cancelRequested = true;
}

void ui::pollLoad(AppState &state) {
    if (!state.loadJob || !state.loadJob->finished) return;

    std::shared_ptr<LoadJob> job = std::move(state.loadJob);
    state.loadJob.reset();
    job->thread.join();

    state.loadMessage = job->message;
    if (job->ok) {
        state.packets = std::move(job->packets);
        state.clearSelection();
        state.currentFile = job->path;
        state.loadFailed = false;
    } else {
        // Keep whatever was shown before: a failed or cancelled load does not destroy the open capture.
        state.loadFailed = true;
    }

    const bool cancelled = !job->ok && job->message == "Cancelled";
    if (!state.loadMessage.empty() && !cancelled) {
        std::cerr << job->path << ": " << state.loadMessage << std::endl;
        state.openLoadError = true;
    }
}

void ui::loadCapture(AppState &state, const std::string &path) {
    startLoad(state, path);
    while (state.loading()) {
        pollLoad(state);
        if (state.loading()) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

// Progress popup: only shown for loads that take noticeable time, so small files do not flash a dialog.
void ui::drawLoadProgressPopup(AppState &state) {
    if (!state.loading()) return;
    const auto elapsed = std::chrono::steady_clock::now() - state.loadJob->started;
    if (elapsed < std::chrono::milliseconds(250)) return;

    const auto &control = state.loadJob->control;
    const uint64_t total = control.totalBytes;
    const float fraction = total ? static_cast<float>(static_cast<double>(control.bytesProcessed) / static_cast<double>(total)) : 0.0f;

    ImGui::OpenPopup("Loading capture");
    if (ImGui::BeginPopupModal("Loading capture", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove)) {
        ImGui::TextUnformatted(state.loadJob->path.c_str());
        ImGui::ProgressBar(fraction, ImVec2(420, 0));
        ImGui::Text("%llu packets, %.1f / %.1f MB", static_cast<unsigned long long>(control.packetsLoaded.load()),
                    static_cast<double>(control.bytesProcessed) / 1048576.0, static_cast<double>(total) / 1048576.0);
        if (ImGui::Button("Cancel", ImVec2(120, 0))) cancelLoad(state);
        ImGui::EndPopup();
    }
}
