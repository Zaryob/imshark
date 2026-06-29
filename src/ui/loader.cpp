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
#include <gzip.h>

namespace ui {
    /// One background load. Owned by AppState::loadJob; destroying it cancels and joins the thread.
    struct LoadJob {
        std::string path;
        std::shared_ptr<const dissect::Registry> registry;   // Decode As rules in effect (null = built-in)
        core::LoadControl control;
        std::chrono::steady_clock::time_point started = std::chrono::steady_clock::now();

        // written by the worker, read after `finished` is set
        std::vector<packet::PacketInfo> packets;
        std::string message;
        bool ok = false;
        double startEpoch = 0;
        core::CaptureInfo info;
        core::SessionTables sessions;
        tls::KeyStore tlsKeys;              // the user's TLS keys as they were when the load started (a copy: see AppState::tlsKeys)

        // .gz input: decompressed to a temporary file first
        std::string dataPath;               // what the packets were read from (== path unless decompressed)
        std::string tempPath;               // the temporary copy (deleted unless taken over by the UI state)
        bool keepTemp = false;
        std::atomic<bool> decompressing{false};
        uint64_t compressedSize = 0;

        std::atomic<bool> finished{false};
        std::thread thread;

        ~LoadJob() {
            control.cancelRequested = true;
            if (thread.joinable()) thread.join();
            if (!tempPath.empty() && !keepTemp) {
                std::error_code ec;
                std::filesystem::remove(core::pathFromUtf8(tempPath), ec);
            }
        }
    };
} // namespace ui

namespace {
    std::string makeTempPath() {
        static std::atomic<unsigned> counter{0};
        const auto stamp = std::chrono::steady_clock::now().time_since_epoch().count();
        return (std::filesystem::temp_directory_path() / ("imshark_" + std::to_string(stamp) + "_" + std::to_string(counter++) + ".cap")).string();
    }

    void runJob(ui::LoadJob &job) {
        core::FileProcessor processor(job.registry ? *job.registry : dissect::Registry::builtin());
        processor.sessions().tlsExternalKeys() = job.tlsKeys;
        if (!std::filesystem::is_regular_file(core::pathFromUtf8(job.path))) {
            job.message = "Not a regular file: " + job.path;
            job.finished = true;
            return;
        }

        job.dataPath = job.path;
        if (core::detectFileFormat(job.path) == core::FileFormat::Gzip) {
            // the packets keep file offsets, so a compressed capture is unpacked to a temporary file first
            job.decompressing = true;
            job.tempPath = makeTempPath();
            std::error_code ec;
            job.compressedSize = std::filesystem::file_size(core::pathFromUtf8(job.path), ec);
            std::string error;
            if (!core::gunzipFile(job.path, job.tempPath, error, &job.control)) {
                job.message = error.empty() ? "Cancelled" : error;
                job.decompressing = false;
                job.finished = true;
                return;
            }
            job.decompressing = false;
            job.dataPath = job.tempPath;
        }
        job.ok = processor.processFile(job.dataPath, job.packets, job.message, &job.control);
        job.startEpoch = processor.captureStartEpoch();
        job.info = processor.captureInfo();
        job.sessions = processor.sessions();
        if (!job.tempPath.empty()) {
            job.info.container = "gzip";
            job.info.compressedSize = job.compressedSize;
        }
        job.finished = true;
    }
} // namespace

namespace {
    // Absolute UTF-8 path: the file is reopened later for the details pane and remembered as a recent file.
    std::string absoluteUtf8(const std::string &path) {
        std::error_code ec;
        const auto abs = std::filesystem::absolute(core::pathFromUtf8(path), ec);
        if (ec) return path;
        const auto u8 = abs.u8string();
        return std::string(u8.begin(), u8.end());
    }
} // namespace

void ui::startLoad(AppState &state, const std::string &path) {
    state.loadJob.reset(); // cancels and joins a load that is still running

    auto job = std::make_shared<LoadJob>();
    job->path = absoluteUtf8(path);
    job->registry = state.registry;
    job->tlsKeys = state.tlsKeys;
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
        cancelBackgroundJobs(state); // background threads read state.packets
        discardLiveCapture(state);   // the file replaces a live capture (its temporary pcap goes with state.tempFile below)
        state.live.error.clear();
        state.packets.assign(std::move(job->packets));
        if (!state.tempFile.empty()) { // the previous capture's decompressed copy is not needed any more
            std::error_code ec;
            std::filesystem::remove(core::pathFromUtf8(state.tempFile), ec);
        }
        state.tempFile = job->tempPath;
        job->keepTemp = true;
        state.captureStartEpoch = job->startEpoch;
        state.captureInfo = std::move(job->info);
        state.sessions = std::move(job->sessions);
        state.clearSelection();
        refilter(state); // an active display filter stays active on the new capture
        state.currentFile = job->dataPath;
        state.displayName = job->path;
        state.loadFailed = false;
        addRecentFile(state.settings, job->path);
        state.settingsDirty = true;
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
        if (state.loadJob->decompressing) {
            ImGui::Text("Decompressing... %.1f / %.1f MB", static_cast<double>(control.bytesProcessed) / 1048576.0, static_cast<double>(total) / 1048576.0);
        } else {
            ImGui::Text("%llu packets, %.1f / %.1f MB", static_cast<unsigned long long>(control.packetsLoaded.load()),
                        static_cast<double>(control.bytesProcessed) / 1048576.0, static_cast<double>(total) / 1048576.0);
        }
        if (ImGui::Button("Cancel", ImVec2(120, 0))) cancelLoad(state);
        ImGui::EndPopup();
    }
}

ui::AppState::~AppState() {
    loadJob.reset(); // joins the worker before the state goes away
    if (!tempFile.empty()) {
        std::error_code ec;
        std::filesystem::remove(core::pathFromUtf8(tempFile), ec);
    }
}

void ui::closeCapture(AppState &state) {
    discardLiveCapture(state);
    clearCapture(state);
}

void ui::clearCapture(AppState &state) {
    state.loadJob.reset();
    cancelBackgroundJobs(state);
    state.packets.clear();
    refilter(state);
    state.clearSelection();
    state.currentFile.clear();
    state.displayName.clear();
    state.captureInfo = core::CaptureInfo();
    state.sessions.clear();
    state.loadMessage.clear();
    state.loadFailed = false;
    state.live.error.clear();
    if (!state.tempFile.empty()) {
        std::error_code ec;
        std::filesystem::remove(core::pathFromUtf8(state.tempFile), ec);
        state.tempFile.clear();
    }
}
