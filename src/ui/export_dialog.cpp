#include "ui.h"

#include <atomic>
#include <filesystem>
#include <numeric>
#include <thread>

#include <imgui.h>

#include <ImGuiFileDialog.h>

#include <core.h>

namespace ui {
    /// One background export. The thread works on a snapshot of the packet list.
    struct ExportJob {
        std::thread thread;
        core::ScanControl control;
        std::atomic<bool> finished{false};
        bool ok = false;
        std::string error;
        std::string path;
        size_t count = 0;
        exporter::Format format = exporter::Format::Pcapng;
        std::shared_ptr<const std::vector<packet::PacketInfo>> packets;   // snapshot of the capture
        std::vector<core::DecryptionSecrets> secrets;                     // pcapng Decryption Secrets Blocks of the capture
        core::CaptureInfo info;                                           // exact start time and timestamp resolution of the capture

        ~ExportJob() {
            control.cancelRequested = true;
            if (thread.joinable()) thread.join();
        }
    };
} // namespace ui

namespace {
    using exporter::Format;

    constexpr Format kFormats[] = {Format::Pcapng, Format::Pcap, Format::Csv, Format::Json};
    constexpr const char *kFormatLabels[] = {"pcapng (Wireshark capture file)", "pcap (classic capture file)", "CSV (packet list table)", "JSON (packet list)"};
}

std::vector<uint32_t> ui::exportIndices(const AppState &state, ExportState::Range range) {
    std::vector<uint32_t> out;
    switch (range) {
        case ExportState::All:
            out.resize(state.packets.size());
            std::iota(out.begin(), out.end(), 0u);
            break;
        case ExportState::Displayed:
            if (state.filter.active) out = state.filter.visible;     // ascending = capture order
            else { out.resize(state.packets.size()); std::iota(out.begin(), out.end(), 0u); }
            break;
        case ExportState::Selected:
            if (state.selectedPacket >= 0 && state.selectedPacket < static_cast<int>(state.packets.size())) out.push_back(static_cast<uint32_t>(state.selectedPacket));
            break;
    }
    return out;
}

bool ui::startExport(AppState &state, ExportState::Range range, Format format, const std::string &path) {
    auto indices = exportIndices(state, range);
    if (indices.empty() || path.empty()) return false;
    if (!exporter::isCaptureFormat(format)) {
        // a table follows the list as displayed (sorted), not the capture order
        if (range == ExportState::Displayed && !state.order.empty() && state.order.size() == indices.size()) indices = state.order;
    }

    auto &e = state.exportDialog;
    e.job.reset();
    auto job = std::make_shared<ExportJob>();
    job->path = path;
    job->count = indices.size();
    job->format = format;
    job->control.total = indices.size();
    const std::string capture = state.currentFile;
    job->packets = state.packets.share();
    job->secrets = state.captureInfo.decryptionSecrets;
    const double epoch = state.captureStartEpoch;
    job->info = state.captureInfo;
    job->thread = std::thread([raw = job.get(), capture, epoch, format, indices = std::move(indices)] {
        raw->ok = exporter::exportPackets(capture, *raw->packets, indices, epoch, format, raw->path, raw->error, &raw->control, &raw->secrets, &raw->info);
        raw->finished = true;
    });
    e.job = std::move(job);
    return true;
}

void ui::drawExportDialog(AppState &state) {
    auto &e = state.exportDialog;

    // finished job -> result message
    if (e.job && e.job->finished) {
        std::shared_ptr<ExportJob> job = std::move(e.job);
        e.job.reset();
        job->thread.join();
        if (job->ok) {
            // a finished live capture that was saved completely (as a capture file) no longer asks to be discarded
            if (state.live.session && !state.live.capturing() && exporter::isCaptureFormat(job->format) && job->count == state.packets.size()) {
                state.live.unsaved = false;
            }
            e.resultMessage = "Exported " + std::to_string(job->count) + " packets to\n" + job->path;
            e.resultIsError = false;
            e.showResult = true;
        } else if (!job->error.empty()) {
            e.resultMessage = job->error;
            e.resultIsError = true;
            e.showResult = true;
        } else {
            std::error_code ec;
            std::filesystem::remove(core::pathFromUtf8(job->path), ec); // cancelled: do not leave a partial file
            e.resultMessage.clear();
        }
    }

    if (e.openPopup) {
        ImGui::OpenPopup("Export Packets");
        e.openPopup = false;
    }
    if (ImGui::BeginPopupModal("Export Packets", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        const size_t all = state.packets.size();
        const size_t displayed = exportIndices(state, ExportState::Displayed).size();
        const std::string rangeItems = "All packets (" + std::to_string(all) + ")" + '\0' + "Displayed packets (" + std::to_string(displayed) + ")" + '\0' +
                                       (state.selectedPacket >= 0 ? "Selected packet (1)" : "Selected packet (none)") + '\0';
        ImGui::SetNextItemWidth(300);
        ImGui::Combo("Packets", &e.range, rangeItems.c_str());
        ImGui::SetNextItemWidth(300);
        if (ImGui::BeginCombo("Format", kFormatLabels[e.format])) {
            for (int i = 0; i < 4; ++i) {
                if (ImGui::Selectable(kFormatLabels[i], e.format == i)) e.format = i;
            }
            ImGui::EndCombo();
        }
        if (e.format == 3 || e.format == 2) ImGui::TextDisabled("Tables are written in the order of the packet list.");
        else ImGui::TextDisabled("Capture files keep the original frames and timestamps (microseconds).");

        const bool empty = exportIndices(state, static_cast<ExportState::Range>(e.range)).empty();
        if (empty) ImGui::TextColored(ImVec4(1.0f, 0.5f, 0.5f, 1.0f), "There is nothing to export for this selection.");
        ImGui::BeginDisabled(empty);
        if (ImGui::Button("Save As...", ImVec2(120, 0))) {
            IGFD::FileDialogConfig config;
            config.path = ".";
            config.fileName = std::string("export") + exporter::formatExtension(kFormats[e.format]);
            config.flags = ImGuiFileDialogFlags_ConfirmOverwrite | ImGuiFileDialogFlags_Modal;
            ImGuiFileDialog::Instance()->OpenDialog("ExportDlgKey", "Export Packets", exporter::formatExtension(kFormats[e.format]), config);
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Cancel", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }

    if (ImGuiFileDialog::Instance()->Display("ExportDlgKey")) {
        if (ImGuiFileDialog::Instance()->IsOk()) {
            startExport(state, static_cast<ExportState::Range>(e.range), kFormats[e.format], ImGuiFileDialog::Instance()->GetFilePathName());
        }
        ImGuiFileDialog::Instance()->Close();
    }

    // progress while exporting
    if (e.job) {
        ImGui::OpenPopup("Exporting");
        if (ImGui::BeginPopupModal("Exporting", nullptr, ImGuiWindowFlags_AlwaysAutoResize | ImGuiWindowFlags_NoMove)) {
            const uint64_t total = e.job->control.total, done = e.job->control.done;
            ImGui::TextUnformatted(e.job->path.c_str());
            ImGui::ProgressBar(total ? static_cast<float>(static_cast<double>(done) / static_cast<double>(total)) : 0.0f, ImVec2(380, 0));
            if (ImGui::Button("Cancel", ImVec2(120, 0))) e.job->control.cancelRequested = true;
            ImGui::EndPopup();
        }
    } else if (e.showResult) {
        ImGui::OpenPopup("Export finished");
        e.showResult = false;
    }
    if (ImGui::BeginPopupModal("Export finished", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextColored(e.resultIsError ? ImVec4(1.0f, 0.45f, 0.45f, 1.0f) : ImVec4(0.6f, 0.9f, 0.6f, 1.0f), "%s", e.resultMessage.c_str());
        ImGui::Spacing();
        if (ImGui::Button("OK", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}
