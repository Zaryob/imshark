#include "ui.h"

#include <atomic>
#include <thread>

#include <fstream>

#include <imgui.h>

#include <ImGuiFileDialog.h>

#include <core.h>

#include <stream/follow.h>

namespace ui {
    /// One background reassembly. The thread reads `state.packets` (see cancelBackgroundJobs).
    struct FollowJob {
        std::thread thread;
        core::ScanControl control;
        std::atomic<bool> finished{false};
        bool ok = false;
        stream::Stream stream;

        ~FollowJob() {
            control.cancelRequested = true;
            if (thread.joinable()) thread.join();
        }
    };
} // namespace ui

void ui::cancelBackgroundJobs(AppState &state) {
    cancelSearch(state);
    state.follow.job.reset();
    state.exportDialog.job.reset();
}

bool ui::startFollow(AppState &state, int packetIndex) {
    if (packetIndex < 0 || packetIndex >= static_cast<int>(state.packets.size()) || state.currentFile.empty()) return false;
    auto indices = stream::conversationPackets(state.packets, static_cast<uint32_t>(packetIndex));
    if (indices.empty()) return false;

    auto &f = state.follow;
    f.job.reset(); // a previous job is cancelled and joined
    f.open = true;
    f.valid = false;
    f.error.clear();
    f.lines.clear();

    const auto &p = state.packets[packetIndex];
    f.title = std::string("Follow ") + (p.ip_protocol == 6 ? "TCP" : "UDP") + " Stream (" + p.source + ":" + std::to_string(p.src_port) +
              " <-> " + p.destination + ":" + std::to_string(p.dst_port) + ")";

    auto job = std::make_shared<FollowJob>();
    job->control.total = indices.size();
    const std::string path = state.currentFile;
    const auto *packets = &state.packets;
    job->thread = std::thread([raw = job.get(), path, packets, indices = std::move(indices)] {
        raw->ok = stream::reassemble(path, *packets, indices, raw->stream, &raw->control);
        raw->finished = true;
    });
    f.job = std::move(job);
    return true;
}

namespace {
    void pollFollow(ui::AppState &state) {
        auto &f = state.follow;
        if (!f.job || !f.job->finished) return;
        std::shared_ptr<ui::FollowJob> job = std::move(f.job);
        f.job.reset();
        job->thread.join();
        if (job->ok) {
            f.stream = std::move(job->stream);
            f.valid = true;
            f.linesDirty = true;
        } else {
            f.error = job->control.cancelRequested ? "Cancelled" : "The capture file could not be read";
        }
    }

    std::string sizeText(uint64_t bytes) {
        char buf[32];
        if (bytes < 10000) std::snprintf(buf, sizeof(buf), "%llu bytes", static_cast<unsigned long long>(bytes));
        else std::snprintf(buf, sizeof(buf), "%.1f KB", static_cast<double>(bytes) / 1024.0);
        return buf;
    }
} // namespace

void ui::drawFollowWindow(AppState &state) {
    auto &f = state.follow;
    pollFollow(state);
    if (!f.open) return;

    ImGui::SetNextWindowSize(ImVec2(760, 520), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin((f.title + "###followstream").c_str(), &f.open)) { ImGui::End(); return; }
    if (!f.open) { f.job.reset(); ImGui::End(); return; }

    if (f.job) {
        ImGui::Text("Reading packets... %llu / %llu", static_cast<unsigned long long>(f.job->control.done.load()),
                    static_cast<unsigned long long>(f.job->control.total.load()));
        if (ImGui::Button("Cancel")) f.job->control.cancelRequested = true;
        ImGui::End();
        return;
    }
    if (!f.valid) {
        ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", f.error.empty() ? "No data" : f.error.c_str());
        ImGui::End();
        return;
    }

    const auto &s = f.stream;
    const std::string a = s.addressA + ":" + std::to_string(s.portA), b = s.addressB + ":" + std::to_string(s.portB);
    ImGui::TextColored(ImVec4(1.0f, 0.55f, 0.55f, 1.0f), "%s -> %s: %s", a.c_str(), b.c_str(), sizeText(s.bytesAtoB).c_str());
    ImGui::SameLine();
    ImGui::TextColored(ImVec4(0.55f, 0.7f, 1.0f, 1.0f), "%s -> %s: %s", b.c_str(), a.c_str(), sizeText(s.bytesBtoA).c_str());
    ImGui::Text("%d packets", s.packets);
    if (s.missingBytes > 0) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), " |  %s were not captured", sizeText(s.missingBytes).c_str());
    }
    if (s.truncated) {
        ImGui::SameLine();
        ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), " |  stream truncated at the size limit");
    }

    int dir = static_cast<int>(f.direction), view = static_cast<int>(f.view);
    ImGui::SetNextItemWidth(260);
    const std::string entire = "Entire conversation (" + sizeText(s.bytesAtoB + s.bytesBtoA) + ")";
    const std::string dirItems = entire + '\0' + a + " -> " + b + '\0' + b + " -> " + a + '\0';
    if (ImGui::Combo("##dir", &dir, dirItems.c_str())) { f.direction = static_cast<FollowDirection>(dir); f.linesDirty = true; }
    ImGui::SameLine();
    ImGui::SetNextItemWidth(120);
    if (ImGui::Combo("##view", &view, "ASCII\0Hex Dump\0")) { f.view = static_cast<FollowView>(view); f.linesDirty = true; }
    ImGui::SameLine();
    if (ImGui::Button("Copy")) ImGui::SetClipboardText(followText(f.lines).c_str());
    ImGui::SameLine();
    if (ImGui::Button("Save As...")) {
        IGFD::FileDialogConfig config;
        config.path = ".";
        config.fileName = "stream.bin";
        config.flags = ImGuiFileDialogFlags_ConfirmOverwrite | ImGuiFileDialogFlags_Modal;
        ImGuiFileDialog::Instance()->OpenDialog("SaveStreamDlg", "Save the stream data", ".*", config);
    }
    ImGui::SameLine();
    if (ImGui::Button("Filter Out This Stream")) {
        // show only this conversation in the packet list
        stats::Conversation c;
        c.addressA = s.addressA; c.portA = s.portA; c.addressB = s.addressB; c.portB = s.portB;
        applyFilter(state, stats::conversationFilter(c, s.tcp ? stats::AddressKind::Tcp : stats::AddressKind::Udp));
    }

    if (ImGuiFileDialog::Instance()->Display("SaveStreamDlg")) {
        if (ImGuiFileDialog::Instance()->IsOk()) {
            // the shown direction is what gets saved, as raw bytes
            std::ofstream file(core::pathFromUtf8(ImGuiFileDialog::Instance()->GetFilePathName()), std::ios::binary | std::ios::trunc);
            const std::string bytes = followRawBytes(s, f.direction);
            file.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
            f.error = file ? "" : "Could not write the file";
        }
        ImGuiFileDialog::Instance()->Close();
    }

    if (f.linesDirty) {
        f.lines = buildFollowLines(s, f.direction, f.view);
        f.linesDirty = false;
    }

    ImGui::BeginChild("streamtext", ImVec2(0, 0), true, ImGuiWindowFlags_HorizontalScrollbar);
    ImGuiListClipper clipper;
    clipper.Begin(static_cast<int>(f.lines.size()));
    while (clipper.Step()) {
        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
            const auto &line = f.lines[i];
            ImVec4 color = line.direction == stream::Direction::AtoB ? ImVec4(1.0f, 0.55f, 0.55f, 1.0f) : ImVec4(0.55f, 0.7f, 1.0f, 1.0f);
            if (line.kind == FollowLine::Kind::Gap) color = ImVec4(1.0f, 0.8f, 0.3f, 1.0f);
            ImGui::TextColored(color, "%s", line.text.empty() ? " " : line.text.c_str());
        }
    }
    ImGui::EndChild();
    ImGui::End();
}
