#include "ui.h"

#include <cstdlib>
#include <filesystem>

#include <imgui.h>

#include <ImGuiFileDialog.h>

void ui::applyTheme(bool dark) {
    if (dark) ImGui::StyleColorsDark();
    else ImGui::StyleColorsLight();
}

void ui::initSettings(AppState &state, const std::string &path) {
    state.settingsPath = path;
    state.settings = path.empty() ? Settings() : loadSettings(path);
    state.listHeight = state.settings.listHeight;
    state.settingsDirty = false;
    recompileColorRules(state);
}

void ui::saveSettingsIfDirty(AppState &state) {
    if (state.settingsPath.empty()) return;
    if (state.settings.listHeight != state.listHeight) {
        state.settings.listHeight = state.listHeight;
        state.settingsDirty = true;
    }
    if (!state.settingsDirty) return;
    saveSettings(state.settings, state.settingsPath);
    state.settingsDirty = false;
}

float ui::statusBarHeight() { return ImGui::GetFrameHeight() + 2 * ImGui::GetStyle().WindowPadding.y; }

void ui::drawMenuAndDialogs(AppState &state) {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open...", "Ctrl+O")) {
                ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Choose File", ".pcapng,.pcap,");
            }
            if (ImGui::BeginMenu("Open Recent", !state.settings.recentFiles.empty())) {
                std::string chosen;
                for (const auto &recent: state.settings.recentFiles) {
                    const std::string name = std::filesystem::path(recent).filename().string();
                    if (ImGui::MenuItem(name.c_str())) chosen = recent;
                    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", recent.c_str());
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Clear Recent")) {
                    state.settings.recentFiles.clear();
                    state.settingsDirty = true;
                }
                ImGui::EndMenu();
                if (!chosen.empty()) startLoad(state, chosen);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Capture File Properties...", nullptr, false, !state.currentFile.empty())) state.showCaptureInfo = true;
            if (ImGui::MenuItem("Export Packets...", nullptr, false, !state.packets.empty())) state.exportDialog.openPopup = true;
            if (ImGui::MenuItem("Close File", "Ctrl+W", false, !state.currentFile.empty())) {
                state.loadJob.reset();
                cancelBackgroundJobs(state);
                state.packets.clear();
                refilter(state);
                state.clearSelection();
                state.currentFile.clear();
                state.loadMessage.clear();
                state.loadFailed = false;
            }
            if (ImGui::MenuItem("Exit")) std::exit(0);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Analyze")) {
            const packet::PacketInfo *sel = state.currentPacket();
            const bool isStream = sel && sel->ip_version != 0 && (sel->ip_protocol == 6 || sel->ip_protocol == 17);
            if (ImGui::MenuItem("Follow TCP Stream", nullptr, false, isStream && sel->ip_protocol == 6)) startFollow(state, state.selectedPacket);
            if (ImGui::MenuItem("Follow UDP Stream", nullptr, false, isStream && sel->ip_protocol == 17)) startFollow(state, state.selectedPacket);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Statistics")) {
            ImGui::MenuItem("Expert Information", nullptr, &state.stats.showExpert);
            ImGui::Separator();
            ImGui::MenuItem("Protocol Hierarchy", nullptr, &state.stats.showHierarchy);
            ImGui::MenuItem("Conversations", nullptr, &state.stats.showConversations);
            ImGui::MenuItem("Endpoints", nullptr, &state.stats.showEndpoints);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("View")) {
            if (ImGui::MenuItem("Dark Theme", nullptr, state.settings.darkTheme)) {
                state.settings.darkTheme = true;
                state.settingsDirty = true;
                applyTheme(true);
            }
            if (ImGui::MenuItem("Light Theme", nullptr, !state.settings.darkTheme)) {
                state.settings.darkTheme = false;
                state.settingsDirty = true;
                applyTheme(false);
            }
            ImGui::Separator();
            if (ImGui::BeginMenu("Time Display Format")) {
                for (auto f: {TimeFormat::SinceCaptureStart, TimeFormat::SincePrevious, TimeFormat::UtcDateTime, TimeFormat::EpochSeconds}) {
                    if (ImGui::MenuItem(timeFormatName(f), nullptr, state.settings.timeFormat == f)) {
                        state.settings.timeFormat = f;
                        state.settingsDirty = true;
                    }
                }
                ImGui::EndMenu();
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Colorize Packet List", nullptr, state.settings.colorize)) {
                state.settings.colorize = !state.settings.colorize;
                state.settingsDirty = true;
            }
            if (ImGui::MenuItem("Coloring Rules...")) state.showColorRules = true;
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }

    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_W, false) && !state.currentFile.empty()) {
        state.loadJob.reset();
        cancelBackgroundJobs(state);
        state.packets.clear();
        refilter(state);
        state.clearSelection();
        state.currentFile.clear();
        state.loadMessage.clear();
        state.loadFailed = false;
    }

    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O, false)) {
        ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Choose File", ".pcapng,.pcap,");
    }

    if (ImGuiFileDialog::Instance()->Display("ChooseFileDlgKey")) {
        if (ImGuiFileDialog::Instance()->IsOk()) {
            startLoad(state, ImGuiFileDialog::Instance()->GetFilePathName());
        }
        ImGuiFileDialog::Instance()->Close();
    }
}

void ui::drawStatusBar(const AppState &state) {
    const ImVec2 display = ImGui::GetIO().DisplaySize;
    ImGui::SetNextWindowPos(ImVec2(0, display.y - statusBarHeight()));
    ImGui::SetNextWindowSize(ImVec2(display.x, statusBarHeight()));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                                   ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;
    if (ImGui::Begin("##status", nullptr, flags)) {
        if (state.loading()) {
            ImGui::Text("Loading %s ...", loadingPath(state).c_str());
        } else if (state.currentFile.empty()) {
            ImGui::TextUnformatted("No file loaded. Use File > Open.");
        } else {
            if (state.filter.active) {
                ImGui::Text("%s  |  Displayed: %zu / %zu packets", state.currentFile.c_str(), state.displayedCount(), state.packets.size());
            } else {
                ImGui::Text("%s  |  %zu packets", state.currentFile.c_str(), state.packets.size());
            }
        }
        if (!state.loadMessage.empty()) {
            ImGui::SameLine();
            ImGui::TextColored(state.loadFailed ? ImVec4(1.0f, 0.4f, 0.4f, 1.0f) : ImVec4(1.0f, 0.8f, 0.3f, 1.0f),
                               "  |  %s", state.loadMessage.c_str());
        }
    }
    ImGui::End();
}

void ui::drawLoadErrorPopup(AppState &state) {
    if (state.openLoadError) {
        ImGui::OpenPopup("Load problem");
        state.openLoadError = false;
    }
    if (ImGui::BeginPopupModal("Load problem", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::TextWrapped("%s", state.loadFailed ? "The file could not be opened." : "The file was opened with a warning.");
        ImGui::Separator();
        ImGui::TextWrapped("%s", state.loadMessage.c_str());
        ImGui::Spacing();
        if (ImGui::Button("OK", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
        ImGui::EndPopup();
    }
}
