#include "ui.h"

#include <algorithm>
#include <filesystem>

#include <imgui.h>

#include <ImGuiFileDialog.h>

#include "theme.h"

#include <capture/live_capture.h>
#include <core.h>

void ui::openCaptureDialog() {
    IGFD::FileDialogConfig config;
    config.path = ".";
    config.flags = ImGuiFileDialogFlags_Modal;
    ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Open capture file", ".pcapng,.pcap,.cap,.snoop,.erf,.iptrace,.gz,.*", config);
}

void ui::applyTheme(bool dark) {
    applyThemeStyle(dark);
}

void ui::initSettings(AppState &state, const std::string &path) {
    state.settingsPath = path;
    state.settings = path.empty() ? Settings() : loadSettings(path);
    state.listHeight = state.settings.listHeight;
    state.live.options.interfaceName = state.settings.captureInterface;
    state.live.options.filter = state.settings.captureFilter;
    state.live.options.snaplen = state.settings.captureSnaplen;
    state.live.options.promiscuous = state.settings.capturePromiscuous;
    state.settingsDirty = false;
    recompileColorRules(state);
    state.preferences.tlsKeyLogEdit = state.settings.tlsKeyLogFile;
    loadTlsKeyLog(state);
}

void ui::saveSettingsIfDirty(AppState &state) {
    if (state.settingsPath.empty()) return;
    if (state.settings.listHeight != state.listHeight) {
        state.settings.listHeight = state.listHeight;
        state.settingsDirty = true;
    }
    if (!state.settingsDirty) return;
    if (saveSettings(state.settings, state.settingsPath)) state.settingsDirty = false;
}

float ui::statusBarHeight() { return ImGui::GetFrameHeight() + 2 * ImGui::GetStyle().WindowPadding.y; }

void ui::drawMenuAndDialogs(AppState &state) {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open...", "Ctrl+O")) {
                openCaptureDialog();
            }
            if (ImGui::BeginMenu("Open Recent", !state.settings.recentFiles.empty())) {
                std::string chosen;
                for (const auto &recent: state.settings.recentFiles) {
                    const std::string name = std::filesystem::path(recent).filename().string();
                    ImGui::PushID(recent.c_str()); // captures in different directories may have the same filename
                    if (ImGui::MenuItem(name.c_str())) chosen = recent;
                    if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", recent.c_str());
                    ImGui::PopID();
                }
                ImGui::Separator();
                if (ImGui::MenuItem("Clear Recent")) {
                    state.settings.recentFiles.clear();
                    state.settingsDirty = true;
                }
                ImGui::EndMenu();
                if (!chosen.empty()) requestOpen(state, chosen);
            }
            ImGui::Separator();
            if (ImGui::MenuItem("Capture File Properties...", nullptr, false, !state.currentFile.empty())) state.showCaptureInfo = true;
            if (ImGui::MenuItem("Export Packets...", nullptr, false, !state.packets.empty())) state.exportDialog.openPopup = true;
            if (ImGui::MenuItem("Close File", "Ctrl+W", false, !state.currentFile.empty())) requestClose(state);
            if (ImGui::MenuItem("Exit")) requestQuit(state);
            ImGui::EndMenu();
        }
        if (ImGui::BeginMenu("Edit")) {
            if (ImGui::MenuItem("Preferences...")) state.preferences.open = true;
            ImGui::EndMenu();
        }
        drawCaptureMenu(state);
        if (ImGui::BeginMenu("Analyze")) {
            const packet::PacketInfo *sel = state.currentPacket();
            const bool isStream = sel && sel->ip_version != 0 && (sel->ip_protocol == 6 || sel->ip_protocol == 17);
            if (ImGui::MenuItem("Follow TCP Stream", nullptr, false, isStream && sel->ip_protocol == 6)) startFollow(state, state.selectedPacket);
            if (ImGui::MenuItem("Follow UDP Stream", nullptr, false, isStream && sel->ip_protocol == 17)) startFollow(state, state.selectedPacket);
            ImGui::Separator();
            if (ImGui::MenuItem("Decode As...")) state.decodeAs.open = true;
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
            if (ImGui::MenuItem("Toolbar", nullptr, state.settings.showToolbar)) {
                state.settings.showToolbar = !state.settings.showToolbar;
                state.settingsDirty = true;
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

    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_W, false) && !state.currentFile.empty()) requestClose(state);
    handleCaptureShortcuts(state);

    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O, false)) {
        openCaptureDialog();
    }

    if (ImGuiFileDialog::Instance()->Display("ChooseFileDlgKey")) {
        if (ImGuiFileDialog::Instance()->IsOk()) {
            requestOpen(state, ImGuiFileDialog::Instance()->GetFilePathName());
        }
        ImGuiFileDialog::Instance()->Close();
    }
}

ui::StatusSegments ui::statusSegments(const AppState &state) {
    StatusSegments seg;
    if (state.loading()) {
        seg.left = "Loading " + loadingPath(state) + " ...";
    } else if (state.live.session) {
        seg.left = captureStatusText(state);
        const auto cut = seg.left.find("  |  Displayed:"); // shown in its own segment
        if (cut != std::string::npos) seg.left.resize(cut);
    } else if (state.currentFile.empty()) {
        seg.left = "No file loaded. Use File > Open.";
    } else {
        const auto name = core::pathFromUtf8(state.displayName).filename().u8string();
        seg.left.assign(name.begin(), name.end());
        if (seg.left.empty()) seg.left = state.displayName;
        seg.leftTooltip = state.displayName;
    }
    if (!state.loading() && (state.live.session || !state.currentFile.empty())) {
        seg.displayed = "Displayed: " + std::to_string(state.displayedCount()) + " / " + std::to_string(state.packets.size());
        if (const packet::PacketInfo *sel = state.currentPacket()) seg.selected = "Selected: #" + std::to_string(sel->number);
        if (state.filter.active) seg.filter = state.filter.appliedText;
    }
    seg.error = state.live.error;
    seg.message = state.loadMessage;
    return seg;
}

ui::ToolbarEnabled ui::toolbarEnabled(const AppState &state) {
    const auto &l = state.live;
    const bool available = capture::liveCaptureAvailable();
    ToolbarEnabled e;
    e.open = true;
    e.close = !state.currentFile.empty();
    e.reload = !state.displayName.empty() && !l.session && !state.loading();
    e.start = available && !l.capturing();
    e.stop = available && l.capturing();
    e.restart = available && l.session && !l.injected;
    e.find = !state.packets.empty();
    e.statistics = !state.packets.empty();
    return e;
}

void ui::drawStatusBar(const AppState &state) {
    const ImVec2 display = ImGui::GetIO().DisplaySize;
    ImGui::SetNextWindowPos(ImVec2(0, display.y - statusBarHeight()));
    ImGui::SetNextWindowSize(ImVec2(display.x, statusBarHeight()));
    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoDecoration | ImGuiWindowFlags_NoMove |
                                   ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoBringToFrontOnFocus;
    if (ImGui::Begin("##status", nullptr, flags)) {
        const StatusSegments seg = statusSegments(state);
        const ImVec4 red(1.0f, 0.4f, 0.4f, 1.0f);
        const ImVec4 amber(1.0f, 0.8f, 0.3f, 1.0f);
        auto separator = [] {
            ImGui::SameLine();
            ImGui::TextDisabled("|");
            ImGui::SameLine();
        };
        ImGui::TextUnformatted(seg.left.c_str());
        if (!seg.leftTooltip.empty() && ImGui::IsItemHovered()) ImGui::SetTooltip("%s", seg.leftTooltip.c_str());
        if (!seg.displayed.empty()) {
            separator();
            ImGui::TextUnformatted(seg.displayed.c_str());
        }
        if (!seg.selected.empty()) {
            separator();
            ImGui::TextUnformatted(seg.selected.c_str());
        }
        if (!seg.filter.empty()) {
            separator();
            constexpr size_t kMaxFilterChars = 60;
            std::string shown = seg.filter;
            if (shown.size() > kMaxFilterChars) {
                shown.resize(kMaxFilterChars);
                while (!shown.empty() && (static_cast<unsigned char>(shown.back()) & 0xC0) == 0x80) shown.pop_back(); // keep UTF-8 intact
                if (!shown.empty() && static_cast<unsigned char>(shown.back()) >= 0xC0) shown.pop_back();
                shown += "...";
            }
            ImGui::Text("Filter: %s", shown.c_str());
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", seg.filter.c_str());
        }
        // Problems on the right edge
        const float gap = ImGui::GetStyle().ItemSpacing.x;
        float width = 0;
        if (!seg.error.empty()) width += ImGui::CalcTextSize(seg.error.c_str()).x;
        if (!seg.message.empty()) width += ImGui::CalcTextSize(seg.message.c_str()).x;
        if (!seg.error.empty() && !seg.message.empty()) width += 2 * gap + ImGui::CalcTextSize("|").x;
        if (width > 0) {
            ImGui::SameLine(std::max(ImGui::GetCursorPosX() + gap, ImGui::GetWindowContentRegionMax().x - width));
            if (!seg.error.empty()) {
                ImGui::TextColored(red, "%s", seg.error.c_str());
                if (!seg.message.empty()) separator();
            }
            if (!seg.message.empty()) ImGui::TextColored(state.loadFailed ? red : amber, "%s", seg.message.c_str());
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
