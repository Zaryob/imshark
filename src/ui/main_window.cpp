#include "ui.h"
#include "theme.h"

#include <algorithm>
#include <filesystem>

#include <imgui.h>

#include <capture/live_capture.h>
#include <core.h>

namespace {
    /// A toolbar button; the tooltip also appears while it is disabled and names the keyboard shortcut.
    bool toolbarButton(const char *label, bool enabled, const char *tip) {
        ImGui::BeginDisabled(!enabled);
        const bool pressed = ImGui::Button(label);
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) ImGui::SetTooltip("%s", tip);
        return pressed;
    }
} // namespace

bool ui::welcomeVisible(const AppState &state) {
    return state.currentFile.empty() && state.packets.empty() && !state.loading() && !state.live.session;
}

void ui::drawToolbar(AppState &state) {
    const ToolbarEnabled e = toolbarEnabled(state);
    const std::string unavailable = captureUnavailableReason();
    auto captureTip = [&](const char *text) { return unavailable.empty() ? std::string(text) : unavailable; };

    if (toolbarButton("Open", e.open, "Open a capture file (Ctrl+O)")) openCaptureDialog();
    ImGui::SameLine();
    if (toolbarButton("Close", e.close, "Close the capture file (Ctrl+W)")) requestClose(state);
    ImGui::SameLine();
    if (toolbarButton("Reload", e.reload, "Load the capture file again")) startLoad(state, state.displayName);
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    if (toolbarButton("Start", e.start, captureTip("Start a live capture (Ctrl+E)").c_str())) requestStartCapture(state);
    ImGui::SameLine();
    if (toolbarButton("Stop", e.stop, captureTip("Stop the live capture (Ctrl+E)").c_str())) stopCapture(state);
    ImGui::SameLine();
    if (toolbarButton("Restart", e.restart, captureTip("Restart the live capture (Ctrl+R)").c_str())) requestRestartCapture(state);
    ImGui::SameLine();
    ImGui::TextDisabled("|");
    ImGui::SameLine();
    if (toolbarButton("Find", e.find, "Find a packet (Ctrl+F)")) {
        state.find.open = true;
        state.find.focusRequested = true;
    }
    ImGui::SameLine();
    if (toolbarButton("Statistics", e.statistics, "Protocol hierarchy, conversations, endpoints and expert information (Statistics menu)")) {
        ImGui::OpenPopup("##toolbar_stats");
    }
    if (ImGui::BeginPopup("##toolbar_stats")) {
        ImGui::MenuItem("Expert Information", nullptr, &state.stats.showExpert);
        ImGui::MenuItem("Protocol Hierarchy", nullptr, &state.stats.showHierarchy);
        ImGui::MenuItem("Conversations", nullptr, &state.stats.showConversations);
        ImGui::MenuItem("Endpoints", nullptr, &state.stats.showEndpoints);
        ImGui::EndPopup();
    }
    ImGui::Separator();
}

void ui::drawWelcome(AppState &state) {
    const ImVec2 avail = ImGui::GetContentRegionAvail();
    const float width = std::min(avail.x, ImGui::GetFontSize() * 30.0f);
    const float left = std::max(0.0f, (avail.x - width) * 0.5f);
    const float top = std::max(0.0f, (avail.y - ImGui::GetFontSize() * 18.0f) * 0.35f);
    ImGui::SetCursorPos(ImVec2(ImGui::GetCursorPosX() + left, ImGui::GetCursorPosY() + top));
    ImGui::BeginGroup();
    ImGui::SetWindowFontScale(2.0f);
    ImGui::TextUnformatted("ImShark");
    ImGui::SetWindowFontScale(1.0f);
    ImGui::TextDisabled("A packet analyzer for capture files and live traffic");
    ImGui::Spacing();
    ImGui::Spacing();

    // Both buttons as wide as the longer label, so neither is clipped at any font size
    const ImVec2 button(ImGui::CalcTextSize("Start live capture...").x + 2 * ImGui::GetStyle().FramePadding.x, 0);
    if (ImGui::Button("Open capture...", button)) openCaptureDialog();
    if (capture::liveCaptureAvailable()) {
        ImGui::SameLine();
        if (ImGui::Button("Start live capture...", button)) requestStartCapture(state);
    }
    ImGui::Spacing();
    ImGui::TextDisabled("or drop a .pcap/.pcapng file anywhere on the window");

    if (!state.settings.recentFiles.empty()) {
        ImGui::Spacing();
        ImGui::Spacing();
        ImGui::TextUnformatted("Recent files");
        // A rule as wide as the panel (Separator would run to the window edge from inside the centred group)
        const ImVec2 at = ImGui::GetCursorScreenPos();
        ImGui::GetWindowDrawList()->AddLine(at, ImVec2(at.x + width, at.y), ImGui::GetColorU32(ImGuiCol_Separator));
        ImGui::Dummy(ImVec2(width, ImGui::GetStyle().ItemSpacing.y));
        std::string chosen;
        for (const auto &recent: state.settings.recentFiles) {
            const std::filesystem::path path = core::pathFromUtf8(recent);
            const auto name = path.filename().u8string();
            const auto dir = path.parent_path().u8string();
            ImGui::PushID(recent.c_str()); // captures in different directories may have the same filename
            if (ImGui::Selectable(reinterpret_cast<const char *>(name.c_str()))) chosen = recent;
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("%s", recent.c_str());
            ImGui::SameLine();
            ImGui::TextDisabled("%s", reinterpret_cast<const char *>(dir.c_str()));
            ImGui::PopID();
        }
        if (!chosen.empty()) requestOpen(state, chosen);
    }
    ImGui::EndGroup();
}

void ui::drawMainWindow(AppState &state) {
    // Fill the area between the menu bar and the status bar
    const float menuHeight = ImGui::GetFrameHeight();
    ImVec2 size = ImGui::GetIO().DisplaySize;
    size.y -= menuHeight + statusBarHeight();
    ImGui::SetNextWindowPos(ImVec2(0, menuHeight));
    ImGui::SetNextWindowSize(size);

    const ImGuiWindowFlags flags = ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoCollapse |
                                   ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoSavedSettings;
    if (ImGui::Begin("ImShark", nullptr, flags)) {
        if (state.settings.showToolbar) drawToolbar(state);
        if (welcomeVisible(state)) {
            drawWelcome(state);
            ImGui::End();
            drawOtherWindows(state);
            return;
        }
        drawFilterBar(state);
        drawFindBar(state);
        const float available = ImGui::GetContentRegionAvail().y;
        const float splitter = 6.0f;

        if (!state.currentPacket()) {
            drawPacketList(state, available);
        } else {
            state.listHeight = std::max(100.0f, std::min(state.listHeight, available - 100.0f - splitter));
            drawPacketList(state, state.listHeight);

            // Draggable splitter between the list and the details
            ImGui::InvisibleButton("##splitter", ImVec2(-1, splitter));
            if (ImGui::IsItemActive()) state.listHeight += ImGui::GetIO().MouseDelta.y;
            drawSplitterLine();

            drawPacketDetails(state);
        }
    }
    ImGui::End();
    drawOtherWindows(state);
}

void ui::drawOtherWindows(AppState &state) {
    drawFilterHelp(state);
    drawColorRulesWindow(state);
    drawStatsWindows(state);
    drawDecodeAsWindow(state);
    drawPreferencesWindow(state);
    drawFollowWindow(state);
    drawExportDialog(state);
    drawCaptureInfoWindow(state);
    drawCaptureDialogs(state);
}
