#include "ui.h"

#include <algorithm>

#include <imgui.h>

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
        drawFilterBar(state);
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
            if (ImGui::IsItemHovered() || ImGui::IsItemActive()) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);

            drawPacketDetails(state);
        }
    }
    ImGui::End();
    drawFilterHelp(state);
    drawColorRulesWindow(state);
}
