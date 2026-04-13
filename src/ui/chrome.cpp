#include "ui.h"

#include <cstdlib>

#include <imgui.h>

#include <ImGuiFileDialog.h>

float ui::statusBarHeight() { return ImGui::GetFrameHeight() + 2 * ImGui::GetStyle().WindowPadding.y; }

void ui::drawMenuAndDialogs(AppState &state) {
    if (ImGui::BeginMainMenuBar()) {
        if (ImGui::BeginMenu("File")) {
            if (ImGui::MenuItem("Open...", "Ctrl+O")) {
                ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Choose File", ".pcapng,.pcap,");
            }
            if (ImGui::MenuItem("Close File", nullptr, false, !state.currentFile.empty())) {
                state.packets.clear();
                state.clearSelection();
                state.currentFile.clear();
                state.loadMessage.clear();
                state.loadFailed = false;
            }
            if (ImGui::MenuItem("Exit")) std::exit(0);
            ImGui::EndMenu();
        }
        ImGui::EndMainMenuBar();
    }

    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_O, false)) {
        ImGuiFileDialog::Instance()->OpenDialog("ChooseFileDlgKey", "Choose File", ".pcapng,.pcap,");
    }

    if (ImGuiFileDialog::Instance()->Display("ChooseFileDlgKey")) {
        if (ImGuiFileDialog::Instance()->IsOk()) {
            loadCapture(state, ImGuiFileDialog::Instance()->GetFilePathName());
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
        if (state.currentFile.empty()) {
            ImGui::TextUnformatted("No file loaded. Use File > Open.");
        } else {
            ImGui::Text("%s  |  %zu packets", state.currentFile.c_str(), state.packets.size());
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
