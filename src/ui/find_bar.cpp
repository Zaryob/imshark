#include "ui.h"

#include <algorithm>

#include <imgui.h>

#include "text_input.h"

bool ui::findAndSelect(AppState &state, bool forward) {
    auto &f = state.find;
    if (state.order.empty() && state.orderDirty) {
        // the list has not been laid out yet (e.g. right after loading): use the natural order
        state.order = state.filter.active ? state.filter.visible : std::vector<uint32_t>();
        if (!state.filter.active) {
            state.order.resize(state.packets.size());
            for (size_t i = 0; i < state.order.size(); ++i) state.order[i] = static_cast<uint32_t>(i);
        }
    }

    int from = -1;
    if (state.selectedPacket >= 0) {
        const auto it = std::find(state.order.begin(), state.order.end(), static_cast<uint32_t>(state.selectedPacket));
        if (it != state.order.end()) from = static_cast<int>(it - state.order.begin());
    }

    const FindResult r = findPacket(state.packets, state.order, state.captureStartEpoch, f.mode, f.text, from, forward);
    f.messageIsError = !r.error.empty();
    if (!r.error.empty()) {
        f.message = r.error;
        return false;
    }
    if (r.position < 0) {
        f.message = f.text.empty() ? "" : "No match";
        f.messageIsError = !f.text.empty();
        return false;
    }

    const int packetIndex = static_cast<int>(state.order[r.position]);
    state.selectPacket(packetIndex);
    state.scrollToSelection = true;
    f.message = "Packet " + std::to_string(state.packets[packetIndex].number) + "  (row " + std::to_string(r.position + 1) +
                " of " + std::to_string(state.order.size()) + ")";
    return true;
}

void ui::drawFindBar(AppState &state) {
    auto &f = state.find;
    const ImGuiIO &io = ImGui::GetIO();

    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F, false)) {
        f.open = true;
        f.focusRequested = true;
    }
    // F3 / Shift+F3 repeat the last search even while the bar is closed
    if (ImGui::IsKeyPressed(ImGuiKey_F3) && !f.text.empty() && !state.packets.empty()) findAndSelect(state, !io.KeyShift);
    if (!f.open) return;
    if (ImGui::IsKeyPressed(ImGuiKey_Escape) && !ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopupId)) {
        f.open = false;
        return;
    }

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Find:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140);
    int mode = static_cast<int>(f.mode);
    if (ImGui::Combo("##findmode", &mode, "Text in summary\0Display filter\0")) f.mode = static_cast<FindMode>(mode);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(std::max(120.0f, ImGui::GetContentRegionAvail().x - 210));
    if (f.focusRequested) {
        ImGui::SetKeyboardFocusHere();
        f.focusRequested = false;
    }
    const bool enter = inputText("##findtext", f.mode == FindMode::Text ? "text in source, destination, protocol or info"
                                                                          : "display filter, e.g. tcp.flags.rst",
                                 f.text, ImGuiInputTextFlags_EnterReturnsTrue);
    if (enter) {
        findAndSelect(state, !io.KeyShift);
        f.focusRequested = true; // keep typing / pressing Enter
    }
    ImGui::SameLine();
    if (ImGui::Button("Prev")) findAndSelect(state, false);
    ImGui::SameLine();
    if (ImGui::Button("Next")) findAndSelect(state, true);
    ImGui::SameLine();
    if (ImGui::Button("Close")) f.open = false;

    if (!f.message.empty()) {
        ImGui::TextColored(f.messageIsError ? ImVec4(1.0f, 0.45f, 0.45f, 1.0f) : ImVec4(0.6f, 0.9f, 0.6f, 1.0f), "%s", f.message.c_str());
    }
}
