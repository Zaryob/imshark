#include "ui.h"

#include <cstdio>

#include <imgui.h>

namespace {
    using packet::Field;

    bool containsField(const Field &root, const Field *target) {
        if (&root == target) return true;
        for (const auto &c: root.children) {
            if (containsField(c, target)) return true;
        }
        return false;
    }

    // Deepest field that covers `byte` (children are more specific than their parents).
    const Field *deepestFieldAt(const Field &f, size_t byte) {
        if (!f.contains(byte)) {
            // Containers like "Frame" / "Options" may have child ranges outside their own; still look inside.
            for (const auto &c: f.children) {
                if (auto r = deepestFieldAt(c, byte)) return r;
            }
            return nullptr;
        }
        for (const auto &c: f.children) {
            if (auto r = deepestFieldAt(c, byte)) return r;
        }
        return &f;
    }

    void selectField(ui::AppState &state, const Field &f) {
        state.selectedField = &f;
        if (f.length > 0) {
            state.selectionStart = static_cast<int>(f.offset);
            state.selectionEnd = static_cast<int>(f.offset + f.length) - 1;
        } else {
            state.selectionStart = state.selectionEnd = -1;
        }
    }

    void drawField(ui::AppState &state, const Field &f, bool topLevel) {
        const bool leaf = f.children.empty();
        ImGuiTreeNodeFlags flags = ImGuiTreeNodeFlags_OpenOnArrow | ImGuiTreeNodeFlags_SpanAvailWidth;
        if (leaf) flags |= ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen;
        if (state.selectedField == &f) flags |= ImGuiTreeNodeFlags_Selected;

        if (!leaf) {
            if (state.revealSelectedField && state.selectedField && containsField(f, state.selectedField) &&
                state.selectedField != &f) {
                ImGui::SetNextItemOpen(true);
            } else if (topLevel) {
                ImGui::SetNextItemOpen(true, ImGuiCond_Once);
            }
        }

        const bool open = ImGui::TreeNodeEx(static_cast<const void *>(&f), flags, "%s", f.text.c_str());
        if (state.revealSelectedField && state.selectedField == &f) ImGui::SetScrollHereY();
        if (ImGui::IsItemClicked()) selectField(state, f);

        if (!leaf && open) {
            for (const auto &c: f.children) drawField(state, c, false);
            ImGui::TreePop();
        }
    }

    void drawHexView(ui::AppState &state, const packet::PacketInfo &packet) {
        constexpr int kBytesPerRow = 16;
        const auto &data = packet.raw_data;
        const int size = static_cast<int>(data.size());
        const int rows = (size + kBytesPerRow - 1) / kBytesPerRow;

        const float cellW = ImGui::CalcTextSize("00").x + ImGui::GetStyle().ItemSpacing.x;
        const float charW = ImGui::CalcTextSize("M").x;

        ImGui::BeginChild("HexView", ImVec2(0, 0), true);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(4, 1));

        ImGui::TextDisabled("Offset ");
        for (int col = 0; col < kBytesPerRow; ++col) {
            ImGui::SameLine();
            ImGui::TextDisabled("%02X", col);
        }

        ImGuiListClipper clipper;
        clipper.Begin(rows);
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                ImGui::TextDisabled("%06X ", row * kBytesPerRow);

                for (int col = 0; col < kBytesPerRow; ++col) {
                    ImGui::SameLine();
                    const int index = row * kBytesPerRow + col;
                    if (index >= size) {
                        ImGui::Dummy(ImVec2(cellW - 4, 1));
                        continue;
                    }
                    char text[3];
                    snprintf(text, sizeof(text), "%02X", static_cast<unsigned char>(data[index]));
                    ImGui::PushID(index);
                    if (ImGui::Selectable(text, state.isSelected(index), 0, ImVec2(cellW - 4, 0))) {
                        // Clicking a byte selects the most specific field it belongs to (and reveals it in the tree)
                        const Field *field = nullptr;
                        for (const auto &layer: packet.fields) {
                            // skip the "Frame" summary, which covers every byte
                            if (&layer == &packet.fields.front()) continue;
                            if ((field = deepestFieldAt(layer, index))) break;
                        }
                        if (field) {
                            selectField(state, *field);
                            state.revealSelectedField = true;
                        } else {
                            state.selectedField = nullptr;
                            state.selectionStart = state.selectionEnd = index;
                        }
                    }
                    ImGui::PopID();
                }

                // ASCII column
                ImGui::SameLine(0, charW * 2);
                for (int col = 0; col < kBytesPerRow; ++col) {
                    const int index = row * kBytesPerRow + col;
                    if (index >= size) break;
                    const unsigned char c = static_cast<unsigned char>(data[index]);
                    char text[2] = {(c >= 32 && c < 127) ? static_cast<char>(c) : '.', 0};
                    ImGui::PushID(index + 0x100000);
                    if (col > 0) ImGui::SameLine(0, 0);
                    if (ImGui::Selectable(text, state.isSelected(index), 0, ImVec2(charW, 0))) {
                        state.selectedField = nullptr;
                        state.selectionStart = state.selectionEnd = index;
                    }
                    ImGui::PopID();
                }
            }
        }

        ImGui::PopStyleVar();
        ImGui::EndChild();
    }
} // namespace

void ui::drawPacketDetails(AppState &state) {
    const packet::PacketInfo *packet = state.currentPacket();
    if (!packet) return;

    const float available = ImGui::GetContentRegionAvail().y;

    ImGui::BeginChild("Packet Tree", ImVec2(0, available * 0.5f), true);
    ImGui::TextWrapped("%s", packet->info.c_str());
    ImGui::Separator();
    for (const auto &layer: packet->fields) drawField(state, layer, true);
    ImGui::EndChild();
    state.revealSelectedField = false;

    if (!packet->raw_data.empty()) drawHexView(state, *packet);
}
