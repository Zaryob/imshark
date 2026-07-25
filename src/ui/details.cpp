#include "ui.h"

#include <cstdio>

#include <imgui.h>

#include <core.h>

#include "clipboard.h"

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
        if (ImGui::IsItemClicked(ImGuiMouseButton_Left) || ImGui::IsItemClicked(ImGuiMouseButton_Right)) selectField(state, f);
        if (ImGui::BeginPopupContextItem()) {
            const auto &raw = state.detail.raw_data;
            if (ImGui::MenuItem("Copy")) ImGui::SetClipboardText(f.text.c_str());
            if (ImGui::MenuItem("Copy Value")) ImGui::SetClipboardText(ui::fieldValue(f).c_str());
            if (f.length > 0) {
                if (ImGui::MenuItem("Copy Bytes as Hex")) ImGui::SetClipboardText(ui::bytesToHex(raw, f.offset, f.length).c_str());
                if (ImGui::MenuItem("Copy Bytes as ASCII")) ImGui::SetClipboardText(ui::bytesToAscii(raw, f.offset, f.length).c_str());
            }
            ImGui::EndPopup();
        }

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

        // Right click (or Ctrl+C while hovering) copies the highlighted bytes
        const bool hasSel = state.hasSelection();
        const size_t selLen = hasSel ? static_cast<size_t>(state.selectionEnd - state.selectionStart + 1) : 0;
        const size_t selOff = hasSel ? static_cast<size_t>(state.selectionStart) : 0;
        if (hasSel && ImGui::IsWindowHovered() && ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_C, false)) {
            ImGui::SetClipboardText(ui::bytesToHex(data, selOff, selLen).c_str());
        }
        if (ImGui::BeginPopupContextWindow("hexcopy")) {
            if (ImGui::MenuItem("Copy Selection as Hex", nullptr, false, hasSel)) ImGui::SetClipboardText(ui::bytesToHex(data, selOff, selLen).c_str());
            if (ImGui::MenuItem("Copy Selection as ASCII", nullptr, false, hasSel)) ImGui::SetClipboardText(ui::bytesToAscii(data, selOff, selLen).c_str());
            if (ImGui::MenuItem("Copy All as Hex Dump")) ImGui::SetClipboardText(ui::hexDump(data).c_str());
            ImGui::EndPopup();
        }
        ImGui::EndChild();
    }
} // namespace

bool ui::ensureDetail(AppState &state) {
    const packet::PacketInfo *summary = state.currentPacket();
    if (!summary) return false;
    if (state.detailIndex == state.selectedPacket) return state.detailOk;

    state.detailIndex = state.selectedPacket;
    state.selectedField = nullptr; // pointed into the previous detail
    state.detailOk = core::buildPacketDetails(state.currentFile, *summary, state.detail, &state.packets, &state.captureInfo);
    if (!state.detailOk) state.detail = *summary; // keep the summary columns, no bytes/fields
    return state.detailOk;
}

void ui::drawPacketDetails(AppState &state) {
    if (!state.currentPacket()) return;
    const bool ok = ensureDetail(state);
    const packet::PacketInfo &packet = state.detail;

    const float available = ImGui::GetContentRegionAvail().y;

    ImGui::BeginChild("Packet Tree", ImVec2(0, available * 0.5f), true);
    ImGui::TextWrapped("%s", packet.info.c_str());
    ImGui::Separator();
    if (!ok) {
        ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "Could not read this packet from %s (moved or modified?)",
                           state.currentFile.c_str());
    }
    for (const auto &layer: packet.fields) drawField(state, layer, true);
    ImGui::EndChild();
    state.revealSelectedField = false;

    if (!packet.raw_data.empty()) drawHexView(state, packet);
}
