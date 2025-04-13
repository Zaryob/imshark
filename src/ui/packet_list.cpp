#include "ui.h"

#include <string>

#include <imgui.h>

void ui::drawPacketList(AppState &state, float height) {
    ImGui::BeginChild("Packet List", ImVec2(0, height), true);
    if (ImGui::BeginTable("Packets", 7,
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                              ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("No.");
        ImGui::TableSetupColumn("Time");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Destination");
        ImGui::TableSetupColumn("Protocol");
        ImGui::TableSetupColumn("Length");
        ImGui::TableSetupColumn("Info");
        ImGui::TableHeadersRow();

        // Only the visible rows are laid out, so huge captures stay responsive.
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(state.packets.size()));
        while (clipper.Step()) {
            for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                const auto &packet = state.packets[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                if (ImGui::Selectable(std::to_string(packet.number).c_str(), state.selectedPacket == i,
                                      ImGuiSelectableFlags_SpanAllColumns)) {
                    if (state.selectedPacket != i) {
                        state.selectedPacket = i;
                        state.selectedField = nullptr;
                        state.selectionStart = state.selectionEnd = -1;
                    }
                }
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%.6f", packet.time);
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(packet.source.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::TextUnformatted(packet.destination.c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::TextUnformatted(packet.protocol.c_str());
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("%u", packet.length);
                ImGui::TableSetColumnIndex(6);
                ImGui::TextUnformatted(packet.info.c_str());
            }
        }
        ImGui::EndTable();
    }
    ImGui::EndChild();
}
