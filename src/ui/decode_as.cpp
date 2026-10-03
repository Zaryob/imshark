#include "ui.h"

#include <algorithm>

#include <imgui.h>

std::shared_ptr<const dissect::Registry> ui::buildRegistry(const std::vector<DecodeAsRule> &rules, std::string &error) {
    error.clear();
    auto registry = std::make_shared<dissect::Registry>(dissect::Registry::builtin());
    for (const auto &r: rules) {
        std::string why;
        if (r.port < 1 || r.port > 65535) {
            error = "Port " + std::to_string(r.port) + " is not between 1 and 65535";
            return nullptr;
        }
        if (!registry->decodeAs(r.tcp, static_cast<uint16_t>(r.port), r.protocol, &why)) {
            error = why;
            return nullptr;
        }
    }
    return registry;
}

bool ui::applyDecodeAs(AppState &state, const std::vector<DecodeAsRule> &rules) {
    std::string error;
    auto registry = buildRegistry(rules, error);
    state.decodeAs.error = error;
    if (!registry) return false;
    state.decodeAs.rules = rules;
    state.registry = rules.empty() ? nullptr : std::move(registry);
    if (!state.displayName.empty()) startLoad(state, state.displayName);   // the summaries depend on the dissectors: load again
    return true;
}

void ui::drawDecodeAsWindow(AppState &state) {
    auto &d = state.decodeAs;
    if (!d.open) { d.wasOpen = false; return; }
    if (!d.wasOpen) { d.edit = d.rules; d.error.clear(); d.wasOpen = true; }

    ImGui::SetNextWindowSize(ImVec2(520, 300), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Decode As", &d.open)) {
        ImGui::TextWrapped("Decode the traffic of a port with another protocol. Changing the rules loads the capture again.");
        const auto &builtin = dissect::Registry::builtin();
        int remove = -1;
        if (ImGui::BeginTable("rules", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) {
            ImGui::TableSetupColumn("Transport", ImGuiTableColumnFlags_WidthFixed, 90);
            ImGui::TableSetupColumn("Port", ImGuiTableColumnFlags_WidthFixed, 110);
            ImGui::TableSetupColumn("Decode as");
            ImGui::TableSetupColumn("##remove", ImGuiTableColumnFlags_WidthFixed, 30);
            ImGui::TableHeadersRow();
            for (size_t i = 0; i < d.edit.size(); ++i) {
                auto &r = d.edit[i];
                ImGui::PushID(static_cast<int>(i));
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                int transport = r.tcp ? 0 : 1;
                ImGui::SetNextItemWidth(-1);
                if (ImGui::Combo("##transport", &transport, "TCP\0UDP\0")) { r.tcp = transport == 0; r.protocol.clear(); }
                ImGui::TableNextColumn();
                ImGui::SetNextItemWidth(-1);
                ImGui::InputInt("##port", &r.port, 0, 0);
                r.port = std::max(0, std::min(r.port, 65535));
                ImGui::TableNextColumn();
                const auto names = builtin.protocolNames(r.tcp);
                ImGui::SetNextItemWidth(-1);
                if (ImGui::BeginCombo("##protocol", r.protocol.empty() ? "(choose)" : r.protocol.c_str())) {
                    for (const auto &n: names) if (ImGui::Selectable(n.c_str(), n == r.protocol)) r.protocol = n;
                    ImGui::EndCombo();
                }
                ImGui::TableNextColumn();
                if (ImGui::SmallButton("x")) remove = static_cast<int>(i);
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        if (remove >= 0) d.edit.erase(d.edit.begin() + remove);
        if (ImGui::Button("Add rule")) d.edit.push_back({true, 8080, "HTTP"});
        ImGui::SameLine();
        const bool changed = !(d.edit == d.rules);
        if (!changed) ImGui::BeginDisabled();
        if (ImGui::Button("Apply")) applyDecodeAs(state, d.edit);
        if (!changed) ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Revert")) { d.edit = d.rules; d.error.clear(); }
        if (!d.error.empty()) ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", d.error.c_str());
    }
    ImGui::End();
}
