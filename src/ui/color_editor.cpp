#include "ui.h"

#include <algorithm>
#include <cfloat>
#include <cmath>

#include <imgui.h>

#include "text_input.h"

namespace {
    ImVec4 toColor(uint32_t rgb) {
        return ImVec4(((rgb >> 16) & 0xFF) / 255.0f, ((rgb >> 8) & 0xFF) / 255.0f, (rgb & 0xFF) / 255.0f, 1.0f);
    }

    uint32_t fromColor(const float c[3]) {
        auto byte = [](float v) { return static_cast<uint32_t>(std::lround(std::max(0.0f, std::min(1.0f, v)) * 255.0f)); };
        return (byte(c[0]) << 16) | (byte(c[1]) << 8) | byte(c[2]);
    }

    bool colorButton(const char *id, uint32_t &rgb) {
        ImVec4 c = toColor(rgb);
        float f[3] = {c.x, c.y, c.z};
        if (ImGui::ColorEdit3(id, f, ImGuiColorEditFlags_NoInputs | ImGuiColorEditFlags_NoLabel)) {
            rgb = fromColor(f);
            return true;
        }
        return false;
    }
} // namespace

void ui::recompileColorRules(AppState &state) {
    state.colors = CompiledColorRules(state.settings.colorRules.empty() ? defaultColorRules() : state.settings.colorRules);
}

void ui::drawColorRulesWindow(AppState &state) {
    if (!state.showColorRules) { state.colorRulesWereOpen = false; return; }
    if (!state.colorRulesWereOpen) { // just opened: start from the rules in effect
        state.colorRuleEdit = state.settings.colorRules.empty() ? defaultColorRules() : state.settings.colorRules;
        state.colorRulesWereOpen = true;
    }

    ImGui::SetNextWindowSize(ImVec2(820, 380), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Coloring Rules", &state.showColorRules)) {
        ImGui::TextWrapped("The first enabled rule whose display filter matches colors the row. Rules are checked top to bottom.");
        auto &rules = state.colorRuleEdit;
        int remove = -1, moveUp = -1, moveDown = -1;

        if (ImGui::BeginTable("rules", 7, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_ScrollY,
                              ImVec2(0, ImGui::GetContentRegionAvail().y - ImGui::GetFrameHeightWithSpacing() * 2))) {
            ImGui::TableSetupColumn("On", ImGuiTableColumnFlags_WidthFixed, 30);
            ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 150);
            ImGui::TableSetupColumn("Display filter", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Back", ImGuiTableColumnFlags_WidthFixed, 40);
            ImGui::TableSetupColumn("Text", ImGuiTableColumnFlags_WidthFixed, 40);
            ImGui::TableSetupColumn("Order", ImGuiTableColumnFlags_WidthFixed, 70);
            ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 30);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();
            for (size_t i = 0; i < rules.size(); ++i) {
                auto &r = rules[i];
                ImGui::PushID(static_cast<int>(i));
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Checkbox("##on", &r.enabled);
                ImGui::TableSetColumnIndex(1);
                ImGui::SetNextItemWidth(-FLT_MIN);
                inputText("##name", "name", r.name);
                ImGui::TableSetColumnIndex(2);
                const bool ok = filter::Filter::compile(r.expression).ok;
                if (!ok) ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.45f, 0.12f, 0.12f, 1.0f));
                ImGui::SetNextItemWidth(-FLT_MIN);
                inputText("##expr", "display filter", r.expression);
                if (!ok) ImGui::PopStyleColor();
                ImGui::TableSetColumnIndex(3);
                colorButton("##bg", r.background);
                ImGui::TableSetColumnIndex(4);
                colorButton("##fg", r.foreground);
                ImGui::TableSetColumnIndex(5);
                if (ImGui::SmallButton("Up") && i > 0) moveUp = static_cast<int>(i);
                ImGui::SameLine();
                if (ImGui::SmallButton("Dn") && i + 1 < rules.size()) moveDown = static_cast<int>(i);
                ImGui::TableSetColumnIndex(6);
                if (ImGui::SmallButton("X")) remove = static_cast<int>(i);
                ImGui::PopID();
            }
            ImGui::EndTable();
        }
        if (remove >= 0) rules.erase(rules.begin() + remove);
        if (moveUp >= 0) std::swap(rules[moveUp], rules[moveUp - 1]);
        if (moveDown >= 0) std::swap(rules[moveDown], rules[moveDown + 1]);

        if (ImGui::Button("New")) rules.push_back(ColorRule{true, "New rule", "", 0xFFF2B3, 0x12272E});
        ImGui::SameLine();
        if (ImGui::Button("Reset to Defaults")) rules = defaultColorRules();
        ImGui::SameLine();
        if (ImGui::Button("Apply")) {
            // the defaults are stored as "no customisation" so that future default changes still reach the user
            state.settings.colorRules = (rules == defaultColorRules()) ? std::vector<ColorRule>() : rules;
            state.settingsDirty = true;
            recompileColorRules(state);
        }
        const auto &problems = state.colors.problems();
        for (const auto &p: problems) ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", p.c_str());
    }
    ImGui::End();
}
