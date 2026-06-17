#include "ui.h"

#include <algorithm>

#include <imgui.h>

#include "text_input.h"

bool ui::applyFilter(AppState &state, const std::string &text) {
    auto &f = state.filter;
    auto result = filter::Filter::compile(text);
    f.text = text;
    f.previewText = text;
    f.previewOk = result.ok;
    f.previewError = result.error;
    if (!result.ok) return false;

    f.applied = result.filter;
    f.appliedText = text;
    f.active = !result.filter.isEmpty();
    if (f.active) {
        addFilterHistory(state.settings, text);
        state.settingsDirty = true;
    }
    refilter(state);
    return true;
}

void ui::refilter(AppState &state) {
    auto &f = state.filter;
    f.visible.clear();
    if (f.active) {
        filter::Context context;
        context.captureStartEpoch = state.captureStartEpoch;
        for (size_t i = 0; i < state.packets.size(); ++i) {
            context.previous = i ? &state.packets[i - 1] : nullptr;
            if (f.applied.matches(state.packets[i], context)) f.visible.push_back(static_cast<uint32_t>(i));
        }
        // the selected packet stays selected only if it is still displayed
        if (state.selectedPacket >= 0 &&
            !std::binary_search(f.visible.begin(), f.visible.end(), static_cast<uint32_t>(state.selectedPacket))) {
            state.clearSelection();
        }
    }
    state.orderDirty = true;
    state.stats.dirty = true; // statistics "limited to displayed packets" depend on the filter
}

void ui::drawFilterBar(AppState &state) {
    auto &f = state.filter;

    // validate what is typed, but only when it changed
    if (f.text != f.previewText) {
        auto r = filter::Filter::compile(f.text);
        f.previewOk = r.ok;
        f.previewError = r.error;
        f.previewText = f.text;
    }
    if (ImGui::GetIO().KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_L, false)) f.focusRequested = true;

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Filter:");
    ImGui::SameLine();

    const bool isApplied = f.active && f.text == f.appliedText;
    int colors = 0;
    if (!f.previewOk) {
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.45f, 0.12f, 0.12f, 1.0f));
        ++colors;
    } else if (isApplied) {
        ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.12f, 0.35f, 0.15f, 1.0f));
        ++colors;
    }

    const float buttons = 3 * (ImGui::GetFrameHeight() + ImGui::GetStyle().ItemSpacing.x) + ImGui::CalcTextSize("Apply").x +
                          ImGui::GetStyle().FramePadding.x * 2 + ImGui::GetStyle().ItemSpacing.x;
    ImGui::SetNextItemWidth(std::max(100.0f, ImGui::GetContentRegionAvail().x - buttons));
    if (f.focusRequested) {
        ImGui::SetKeyboardFocusHere();
        f.focusRequested = false;
    }
    const bool enter = inputText("##filter", "Display filter, e.g.  tcp.port == 443 && ip.addr == 10.0.0.0/8   (Enter to apply)",
                                 f.text, ImGuiInputTextFlags_EnterReturnsTrue);
    ImGui::PopStyleColor(colors);

    ImGui::SameLine();
    if (ImGui::Button("Apply") || enter) applyFilter(state, f.text);
    ImGui::SameLine();
    if (ImGui::Button("X")) applyFilter(state, "");
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear the filter");
    ImGui::SameLine();
    if (ImGui::BeginCombo("##history", "", ImGuiComboFlags_NoPreview)) {
        if (state.settings.filterHistory.empty()) ImGui::TextDisabled("(no filters used yet)");
        std::string chosen;
        for (const auto &h: state.settings.filterHistory) {
            if (ImGui::Selectable(h.c_str())) chosen = h;
        }
        ImGui::EndCombo();
        if (!chosen.empty()) applyFilter(state, chosen);
    }
    ImGui::SameLine();
    if (ImGui::Button("?")) f.showHelp = !f.showHelp;
    if (ImGui::IsItemHovered()) ImGui::SetTooltip("Filter syntax and fields");

    if (!f.previewOk) {
        ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s  (at position %zu)", f.previewError.message.c_str(),
                           f.previewError.position + 1);
    }
}

void ui::drawFilterHelp(AppState &state) {
    auto &f = state.filter;
    if (!f.showHelp) return;

    ImGui::SetNextWindowSize(ImVec2(720, 520), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Display Filter Reference", &f.showHelp)) {
        ImGui::TextWrapped("Combine tests with && || ! (or and / or / not) and parentheses. Comparison operators: == != < > <= >= "
                           "(eq ne lt gt le ge), contains, matches (regular expression, prefix (?i) to ignore case) and "
                           "'in {a b 10..20}'. Text values are quoted; IP addresses may be networks (10.0.0.0/8). "
                           "!= is the exact negation of ==.");
        ImGui::Spacing();
        ImGui::TextUnformatted("Examples (click to use):");
        static const char *examples[] = {
            "tcp.port in {80 443} && !tcp.flags.rst", "ip.addr == 10.0.0.0/8 && !arp", "dns or arp", "tcp.flags.syn && !tcp.flags.ack",
            "info contains \"GET\"", "frame.len > 1000", "ipv6.src == 2001:db8::/32", "malformed", "frame.time_delta > 1.0"};
        for (const char *e: examples) {
            if (ImGui::Selectable(e)) { f.text = e; f.focusRequested = true; }
        }
        ImGui::Separator();
        inputText("##fieldsearch", "Search fields...", f.helpSearch);
        if (ImGui::BeginTable("fields", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("Field");
            ImGui::TableSetupColumn("Type");
            ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();
            for (const auto &info: filter::fieldInfos()) {
                if (!f.helpSearch.empty() && info.name.find(f.helpSearch) == std::string::npos &&
                    info.description.find(f.helpSearch) == std::string::npos) continue;
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                if (ImGui::Selectable(info.name.c_str(), false, ImGuiSelectableFlags_SpanAllColumns)) {
                    f.text += (f.text.empty() || f.text.back() == ' ' ? "" : " ") + info.name;
                    f.focusRequested = true;
                }
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(info.type.c_str());
                ImGui::TableSetColumnIndex(2);
                ImGui::TextUnformatted(info.description.c_str());
            }
            ImGui::EndTable();
        }
    }
    ImGui::End();
}
