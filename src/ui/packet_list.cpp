#include "ui.h"

#include <algorithm>
#include <numeric>
#include <string>

#include <imgui.h>

#include "clipboard.h"
#include "time_format.h"

namespace {
    template<typename T>
    int compare(const T &a, const T &b) { return a < b ? -1 : (b < a ? 1 : 0); }

    // Rebuilds the displayed order: the packets that pass the filter, sorted by the table's sort specs.
    void rebuildOrder(ui::AppState &state, const ImGuiTableSortSpecs *specs) {
        if (state.filter.active) {
            state.order = state.filter.visible;
        } else {
            state.order.resize(state.packets.size());
            std::iota(state.order.begin(), state.order.end(), 0u);
        }
        if (!specs || specs->SpecsCount == 0) return;
        const ImGuiTableColumnSortSpecs &spec = specs->Specs[0];
        ui::sortOrder(state.order, state.packets, static_cast<ui::SortColumn>(spec.ColumnUserID),
                      spec.SortDirection == ImGuiSortDirection_Ascending);
    }

    // Up/Down/PageUp/PageDown/Home/End move the selection through the displayed rows.
    void handleKeys(ui::AppState &state) {
        if (state.order.empty() || ImGui::GetIO().WantTextInput || ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopupId)) return;

        int step = 0;
        bool toStart = false, toEnd = false;
        if (ImGui::IsKeyPressed(ImGuiKey_DownArrow)) step = 1;
        else if (ImGui::IsKeyPressed(ImGuiKey_UpArrow)) step = -1;
        else if (ImGui::IsKeyPressed(ImGuiKey_PageDown)) step = 20;
        else if (ImGui::IsKeyPressed(ImGuiKey_PageUp)) step = -20;
        else if (ImGui::IsKeyPressed(ImGuiKey_Home)) toStart = true;
        else if (ImGui::IsKeyPressed(ImGuiKey_End)) toEnd = true;
        else return;

        const int last = static_cast<int>(state.order.size()) - 1;
        int pos = -1; // position of the selected packet in the displayed order
        if (state.selectedPacket >= 0) {
            const auto it = std::find(state.order.begin(), state.order.end(), static_cast<uint32_t>(state.selectedPacket));
            if (it != state.order.end()) pos = static_cast<int>(it - state.order.begin());
        }
        if (toStart) pos = 0;
        else if (toEnd) pos = last;
        else if (pos < 0) pos = step > 0 ? 0 : last;
        else pos = std::max(0, std::min(last, pos + step));

        state.selectPacket(static_cast<int>(state.order[pos]));
        state.scrollToSelection = true;
    }
} // namespace

void ui::sortPacketOrder(std::vector<uint32_t> &order, const std::vector<packet::PacketInfo> &packets, SortColumn column,
                         bool ascending) {
    order.resize(packets.size());
    std::iota(order.begin(), order.end(), 0u);
    sortOrder(order, packets, column, ascending);
}

void ui::sortOrder(std::vector<uint32_t> &order, const std::vector<packet::PacketInfo> &packets, SortColumn column,
                   bool ascending) {
    std::stable_sort(order.begin(), order.end(), [&](uint32_t ia, uint32_t ib) {
        const auto &a = packets[ia];
        const auto &b = packets[ib];
        int c = 0;
        switch (column) {
            case SortColumn::Number: c = compare(a.number, b.number); break;
            case SortColumn::Time: c = compare(a.time, b.time); break;
            case SortColumn::Source: c = compare(a.source, b.source); break;
            case SortColumn::Destination: c = compare(a.destination, b.destination); break;
            case SortColumn::Protocol: c = compare(a.protocol, b.protocol); break;
            case SortColumn::Length: c = compare(a.length, b.length); break;
            case SortColumn::Info: c = compare(a.info, b.info); break;
        }
        return ascending ? c < 0 : c > 0;
    });
}

void ui::drawPacketList(AppState &state, float height) {
    ImGui::BeginChild("Packet List", ImVec2(0, height), true);
    if (ImGui::BeginTable("Packets", 7,
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable |
                              ImGuiTableFlags_Sortable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_RowBg)) {
        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("No.", 0, 0.0f, static_cast<ImGuiID>(SortColumn::Number));
        ImGui::TableSetupColumn("Time", 0, 0.0f, static_cast<ImGuiID>(SortColumn::Time));
        ImGui::TableSetupColumn("Source", 0, 0.0f, static_cast<ImGuiID>(SortColumn::Source));
        ImGui::TableSetupColumn("Destination", 0, 0.0f, static_cast<ImGuiID>(SortColumn::Destination));
        ImGui::TableSetupColumn("Protocol", 0, 0.0f, static_cast<ImGuiID>(SortColumn::Protocol));
        ImGui::TableSetupColumn("Length", 0, 0.0f, static_cast<ImGuiID>(SortColumn::Length));
        ImGui::TableSetupColumn("Info", ImGuiTableColumnFlags_WidthStretch, 0.0f, static_cast<ImGuiID>(SortColumn::Info));
        ImGui::TableHeadersRow();

        ImGuiTableSortSpecs *specs = ImGui::TableGetSortSpecs();
        if ((specs && specs->SpecsDirty) || state.orderDirty) {
            rebuildOrder(state, specs);
            state.orderDirty = false;
            if (specs) specs->SpecsDirty = false;
        }
        handleKeys(state);

        // Only the visible rows are laid out, so huge captures stay responsive.
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(state.order.size()));
        if (state.scrollToSelection && state.selectedPacket >= 0) {
            const auto it = std::find(state.order.begin(), state.order.end(), static_cast<uint32_t>(state.selectedPacket));
            if (it != state.order.end()) clipper.IncludeItemByIndex(static_cast<int>(it - state.order.begin()));
        }
        while (clipper.Step()) {
            for (int row = clipper.DisplayStart; row < clipper.DisplayEnd; ++row) {
                const int i = static_cast<int>(state.order[row]);
                const auto &packet = state.packets[i];
                ImGui::TableNextRow();
                const ColorRule *rule = nullptr;
                if (state.settings.colorize) {
                    filter::Context context;
                    context.previous = i ? &state.packets[i - 1] : nullptr;
                    context.captureStartEpoch = state.captureStartEpoch;
                    rule = state.colors.match(packet, context);
                }
                if (rule) {
                    const ImU32 bg = IM_COL32((rule->background >> 16) & 0xFF, (rule->background >> 8) & 0xFF, rule->background & 0xFF, 255);
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0, bg);
                    ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg1, bg);
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32((rule->foreground >> 16) & 0xFF, (rule->foreground >> 8) & 0xFF, rule->foreground & 0xFF, 255));
                }
                ImGui::TableSetColumnIndex(0);
                const bool selected = state.selectedPacket == i;
                if (ImGui::Selectable(std::to_string(packet.number).c_str(), selected, ImGuiSelectableFlags_SpanAllColumns)) {
                    state.selectPacket(i);
                }
                if (ImGui::BeginPopupContextItem()) {
                    if (ImGui::MenuItem("Copy Row")) ImGui::SetClipboardText(ui::summaryRow(packet).c_str());
                    if (ImGui::MenuItem("Copy Source")) ImGui::SetClipboardText(packet.source.c_str());
                    if (ImGui::MenuItem("Copy Destination")) ImGui::SetClipboardText(packet.destination.c_str());
                    if (ImGui::MenuItem("Copy Info")) ImGui::SetClipboardText(packet.info.c_str());
                    ImGui::EndPopup();
                }
                if (selected && state.scrollToSelection) {
                    ImGui::SetScrollHereY();
                    state.scrollToSelection = false;
                }
                ImGui::TableSetColumnIndex(1);
                ImGui::TextUnformatted(formatPacketTime(packet, i ? &state.packets[i - 1] : nullptr, state.captureStartEpoch,
                                                        state.settings.timeFormat).c_str());
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
                if (rule) ImGui::PopStyleColor();
            }
        }
        state.scrollToSelection = false;
        ImGui::EndTable();
    }
    ImGui::EndChild();
}
