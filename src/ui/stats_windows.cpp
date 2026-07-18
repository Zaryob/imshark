#include "ui.h"

#include <algorithm>
#include <cstdio>
#include <functional>

#include <imgui.h>

namespace {
    using stats::AddressKind;

    constexpr AddressKind kKinds[stats::kAddressKindCount] = {
        AddressKind::Ipv4,
        AddressKind::Ipv6,
        AddressKind::Tcp,
        AddressKind::Udp,
        AddressKind::Sctp,
        AddressKind::Ethernet,
        AddressKind::Wlan,
        AddressKind::Bluetooth,
        AddressKind::Usb,
        AddressKind::UsbEndpoint
    };

    std::string fmtTime(double seconds) {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%.6f", seconds);
        return buf;
    }

    std::string fmtPercent(uint64_t part, uint64_t whole) {
        char buf[16];
        std::snprintf(buf, sizeof(buf), "%.1f%%", whole ? 100.0 * static_cast<double>(part) / static_cast<double>(whole) : 0.0);
        return buf;
    }

    void refreshIfDirty(ui::AppState &state) {
        auto &s = state.stats;
        if (!s.dirty) return;
        s.dirty = false;
        s.hierarchyValid = false;
        s.expertValid = false;
        for (size_t i = 0; i < stats::kAddressKindCount; ++i) s.conversationsValid[i] = s.endpointsValid[i] = false;
    }

    const std::vector<uint32_t> *subset(const ui::AppState &state) {
        return (state.stats.limitToDisplayed && state.filter.active) ? &state.filter.visible : nullptr;
    }

    void limitCheckbox(ui::AppState &state) {
        if (ImGui::Checkbox("Limit to displayed packets", &state.stats.limitToDisplayed)) state.stats.dirty = true;
        if (state.filter.active && state.stats.limitToDisplayed) {
            ImGui::SameLine();
            ImGui::TextDisabled("(filter: %s)", state.filter.appliedText.c_str());
        }
    }

    template<typename T, typename Compare>
    void sortBySpecs(std::vector<T> &rows, ImGuiTableSortSpecs *specs, Compare compare) {
        if (!specs || specs->SpecsCount == 0) return;
        const auto &spec = specs->Specs[0];
        const bool asc = spec.SortDirection == ImGuiSortDirection_Ascending;
        std::stable_sort(rows.begin(), rows.end(), [&](const T &a, const T &b) {
            const int c = compare(static_cast<int>(spec.ColumnUserID), a, b);
            return asc ? c < 0 : c > 0;
        });
    }

    template<typename T>
    int cmp(const T &a, const T &b) { return a < b ? -1 : (b < a ? 1 : 0); }

    void hierarchyRow(const stats::HierarchyNode &n, uint64_t totalPackets, uint64_t totalBytes) {
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        const bool open = ImGui::TreeNodeEx(n.name.c_str(), (n.children.empty() ? ImGuiTreeNodeFlags_Leaf | ImGuiTreeNodeFlags_NoTreePushOnOpen : 0) |
                                                                ImGuiTreeNodeFlags_DefaultOpen | ImGuiTreeNodeFlags_SpanFullWidth);
        ImGui::TableSetColumnIndex(1);
        ImGui::TextUnformatted(fmtPercent(n.packets, totalPackets).c_str());
        ImGui::TableSetColumnIndex(2);
        ImGui::Text("%llu", static_cast<unsigned long long>(n.packets));
        ImGui::TableSetColumnIndex(3);
        ImGui::TextUnformatted(fmtPercent(n.bytes, totalBytes).c_str());
        ImGui::TableSetColumnIndex(4);
        ImGui::Text("%llu", static_cast<unsigned long long>(n.bytes));
        if (open && !n.children.empty()) {
            for (const auto &c: n.children) hierarchyRow(c, totalPackets, totalBytes);
            ImGui::TreePop();
        }
    }

    void drawExpert(ui::AppState &state) {
        auto &s = state.stats;
        ImGui::SetNextWindowSize(ImVec2(640, 320), ImGuiCond_FirstUseEver);
        if (!ImGui::Begin("Expert Information", &s.showExpert)) { ImGui::End(); return; }
        limitCheckbox(state);
        refreshIfDirty(state);
        if (!s.expertValid) {
            s.expert = stats::expertInfo(state.packets, subset(state), state.captureStartEpoch);
            s.expertValid = true;
        }
        if (s.expert.empty()) ImGui::TextDisabled("Nothing noteworthy found.");
        if (ImGui::BeginTable("expert", 3, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable)) {
            ImGui::TableSetupColumn("Severity", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("Summary", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("Packets", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableHeadersRow();
            for (size_t i = 0; i < s.expert.size(); ++i) {
                const auto &item = s.expert[i];
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                const ImVec4 color = item.severity == stats::Severity::Error ? ImVec4(1.0f, 0.4f, 0.4f, 1.0f)
                                     : item.severity == stats::Severity::Warn ? ImVec4(1.0f, 0.8f, 0.3f, 1.0f)
                                     : item.severity == stats::Severity::Note ? ImVec4(0.5f, 0.8f, 1.0f, 1.0f) : ImVec4(0.7f, 0.7f, 0.7f, 1.0f);
                ImGui::TextColored(color, "%s", stats::severityName(item.severity));
                ImGui::TableSetColumnIndex(1);
                ImGui::PushID(static_cast<int>(i));
                if (ImGui::Selectable(item.summary.c_str(), false, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                    if (ImGui::IsMouseDoubleClicked(0)) ui::applyFilter(state, item.filter);
                }
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("Double-click to filter: %s", item.filter.c_str());
                ImGui::PopID();
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%llu", static_cast<unsigned long long>(item.count));
            }
            ImGui::EndTable();
        }
        ImGui::End();
    }

    void drawHierarchy(ui::AppState &state) {
        auto &s = state.stats;
        if (!ImGui::Begin("Protocol Hierarchy", &s.showHierarchy)) { ImGui::End(); return; }
        limitCheckbox(state);
        refreshIfDirty(state);
        if (!s.hierarchyValid) {
            s.hierarchy = stats::protocolHierarchy(state.packets, subset(state));
            s.hierarchyValid = true;
        }
        if (ImGui::BeginTable("hier", 5, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY)) {
            ImGui::TableSetupColumn("Protocol", ImGuiTableColumnFlags_WidthStretch);
            ImGui::TableSetupColumn("% Packets", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("Packets", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("% Bytes", ImGuiTableColumnFlags_WidthFixed, 80);
            ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_WidthFixed, 100);
            ImGui::TableSetupScrollFreeze(0, 1);
            ImGui::TableHeadersRow();
            hierarchyRow(s.hierarchy, s.hierarchy.packets, s.hierarchy.bytes);
            ImGui::EndTable();
        }
        ImGui::End();
    }

    void drawConversations(ui::AppState &state) {
        auto &s = state.stats;
        ImGui::SetNextWindowSize(ImVec2(980, 420), ImGuiCond_FirstUseEver);
        if (!ImGui::Begin("Conversations", &s.showConversations)) { ImGui::End(); return; }
        limitCheckbox(state);
        refreshIfDirty(state);

        if (ImGui::BeginTabBar("convtabs")) {
            for (size_t k = 0; k < stats::kAddressKindCount; ++k) {
                if (!ImGui::BeginTabItem(stats::kindName(kKinds[k]), nullptr, s.selectTab == static_cast<int>(k) ? ImGuiTabItemFlags_SetSelected : 0)) continue;
                s.tab = static_cast<int>(k);
                if (!s.conversationsValid[k]) {
                    s.conversations[k] = stats::conversations(state.packets, subset(state), kKinds[k], state.ethernetAddresses());
                    s.conversationsValid[k] = true;
                }
                auto &rows = s.conversations[k];
                if (ImGui::BeginTable("conv", 10, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable |
                                                     ImGuiTableFlags_Sortable | ImGuiTableFlags_ScrollY)) {
                    ImGui::TableSetupColumn("Address A", 0, 0, 0);
                    ImGui::TableSetupColumn("Address B", 0, 0, 1);
                    ImGui::TableSetupColumn("Packets", 0, 0, 2);
                    ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending, 0, 3);
                    ImGui::TableSetupColumn("Packets A→B", 0, 0, 4);
                    ImGui::TableSetupColumn("Bytes A→B", 0, 0, 5);
                    ImGui::TableSetupColumn("Packets B→A", 0, 0, 6);
                    ImGui::TableSetupColumn("Bytes B→A", 0, 0, 7);
                    ImGui::TableSetupColumn("Rel Start", 0, 0, 8);
                    ImGui::TableSetupColumn("Duration", 0, 0, 9);
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableHeadersRow();
                    if (ImGuiTableSortSpecs *specs = ImGui::TableGetSortSpecs(); specs && specs->SpecsDirty) {
                        sortBySpecs(rows, specs, [](int col, const stats::Conversation &a, const stats::Conversation &b) {
                            switch (col) {
                                case 0: return cmp(std::make_pair(a.addressA, a.portA), std::make_pair(b.addressA, b.portA));
                                case 1: return cmp(std::make_pair(a.addressB, a.portB), std::make_pair(b.addressB, b.portB));
                                case 2: return cmp(a.packets, b.packets);
                                case 3: return cmp(a.bytes, b.bytes);
                                case 4: return cmp(a.packetsAtoB, b.packetsAtoB);
                                case 5: return cmp(a.bytesAtoB, b.bytesAtoB);
                                case 6: return cmp(a.packetsBtoA, b.packetsBtoA);
                                case 7: return cmp(a.bytesBtoA, b.bytesBtoA);
                                case 8: return cmp(a.start, b.start);
                                default: return cmp(a.duration, b.duration);
                            }
                        });
                        specs->SpecsDirty = false;
                    }
                    ImGuiListClipper clipper;
                    clipper.Begin(static_cast<int>(rows.size()));
                    while (clipper.Step()) {
                        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                            const auto &c = rows[i];
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::PushID(i);
                            if (ImGui::Selectable(stats::addressLabel(c.addressA, c.portA, kKinds[k]).c_str(), false,
                                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                                if (ImGui::IsMouseDoubleClicked(0)) ui::applyFilter(state, stats::conversationFilter(c, kKinds[k]));
                            }
                            if (ImGui::BeginPopupContextItem()) {
                                if (ImGui::MenuItem("Apply as Filter")) ui::applyFilter(state, stats::conversationFilter(c, kKinds[k]));
                                if (ImGui::MenuItem("Copy Filter")) ImGui::SetClipboardText(stats::conversationFilter(c, kKinds[k]).c_str());
                                ImGui::EndPopup();
                            }
                            ImGui::PopID();
                            ImGui::TableSetColumnIndex(1);
                            ImGui::TextUnformatted(stats::addressLabel(c.addressB, c.portB, kKinds[k]).c_str());
                            ImGui::TableSetColumnIndex(2);
                            ImGui::Text("%llu", static_cast<unsigned long long>(c.packets));
                            ImGui::TableSetColumnIndex(3);
                            ImGui::Text("%llu", static_cast<unsigned long long>(c.bytes));
                            ImGui::TableSetColumnIndex(4);
                            ImGui::Text("%llu", static_cast<unsigned long long>(c.packetsAtoB));
                            ImGui::TableSetColumnIndex(5);
                            ImGui::Text("%llu", static_cast<unsigned long long>(c.bytesAtoB));
                            ImGui::TableSetColumnIndex(6);
                            ImGui::Text("%llu", static_cast<unsigned long long>(c.packetsBtoA));
                            ImGui::TableSetColumnIndex(7);
                            ImGui::Text("%llu", static_cast<unsigned long long>(c.bytesBtoA));
                            ImGui::TableSetColumnIndex(8);
                            ImGui::TextUnformatted(fmtTime(c.start).c_str());
                            ImGui::TableSetColumnIndex(9);
                            ImGui::TextUnformatted(fmtTime(c.duration).c_str());
                        }
                    }
                    ImGui::EndTable();
                }
                ImGui::TextDisabled("Double-click a row (or right click) to apply it as a display filter.");
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        ImGui::End();
    }

    void drawEndpoints(ui::AppState &state) {
        auto &s = state.stats;
        ImGui::SetNextWindowSize(ImVec2(820, 400), ImGuiCond_FirstUseEver);
        if (!ImGui::Begin("Endpoints", &s.showEndpoints)) { ImGui::End(); return; }
        limitCheckbox(state);
        refreshIfDirty(state);

        if (ImGui::BeginTabBar("eptabs")) {
            for (size_t k = 0; k < stats::kAddressKindCount; ++k) {
                if (!ImGui::BeginTabItem(stats::kindName(kKinds[k]), nullptr, s.selectTab == static_cast<int>(k) ? ImGuiTabItemFlags_SetSelected : 0)) continue;
                if (!s.endpointsValid[k]) {
                    s.endpoints[k] = stats::endpoints(state.packets, subset(state), kKinds[k], state.ethernetAddresses());
                    s.endpointsValid[k] = true;
                }
                auto &rows = s.endpoints[k];
                if (ImGui::BeginTable("ep", 7, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable |
                                                  ImGuiTableFlags_Sortable | ImGuiTableFlags_ScrollY)) {
                    ImGui::TableSetupColumn("Address", 0, 0, 0);
                    ImGui::TableSetupColumn("Packets", 0, 0, 1);
                    ImGui::TableSetupColumn("Bytes", ImGuiTableColumnFlags_DefaultSort | ImGuiTableColumnFlags_PreferSortDescending, 0, 2);
                    ImGui::TableSetupColumn("Tx Packets", 0, 0, 3);
                    ImGui::TableSetupColumn("Tx Bytes", 0, 0, 4);
                    ImGui::TableSetupColumn("Rx Packets", 0, 0, 5);
                    ImGui::TableSetupColumn("Rx Bytes", 0, 0, 6);
                    ImGui::TableSetupScrollFreeze(0, 1);
                    ImGui::TableHeadersRow();
                    if (ImGuiTableSortSpecs *specs = ImGui::TableGetSortSpecs(); specs && specs->SpecsDirty) {
                        sortBySpecs(rows, specs, [](int col, const stats::Endpoint &a, const stats::Endpoint &b) {
                            switch (col) {
                                case 0: return cmp(std::make_pair(a.address, a.port), std::make_pair(b.address, b.port));
                                case 1: return cmp(a.packets, b.packets);
                                case 2: return cmp(a.bytes, b.bytes);
                                case 3: return cmp(a.txPackets, b.txPackets);
                                case 4: return cmp(a.txBytes, b.txBytes);
                                case 5: return cmp(a.rxPackets, b.rxPackets);
                                default: return cmp(a.rxBytes, b.rxBytes);
                            }
                        });
                        specs->SpecsDirty = false;
                    }
                    ImGuiListClipper clipper;
                    clipper.Begin(static_cast<int>(rows.size()));
                    while (clipper.Step()) {
                        for (int i = clipper.DisplayStart; i < clipper.DisplayEnd; ++i) {
                            const auto &e = rows[i];
                            ImGui::TableNextRow();
                            ImGui::TableSetColumnIndex(0);
                            ImGui::PushID(i);
                            if (ImGui::Selectable(stats::addressLabel(e.address, e.port, kKinds[k]).c_str(), false,
                                                  ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                                if (ImGui::IsMouseDoubleClicked(0)) ui::applyFilter(state, stats::endpointFilter(e, kKinds[k]));
                            }
                            if (ImGui::BeginPopupContextItem()) {
                                if (ImGui::MenuItem("Apply as Filter")) ui::applyFilter(state, stats::endpointFilter(e, kKinds[k]));
                                if (ImGui::MenuItem("Copy Filter")) ImGui::SetClipboardText(stats::endpointFilter(e, kKinds[k]).c_str());
                                ImGui::EndPopup();
                            }
                            ImGui::PopID();
                            const unsigned long long v[6] = {e.packets, e.bytes, e.txPackets, e.txBytes, e.rxPackets, e.rxBytes};
                            for (int c = 0; c < 6; ++c) {
                                ImGui::TableSetColumnIndex(c + 1);
                                ImGui::Text("%llu", v[c]);
                            }
                        }
                    }
                    ImGui::EndTable();
                }
                ImGui::TextDisabled("Double-click a row (or right click) to apply it as a display filter.");
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
        }
        ImGui::End();
    }
} // namespace

void ui::drawStatsWindows(AppState &state) {
    if (state.stats.showExpert) drawExpert(state);
    if (state.stats.showHierarchy) drawHierarchy(state);
    if (state.stats.showConversations) drawConversations(state);
    if (state.stats.showEndpoints) drawEndpoints(state);
    state.stats.selectTab = -1; // the request applies to all windows of this frame
}
