#include "ui.h"

#include <cstdio>

#include <imgui.h>

#include <network/timeutil.h>

namespace {
    const char *linkTypeText(uint32_t t) {
        switch (t) {
            case 0: return "NULL (BSD loopback)";
            case 1: return "Ethernet";
            case 101: case 12: case 14: return "Raw IP";
            case 108: return "OpenBSD loopback";
            case 113: return "Linux cooked capture v1";
            case 276: return "Linux cooked capture v2";
            default: return "Unsupported";
        }
    }

    std::string resolution(uint64_t ticksPerSecond) {
        if (ticksPerSecond == 1000000000ull) return "nanosecond";
        if (ticksPerSecond == 1000000ull) return "microsecond";
        if (ticksPerSecond == 1000ull) return "millisecond";
        if (ticksPerSecond == 1ull) return "second";
        return "1/" + std::to_string(ticksPerSecond) + " second";
    }

    std::string sizeText(uint64_t bytes) {
        char buf[48];
        if (bytes < 10240) std::snprintf(buf, sizeof(buf), "%llu bytes", static_cast<unsigned long long>(bytes));
        else std::snprintf(buf, sizeof(buf), "%.1f MB (%llu bytes)", static_cast<double>(bytes) / 1048576.0, static_cast<unsigned long long>(bytes));
        return buf;
    }

    void keyValue(const char *key, const std::string &value) {
        if (value.empty()) return;
        ImGui::TableNextRow();
        ImGui::TableSetColumnIndex(0);
        ImGui::TextDisabled("%s", key);
        ImGui::TableSetColumnIndex(1);
        ImGui::TextWrapped("%s", value.c_str());
    }
} // namespace

void ui::drawCaptureInfoWindow(AppState &state) {
    if (!state.showCaptureInfo) return;
    ImGui::SetNextWindowSize(ImVec2(680, 520), ImGuiCond_FirstUseEver);
    if (!ImGui::Begin("Capture File Properties", &state.showCaptureInfo)) { ImGui::End(); return; }

    const auto &info = state.captureInfo;
    if (state.currentFile.empty()) {
        ImGui::TextDisabled("No capture is open.");
        ImGui::End();
        return;
    }

    ImGui::SeparatorText("General");
    if (ImGui::BeginTable("general", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 150);
        ImGui::TableSetupColumn("");
        keyValue("File", state.currentFile);
        keyValue("Size", sizeText(info.fileSize));
        keyValue("Format", info.format);
        keyValue("Packets", std::to_string(state.packets.size()) +
                                (state.filter.active ? " (" + std::to_string(state.displayedCount()) + " displayed)" : ""));
        if (!state.packets.empty()) {
            const double first = state.captureStartEpoch, span = state.packets.back().time;
            keyValue("First packet", network::formatUtcTime(first) + " UTC");
            keyValue("Last packet", network::formatUtcTime(first + span) + " UTC");
            char buf[64];
            std::snprintf(buf, sizeof(buf), "%.6f seconds", span);
            keyValue("Elapsed", buf);
            if (span > 0) {
                std::snprintf(buf, sizeof(buf), "%.1f packets/s", static_cast<double>(state.packets.size()) / span);
                keyValue("Average rate", buf);
            }
        }
        keyValue("Sections", info.sections > 1 ? std::to_string(info.sections) : "");
        ImGui::EndTable();
    }

    if (!info.comment.empty() || !info.hardware.empty() || !info.os.empty() || !info.application.empty()) {
        ImGui::SeparatorText("Capture file section");
        if (ImGui::BeginTable("shb", 2, ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 150);
            ImGui::TableSetupColumn("");
            keyValue("Comment", info.comment);
            keyValue("Hardware", info.hardware);
            keyValue("Operating system", info.os);
            keyValue("Application", info.application);
            ImGui::EndTable();
        }
    }

    ImGui::SeparatorText("Interfaces");
    if (ImGui::BeginTable("ifaces", 7, ImGuiTableFlags_RowBg | ImGuiTableFlags_Borders | ImGuiTableFlags_Resizable)) {
        ImGui::TableSetupColumn("#", ImGuiTableColumnFlags_WidthFixed, 24);
        ImGui::TableSetupColumn("Name");
        ImGui::TableSetupColumn("Link type");
        ImGui::TableSetupColumn("Snaplen");
        ImGui::TableSetupColumn("Timestamps");
        ImGui::TableSetupColumn("Packets");
        ImGui::TableSetupColumn("Dropped");
        ImGui::TableHeadersRow();
        for (size_t i = 0; i < info.interfaces.size(); ++i) {
            const auto &itf = info.interfaces[i];
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            ImGui::Text("%zu", i);
            ImGui::TableSetColumnIndex(1);
            ImGui::TextUnformatted(itf.name.empty() ? "(unnamed)" : itf.name.c_str());
            if (!itf.description.empty() && ImGui::IsItemHovered()) ImGui::SetTooltip("%s", itf.description.c_str());
            ImGui::TableSetColumnIndex(2);
            ImGui::Text("%s (%u)", linkTypeText(itf.linkType), itf.linkType);
            ImGui::TableSetColumnIndex(3);
            if (itf.snapLen) ImGui::Text("%u", itf.snapLen); else ImGui::TextDisabled("none");
            ImGui::TableSetColumnIndex(4);
            ImGui::TextUnformatted(resolution(itf.ticksPerSecond).c_str());
            ImGui::TableSetColumnIndex(5);
            ImGui::Text("%llu", static_cast<unsigned long long>(itf.packets));
            ImGui::TableSetColumnIndex(6);
            if (itf.hasStats) ImGui::Text("%llu of %llu", static_cast<unsigned long long>(itf.dropped), static_cast<unsigned long long>(itf.received));
            else ImGui::TextDisabled("-");
        }
        ImGui::EndTable();
    }

    if (!info.packetComments.empty()) {
        ImGui::SeparatorText(("Packet comments (" + std::to_string(info.packetComments.size()) + ")").c_str());
        std::vector<uint32_t> numbers;
        for (const auto &kv: info.packetComments) numbers.push_back(kv.first);
        std::sort(numbers.begin(), numbers.end());
        ImGui::BeginChild("comments", ImVec2(0, 140), true);
        for (uint32_t n: numbers) {
            const std::string line = "#" + std::to_string(n) + "  " + info.packetComments.at(n);
            if (ImGui::Selectable(line.c_str()) && n >= 1 && n <= state.packets.size()) {
                state.selectPacket(static_cast<int>(n) - 1);
                state.scrollToSelection = true;
            }
        }
        ImGui::EndChild();
    }

    if (!info.names.empty()) {
        ImGui::SeparatorText(("Name resolution (" + std::to_string(info.names.size()) + " records)").c_str());
        ImGui::BeginChild("names", ImVec2(0, 120), true);
        for (const auto &r: info.names) ImGui::Text("%s  %s", r.address.c_str(), r.name.c_str());
        ImGui::EndChild();
    }
    ImGui::End();
}
