#include "ui.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>

#include <imgui.h>

#include <core.h>

#include "text_input.h"

namespace {
    using namespace std::chrono;

    // One poll appends at most this much: the packets that do not fit stay queued for the next frame, so a burst of
    // traffic cannot freeze the UI (the packet table is clipped, only the dissection and the filter cost time).
    constexpr size_t kChunk = 512;
    constexpr auto kFrameBudget = milliseconds(8);
    constexpr auto kStatsInterval = seconds(1);        // statistics windows are recomputed at most this often while capturing
    constexpr auto kSortInterval = milliseconds(500);  // a sorted list is rebuilt at most this often while capturing

    // Separates the capture description from the counters. (ImGui's built-in font has no em dash.)
    constexpr const char *kDash = "-";

    capture::LiveCapture &deviceOf(ui::LiveState &live) {
        if (!live.device) live.device = std::make_unique<capture::LiveCapture>();
        return *live.device;
    }

    std::string flagsText(const capture::InterfaceDesc &itf) {
        std::string out;
        auto add = [&](const char *text) {
            if (!out.empty()) out += ", ";
            out += text;
        };
        if (itf.up) add("up");
        if (itf.running) add("running");
        if (itf.loopback) add("loopback");
        if (itf.wireless) add("wireless");
        return out;
    }

    // Takes over what the device queued: dissects it (bounded unless `all`), keeps the filter and the list in step.
    void drain(ui::AppState &state, bool all) {
        auto &l = state.live;
        if (!l.processor || !l.device) return;
        if (l.device->packetCount() <= state.packets.size()) return;     // nothing new (also avoids a copy-on-write)

        const size_t before = state.packets.size();
        std::vector<uint32_t> amended;
        const auto start = steady_clock::now();
        {
            auto &packets = state.packets.modify();
            while (capture::appendCapturedPackets(*l.device, *l.processor, packets, kChunk, &amended) > 0) {
                if (!all && steady_clock::now() - start > kFrameBudget) break;
            }
        }
        const size_t after = state.packets.size();
        if (after == before && amended.empty()) return;

        state.captureStartEpoch = l.processor->captureStartEpoch();
        state.captureInfo = l.processor->captureInfo();
        // earlier rows were edited in place (reassembly): their filter result may have changed, their colour and text
        // are evaluated when drawn, and a shown detail view of such a row is stale
        if (ui::extendFilter(state, before, amended)) state.orderDirty = true;
        for (uint32_t i: amended) {
            if (static_cast<int>(i) == state.selectedPacket) state.detailIndex = -1;
        }
        if (after > before && l.autoScroll) l.scrollToEnd = true;
        l.statsPending = true;
        if (all) {
            state.stats.dirty = true;
            l.statsPending = false;
            l.lastStats = steady_clock::now();
        }
    }

    // Stops the device, takes over the rest of its queue and keeps the capture open as an ordinary file.
    void finish(ui::AppState &state) {
        auto &l = state.live;
        if (!l.processor || !l.device) return;
        l.device->stop();
        drain(state, true);
        if (l.processor->captureInfo().interfaces.empty()) l.processor->beginLive(l.device->linkType(), l.device->snaplen());
        state.captureStartEpoch = l.processor->captureStartEpoch();
        state.captureInfo = l.processor->captureInfo();
        state.sessions = l.processor->sessions();
        const std::string error = l.device->lastError();
        const std::string path = l.device->releaseTempFile();   // the file is ours now: it backs the details, export, follow
        state.tempFile = path;
        state.currentFile = path;
        l.processor.reset();
        l.unsaved = !state.packets.empty();
        l.scrollToEnd = false;
        state.stats.dirty = true;
        if (!error.empty()) {
            l.error = error;
            l.openError = true;
            l.errorIsStop = true;
        }
    }

    // Common part of startCapture / startInjectedCapture. `begin` opens the device (or the injection session).
    template<typename Begin>
    bool launch(ui::AppState &state, const capture::CaptureOptions &options, const std::string &name, bool injected, Begin &&begin) {
        auto &l = state.live;
        if (l.processor) finish(state);          // take over everything the previous capture still holds before start() drops it
        l.error.clear();
        l.openError = false;
        state.loadJob.reset();                   // a load that finishes later would replace the capture
        capture::LiveCapture &device = deviceOf(l);
        if (!begin(device)) {
            l.error = device.lastError();
            l.openError = true;
            l.errorIsStop = false;
            return false;                        // the previous capture is untouched
        }
        ui::cancelBackgroundJobs(state);
        ui::clearCapture(state);                 // now the old capture goes
        l.processor = std::make_unique<core::FileProcessor>(state.registry ? *state.registry : dissect::Registry::builtin());
        l.processor->sessions().tlsExternalKeys() = state.tlsKeys;   // the keys known when the capture starts
        l.processor->sessions().setEspNullHeuristic(state.settings.espNullHeuristic);
        l.session = true;
        l.unsaved = true;
        l.injected = injected;
        l.sessionOptions = options;
        l.interfaceName = name;
        l.scrollToEnd = l.autoScroll;
        l.statsPending = false;
        l.lastStats = l.lastSortRebuild = steady_clock::now();
        state.currentFile = device.tempPath();
        state.displayName = "Live capture on " + name;
        ui::refilter(state);
        state.stats.dirty = true;
        return true;
    }

    void perform(ui::AppState &state, const ui::PendingAction &action) {
        switch (action.kind) {
            case ui::PendingAction::Start: ui::startCapture(state, state.live.options); break;
            case ui::PendingAction::Restart: ui::startCapture(state, state.live.sessionOptions); break;
            case ui::PendingAction::Open:
                // the capture stays open (and keeps running) until the file has loaded: pollLoad discards it on success,
                // a failed or cancelled load leaves it intact
                ui::startLoad(state, action.path);
                break;
            case ui::PendingAction::Close: ui::closeCapture(state); break;
            case ui::PendingAction::Quit:
                ui::discardLiveCapture(state);
                state.quitRequested = true;
                break;
            case ui::PendingAction::None: break;
        }
    }

    // Runs `action` now, or after the user decided what happens to the unsaved live capture.
    void request(ui::AppState &state, ui::PendingAction action) {
        if (ui::liveUnsaved(state)) {
            state.live.pending = std::move(action);
            state.live.openConfirm = true;
            return;
        }
        perform(state, action);
    }

    uint32_t dialogLinkType(const ui::AppState &state) {
        for (const auto &itf: state.live.dialog.interfaces.interfaces) {
            if (itf.name == state.live.options.interfaceName) return itf.loopback ? 0u : 1u;   // NULL/loopback vs Ethernet
        }
        return 1;
    }

    void drawInterfacesDialog(ui::AppState &state) {
        auto &l = state.live;
        auto &d = l.dialog;
        if (!d.open) return;
        const bool available = capture::liveCaptureAvailable();
        if (d.needsRefresh) {
            d.interfaces = capture::listInterfaces();
            d.listLoaded = true;
            d.needsRefresh = false;
            if (l.options.interfaceName.empty()) {     // nothing remembered: offer the first real, connected interface
                for (const auto &itf: d.interfaces.interfaces) {
                    if (!itf.loopback && itf.up && itf.running) { l.options.interfaceName = itf.name; break; }
                }
                if (l.options.interfaceName.empty() && !d.interfaces.interfaces.empty()) l.options.interfaceName = d.interfaces.interfaces.front().name;
            }
        }

        ImGui::SetNextWindowSize(ImVec2(820, 520), ImGuiCond_FirstUseEver);
        if (ImGui::Begin("Capture Interfaces", &d.open)) {
            if (!available) ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", ui::captureUnavailableReason().c_str());
            else if (!d.interfaces.error.empty()) ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "%s", d.interfaces.error.c_str());
            else ImGui::TextDisabled("Select an interface. Capturing needs privileges (macOS: access to /dev/bpf*, Linux: CAP_NET_RAW, Windows: Npcap).");

            const float footer = ImGui::GetFrameHeightWithSpacing() * 5.5f + ImGui::GetStyle().ItemSpacing.y * 4;
            std::string chosen;
            if (ImGui::BeginTable("interfaces", 4, ImGuiTableFlags_RowBg | ImGuiTableFlags_Resizable | ImGuiTableFlags_ScrollY | ImGuiTableFlags_Borders,
                                  ImVec2(0, std::max(80.0f, ImGui::GetContentRegionAvail().y - footer)))) {
                ImGui::TableSetupScrollFreeze(0, 1);
                ImGui::TableSetupColumn("Name", ImGuiTableColumnFlags_WidthFixed, 130);
                ImGui::TableSetupColumn("Description", ImGuiTableColumnFlags_WidthStretch, 2.0f);
                ImGui::TableSetupColumn("Addresses", ImGuiTableColumnFlags_WidthStretch, 3.0f);
                ImGui::TableSetupColumn("Flags", ImGuiTableColumnFlags_WidthFixed, 170);
                ImGui::TableHeadersRow();
                for (const auto &itf: d.interfaces.interfaces) {
                    ImGui::TableNextRow();
                    ImGui::TableSetColumnIndex(0);
                    ImGui::PushID(itf.name.c_str());
                    const bool selected = l.options.interfaceName == itf.name;
                    if (ImGui::Selectable(itf.name.c_str(), selected, ImGuiSelectableFlags_SpanAllColumns | ImGuiSelectableFlags_AllowDoubleClick)) {
                        l.options.interfaceName = itf.name;
                        if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) chosen = itf.name;
                    }
                    ImGui::PopID();
                    ImGui::TableSetColumnIndex(1);
                    ImGui::TextUnformatted(itf.description.c_str());
                    ImGui::TableSetColumnIndex(2);
                    ImGui::TextUnformatted(itf.addresses.c_str());
                    ImGui::TableSetColumnIndex(3);
                    ImGui::TextUnformatted(flagsText(itf).c_str());
                }
                ImGui::EndTable();
            }
            if (d.listLoaded && d.interfaces.interfaces.empty() && d.interfaces.error.empty()) ImGui::TextDisabled("No capture interfaces found.");

            // capture filter, validated while typing
            ImGui::AlignTextToFramePadding();
            ImGui::TextUnformatted("Capture filter:");
            ImGui::SameLine();
            const uint32_t linkType = dialogLinkType(state);
            const bool filterEmpty = l.options.filter.empty();
            if (!d.filterChecked || d.checkedFilter != l.options.filter || d.checkedLinkType != linkType || d.checkedSnaplen != l.options.snaplen) {
                d.filterCheck = capture::validateCaptureFilter(l.options.filter, linkType, l.options.snaplen);
                d.checkedFilter = l.options.filter;
                d.checkedLinkType = linkType;
                d.checkedSnaplen = l.options.snaplen;
                d.filterChecked = true;
            }
            const bool filterBad = !filterEmpty && !d.filterCheck.ok;
            if (filterBad) ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.45f, 0.12f, 0.12f, 1.0f));
            else if (!filterEmpty) ImGui::PushStyleColor(ImGuiCol_FrameBg, ImVec4(0.12f, 0.35f, 0.15f, 1.0f));
            ImGui::SetNextItemWidth(-1);
            const bool enter = ui::inputText("##capturefilter", "BPF filter, e.g.  tcp port 443 and host 10.0.0.1   (empty = everything)", l.options.filter,
                                             ImGuiInputTextFlags_EnterReturnsTrue);
            if (!filterEmpty) ImGui::PopStyleColor();
            // The check assumes Ethernet (loopback: NULL) because the real link type of the interface is only known once it
            // is opened, which needs privileges. So it only warns: Start is not blocked, opening the interface compiles the
            // filter for real and reports an error if it is invalid.
            if (filterBad) ImGui::TextColored(ImVec4(1.0f, 0.45f, 0.45f, 1.0f), "Invalid filter: %s  (checked as %s; Start verifies it on the interface)",
                                              d.filterCheck.error.c_str(), linkType == 0 ? "loopback" : "Ethernet");
            else if (!filterEmpty) ImGui::TextColored(ImVec4(0.6f, 0.9f, 0.6f, 1.0f), "Valid filter");
            else ImGui::TextDisabled("No capture filter: all packets are captured.");

            int snaplen = static_cast<int>(l.options.snaplen);
            ImGui::SetNextItemWidth(160);
            if (ImGui::InputInt("Snapshot length (bytes)", &snaplen, 0, 0)) {
                snaplen = std::max(static_cast<int>(ui::Settings::kMinSnaplen), std::min(static_cast<int>(ui::Settings::kMaxSnaplen), snaplen));
                l.options.snaplen = static_cast<uint32_t>(snaplen);
            }
            ImGui::SameLine();
            ImGui::Checkbox("Promiscuous mode", &l.options.promiscuous);

            const bool canStart = available && !l.options.interfaceName.empty();
            ImGui::BeginDisabled(!canStart);
            const bool start = ImGui::Button("Start", ImVec2(120, 0)) || (enter && canStart) || (!chosen.empty() && canStart);
            ImGui::EndDisabled();
            if (!available && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) ImGui::SetTooltip("%s", ui::captureUnavailableReason().c_str());
            ImGui::SameLine();
            if (ImGui::Button("Refresh", ImVec2(120, 0))) d.needsRefresh = true;
            ImGui::SameLine();
            if (ImGui::Button("Close", ImVec2(120, 0))) d.open = false;
            if (start) {
                d.open = false;
                request(state, {ui::PendingAction::Start, {}});
            }
        }
        ImGui::End();
    }

    void drawUnsavedPopup(ui::AppState &state) {
        auto &l = state.live;
        if (l.openConfirm) {
            ImGui::OpenPopup("Unsaved capture");
            l.openConfirm = false;
        }
        if (ImGui::BeginPopupModal("Unsaved capture", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            const size_t packets = l.capturing() ? static_cast<size_t>(l.device->packetCount()) : state.packets.size();
            if (l.capturing()) ImGui::Text("The capture on %s is still running with %zu packets that have not been saved.", l.interfaceName.c_str(), packets);
            else ImGui::Text("The live capture on %s has %zu packets that have not been saved.", l.interfaceName.c_str(), packets);
            ImGui::TextUnformatted("Export them first (File > Export Packets), or discard them?");
            ImGui::Spacing();
            if (ImGui::Button("Export Packets...", ImVec2(150, 0))) {
                ImGui::CloseCurrentPopup();
                ui::resolveUnsaved(state, ui::UnsavedChoice::Export);
            }
            ImGui::SameLine();
            if (ImGui::Button("Discard", ImVec2(120, 0))) {
                ImGui::CloseCurrentPopup();
                ui::resolveUnsaved(state, ui::UnsavedChoice::Discard);
            }
            ImGui::SameLine();
            if (ImGui::Button("Cancel", ImVec2(120, 0))) {
                ImGui::CloseCurrentPopup();
                ui::resolveUnsaved(state, ui::UnsavedChoice::Cancel);
            }
            ImGui::EndPopup();
        }
    }

    void drawCaptureErrorPopup(ui::AppState &state) {
        auto &l = state.live;
        if (l.openError) {
            ImGui::OpenPopup("Capture problem");
            l.openError = false;
        }
        if (ImGui::BeginPopupModal("Capture problem", nullptr, ImGuiWindowFlags_AlwaysAutoResize)) {
            ImGui::TextWrapped("%s", l.errorIsStop ? "The capture stopped with an error. The packets captured so far are kept."
                                                   : "The capture could not be started.");
            ImGui::Separator();
            ImGui::PushTextWrapPos(ImGui::GetFontSize() * 36.0f);
            ImGui::TextWrapped("%s", l.error.c_str());
            ImGui::PopTextWrapPos();
            ImGui::Spacing();
            if (ImGui::Button("OK", ImVec2(120, 0))) ImGui::CloseCurrentPopup();
            ImGui::EndPopup();
        }
    }
} // namespace

bool ui::startCapture(AppState &state, const capture::CaptureOptions &options) {
    auto &l = state.live;
    l.options = options;
    state.settings.captureInterface = options.interfaceName;
    state.settings.captureFilter = options.filter;
    state.settings.captureSnaplen = options.snaplen;
    state.settings.capturePromiscuous = options.promiscuous;
    state.settingsDirty = true;
    return launch(state, options, options.interfaceName, false, [&](capture::LiveCapture &device) { return device.start(options); });
}

bool ui::startInjectedCapture(AppState &state, uint32_t linkType, uint32_t snaplen, const std::string &name) {
    capture::CaptureOptions options;
    options.interfaceName = name;
    options.snaplen = snaplen;
    return launch(state, options, name, true, [&](capture::LiveCapture &device) { return device.beginInjected(linkType, snaplen); });
}

void ui::stopCapture(AppState &state) { finish(state); }

void ui::pollCapture(AppState &state) {
    auto &l = state.live;
    if (!l.processor || !l.device) return;
    drain(state, false);
    if (!l.device->running()) {            // stopped by itself: device error, vanished interface, full disk
        finish(state);
        return;
    }
    if (l.statsPending && steady_clock::now() - l.lastStats >= kStatsInterval) {
        state.stats.dirty = true;
        l.statsPending = false;
        l.lastStats = steady_clock::now();
    }
}

void ui::discardLiveCapture(AppState &state) {
    auto &l = state.live;
    if (l.device) {
        l.device->stop();
        if (l.session) {   // without a session the device's path is stale (an earlier, already removed capture)
            const std::string path = l.device->releaseTempFile();
            if (!path.empty()) {
                std::error_code ec;
                std::filesystem::remove(core::pathFromUtf8(path), ec);
            }
        }
    }
    l.processor.reset();
    l.session = false;
    l.unsaved = false;
    l.injected = false;
    l.scrollToEnd = false;
    l.pending = PendingAction();
    l.openConfirm = false;
}

bool ui::liveUnsaved(const AppState &state) {
    const auto &l = state.live;
    if (!l.session || !l.unsaved) return false;
    const size_t packets = l.capturing() ? static_cast<size_t>(l.device->packetCount()) : state.packets.size();
    return packets > 0;
}

void ui::requestStartCapture(AppState &state) {
    auto &l = state.live;
    if (!capture::liveCaptureAvailable() || l.capturing()) return;
    if (l.options.interfaceName.empty()) {
        l.dialog.open = true;
        l.dialog.needsRefresh = true;
        return;
    }
    request(state, {PendingAction::Start, {}});
}

void ui::requestRestartCapture(AppState &state) {
    if (!capture::liveCaptureAvailable() || !state.live.session || state.live.injected) return;
    request(state, {PendingAction::Restart, {}});
}

void ui::requestOpen(AppState &state, const std::string &path) { request(state, {PendingAction::Open, path}); }
void ui::openDroppedFiles(AppState &state, int count, const char **paths) {
    if (count > 0 && paths && paths[0]) requestOpen(state, paths[0]);
}
void ui::requestClose(AppState &state) { request(state, {PendingAction::Close, {}}); }
void ui::requestQuit(AppState &state) { request(state, {PendingAction::Quit, {}}); }

void ui::resolveUnsaved(AppState &state, UnsavedChoice choice) {
    auto &l = state.live;
    const PendingAction action = std::move(l.pending);
    l.pending = PendingAction();
    l.openConfirm = false;
    switch (choice) {
        case UnsavedChoice::Cancel: break;
        case UnsavedChoice::Discard: perform(state, action); break;
        case UnsavedChoice::Export:
            // the capture ends here so that the export covers everything; the action is asked for again afterwards
            if (l.capturing()) finish(state);
            state.exportDialog.openPopup = true;
            break;
    }
}

std::string ui::captureStatusText(const AppState &state) {
    const auto &l = state.live;
    if (!l.session) return {};
    char buffer[256];
    std::string text;
    if (l.capturing()) {
        std::snprintf(buffer, sizeof buffer, "Capturing on %s %s %llu packets, %llu dropped", l.interfaceName.c_str(), kDash,
                      static_cast<unsigned long long>(l.device->packetCount()), static_cast<unsigned long long>(l.device->droppedCount()));
    } else {
        std::snprintf(buffer, sizeof buffer, "Live capture on %s (stopped)  |  %zu packets", l.interfaceName.c_str(), state.packets.size());
    }
    text = buffer;
    if (state.filter.active) text += "  |  Displayed: " + std::to_string(state.displayedCount()) + " / " + std::to_string(state.packets.size());
    return text;
}

std::string ui::captureUnavailableReason() {
    if (capture::liveCaptureAvailable()) return {};
    return std::string(capture::kNotAvailable) + " (built without libpcap / Npcap; configure with IMSHARK_LIVE_CAPTURE=ON)";
}

void ui::drawCaptureMenu(AppState &state) {
    auto &l = state.live;
    if (!ImGui::BeginMenu("Capture")) return;
    const bool available = capture::liveCaptureAvailable();
    const bool capturing = l.capturing();
    auto note = [&] {
        if (!available && ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled)) ImGui::SetTooltip("%s", captureUnavailableReason().c_str());
    };
    if (ImGui::MenuItem("Interfaces...", "Ctrl+K", false, available)) {
        l.dialog.open = true;
        l.dialog.needsRefresh = true;
    }
    note();
    if (ImGui::MenuItem("Start", "Ctrl+E", false, available && !capturing)) requestStartCapture(state);
    note();
    if (ImGui::MenuItem("Stop", "Ctrl+E", false, available && capturing)) stopCapture(state);
    note();
    if (ImGui::MenuItem("Restart", "Ctrl+R", false, available && l.session && !l.injected)) requestRestartCapture(state);
    note();
    ImGui::Separator();
    ImGui::MenuItem("Auto-scroll During Capture", nullptr, &l.autoScroll);
    ImGui::EndMenu();
}

void ui::handleCaptureShortcuts(AppState &state) {
    const ImGuiIO &io = ImGui::GetIO();
    if (!io.KeyCtrl || !capture::liveCaptureAvailable()) return;
    auto &l = state.live;
    if (ImGui::IsKeyPressed(ImGuiKey_E, false)) {
        if (l.capturing()) stopCapture(state);
        else requestStartCapture(state);
    }
    if (ImGui::IsKeyPressed(ImGuiKey_R, false)) requestRestartCapture(state);
    if (ImGui::IsKeyPressed(ImGuiKey_K, false)) {
        l.dialog.open = true;
        l.dialog.needsRefresh = true;
    }
}

void ui::drawCaptureDialogs(AppState &state) {
    drawInterfacesDialog(state);
    drawUnsavedPopup(state);
    drawCaptureErrorPopup(state);
}
