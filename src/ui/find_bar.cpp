#include "ui.h"

#include <algorithm>
#include <atomic>
#include <thread>

#include <imgui.h>

#include "text_input.h"

namespace ui {
    /// One background search over the frame bytes. The thread reads `state.packets` (see cancelSearch).
    struct SearchJob {
        std::thread thread;
        core::ScanControl control;
        std::atomic<bool> finished{false};
        std::vector<uint32_t> order;       // snapshot of the displayed order the search ran on
        FindResult result;
        bool cancelled = false;

        ~SearchJob() {
            control.cancelRequested = true;
            if (thread.joinable()) thread.join();
        }
    };
} // namespace ui

void ui::cancelSearch(AppState &state) { state.find.job.reset(); }

void ui::pollSearch(AppState &state) {
    auto &f = state.find;
    if (!f.job || !f.job->finished) return;
    std::shared_ptr<SearchJob> job = std::move(f.job);
    f.job.reset();
    job->thread.join();

    f.messageIsError = false;
    if (job->cancelled) {
        f.message = "Search cancelled";
    } else if (!job->result.error.empty()) {
        f.message = job->result.error;
        f.messageIsError = true;
    } else if (job->result.position < 0) {
        f.message = "No match";
        f.messageIsError = true;
    } else {
        const int packetIndex = static_cast<int>(job->order[job->result.position]);
        state.selectPacket(packetIndex);
        state.scrollToSelection = true;
        f.message = "Packet " + std::to_string(state.packets[packetIndex].number) + "  (row " +
                    std::to_string(job->result.position + 1) + " of " + std::to_string(job->order.size()) + ")";
    }
}

bool ui::findAndSelect(AppState &state, bool forward) {
    auto &f = state.find;
    if (state.order.empty() && state.orderDirty) {
        // the list has not been laid out yet (e.g. right after loading): use the natural order
        state.order = state.filter.active ? state.filter.visible : std::vector<uint32_t>();
        if (!state.filter.active) {
            state.order.resize(state.packets.size());
            for (size_t i = 0; i < state.order.size(); ++i) state.order[i] = static_cast<uint32_t>(i);
        }
    }

    int from = -1;
    if (state.selectedPacket >= 0) {
        const auto it = std::find(state.order.begin(), state.order.end(), static_cast<uint32_t>(state.selectedPacket));
        if (it != state.order.end()) from = static_cast<int>(it - state.order.begin());
    }

    if (f.mode == FindMode::Hex || f.mode == FindMode::BytesText) {
        // searching inside the frames needs the file: run it in the background
        f.messageIsError = true;
        if (state.currentFile.empty() || state.order.empty() || f.text.empty()) { f.message = f.text.empty() ? "" : "No match"; return false; }
        ByteNeedle needle;
        if (f.mode == FindMode::Hex) {
            std::string error;
            const auto parsed = parseHexNeedle(f.text, error);
            if (!parsed) { f.message = error; return false; }
            needle = *parsed;
        } else {
            needle = textNeedle(f.text);
        }
        auto job = std::make_shared<SearchJob>();
        job->order = state.order;
        job->control.total = job->order.size();
        const std::string path = state.currentFile;
        const auto *packets = &state.packets;
        job->thread = std::thread([raw = job.get(), path, packets, needle, from, forward] {
            raw->result = findBytes(path, *packets, raw->order, needle, from, forward, &raw->control, &raw->cancelled);
            raw->finished = true;
        });
        f.job = std::move(job);
        f.message = "Searching...";
        f.messageIsError = false;
        return false; // the match is selected by pollSearch when the job finishes
    }

    const FindResult r = findPacket(state.packets, state.order, state.captureStartEpoch, f.mode, f.text, from, forward);
    f.messageIsError = !r.error.empty();
    if (!r.error.empty()) {
        f.message = r.error;
        return false;
    }
    if (r.position < 0) {
        f.message = f.text.empty() ? "" : "No match";
        f.messageIsError = !f.text.empty();
        return false;
    }

    const int packetIndex = static_cast<int>(state.order[r.position]);
    state.selectPacket(packetIndex);
    state.scrollToSelection = true;
    f.message = "Packet " + std::to_string(state.packets[packetIndex].number) + "  (row " + std::to_string(r.position + 1) +
                " of " + std::to_string(state.order.size()) + ")";
    return true;
}

void ui::drawFindBar(AppState &state) {
    auto &f = state.find;
    const ImGuiIO &io = ImGui::GetIO();
    pollSearch(state);

    if (io.KeyCtrl && ImGui::IsKeyPressed(ImGuiKey_F, false)) {
        f.open = true;
        f.focusRequested = true;
    }
    // F3 / Shift+F3 repeat the last search even while the bar is closed
    if (ImGui::IsKeyPressed(ImGuiKey_F3) && !f.text.empty() && !state.packets.empty()) findAndSelect(state, !io.KeyShift);
    if (!f.open) return;
    if (ImGui::IsKeyPressed(ImGuiKey_Escape) && !ImGui::IsPopupOpen("", ImGuiPopupFlags_AnyPopupId)) {
        f.open = false;
        return;
    }

    ImGui::AlignTextToFramePadding();
    ImGui::TextUnformatted("Find:");
    ImGui::SameLine();
    ImGui::SetNextItemWidth(140);
    int mode = static_cast<int>(f.mode);
    if (ImGui::Combo("##findmode", &mode, "Text in summary\0Display filter\0Hex bytes\0Text in bytes\0")) f.mode = static_cast<FindMode>(mode);
    ImGui::SameLine();
    ImGui::SetNextItemWidth(std::max(120.0f, ImGui::GetContentRegionAvail().x - 210));
    if (f.focusRequested) {
        ImGui::SetKeyboardFocusHere();
        f.focusRequested = false;
    }
    const char *hint = f.mode == FindMode::Text ? "text in source, destination, protocol or info"
                       : f.mode == FindMode::Filter ? "display filter, e.g. tcp.flags.rst"
                       : f.mode == FindMode::Hex ? "bytes in hex, e.g. 47 45 54 20" : "text inside the packet bytes, e.g. password";
    const bool enter = inputText("##findtext", hint,
                                 f.text, ImGuiInputTextFlags_EnterReturnsTrue);
    if (enter) {
        findAndSelect(state, !io.KeyShift);
        f.focusRequested = true; // keep typing / pressing Enter
    }
    ImGui::SameLine();
    if (f.job) {
        if (ImGui::Button("Stop")) f.job->control.cancelRequested = true;
    } else {
        if (ImGui::Button("Prev")) findAndSelect(state, false);
        ImGui::SameLine();
        if (ImGui::Button("Next")) findAndSelect(state, true);
    }
    ImGui::SameLine();
    if (ImGui::Button("Close")) f.open = false;

    if (f.job) {
        ImGui::Text("Searching... %llu / %llu packets", static_cast<unsigned long long>(f.job->control.done.load()),
                    static_cast<unsigned long long>(f.job->control.total.load()));
    } else if (!f.message.empty()) {
        ImGui::TextColored(f.messageIsError ? ImVec4(1.0f, 0.45f, 0.45f, 1.0f) : ImVec4(0.6f, 0.9f, 0.6f, 1.0f), "%s", f.message.c_str());
    }
}
