#include "ui.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <thread>

#include <imgui.h>

#include "filter_job.h"
#include "text_input.h"

namespace {
    using ui::AppState;

    /// Stops the running job without waiting for it: a job that is still busy (a pathological regular expression can
    /// spend long on one row) is parked until it ends, so replacing a filter never blocks the UI thread.
    void retireJob(ui::FilterState &f) {
        if (!f.job) return;
        f.job->cancelRequested = true;
        if (!f.job->finished) f.retired.push_back(std::move(f.job));
        f.job.reset();
    }

    /// Makes `filter` the active filter with the given result.
    void commit(AppState &state, const filter::Filter &filter, const std::string &text, std::vector<uint32_t> &&visible) {
        auto &f = state.filter;
        f.applied = filter;
        f.appliedText = text;
        f.active = !filter.isEmpty();
        f.visible = std::move(visible);
        if (!f.active) f.visible.clear();
        // the selected packet stays selected only if it is still displayed
        if (f.active && state.selectedPacket >= 0 &&
            !std::binary_search(f.visible.begin(), f.visible.end(), static_cast<uint32_t>(state.selectedPacket))) {
            state.clearSelection();
        }
        state.orderDirty = true;
        state.stats.dirty = true; // statistics "limited to displayed packets" depend on the filter
    }

    /// Evaluates `filter` over the packets in the background; the result is committed by ui::pollFilter.
    void startJob(AppState &state, const filter::Filter &filter, const std::string &text) {
        auto &f = state.filter;
        retireJob(f);
        if (state.packets.empty()) { // nothing to evaluate
            commit(state, filter, text, {});
            return;
        }
        filter.resetRegexLimitHits(); // the status bar counts the values of this pass only
        auto job = std::make_shared<ui::FilterJob>();
        job->filter = filter;
        job->text = text;
        job->packets = state.packets.share();
        job->total = job->packets->size();
        job->captureStartEpoch = state.captureStartEpoch;
        if (const auto *eth = state.ethernetAddresses()) job->ethernet = *eth;
        if (const auto *ipsec = state.ipsecHeaders()) job->ipsec = *ipsec;
        job->thread = std::thread([raw = job.get()] { raw->run(); });
        f.job = std::move(job);
    }
} // namespace

bool ui::applyFilter(AppState &state, const std::string &text) {
    auto &f = state.filter;
    auto result = filter::Filter::compile(text);
    f.text = text;
    f.previewText = text;
    f.previewOk = result.ok;
    f.previewError = result.error;
    if (!result.ok) return false;

    if (result.filter.isEmpty()) {
        retireJob(f);
        commit(state, result.filter, text, {});
        return true;
    }
    addFilterHistory(state.settings, text);
    state.settingsDirty = true;
    startJob(state, result.filter, text);
    return true;
}

void ui::refilter(AppState &state) {
    auto &f = state.filter;
    // a filter that was still being evaluated is the latest one the user asked for: it applies to the new packets
    const FilterJob *job = f.job.get();
    const bool pending = job != nullptr;
    const filter::Filter target = job ? job->filter : f.applied;
    const std::string targetText = job ? job->text : f.appliedText;
    retireJob(f);
    f.visible.clear(); // indices of the old packets
    if (pending || f.active) startJob(state, target, targetText);
    state.orderDirty = true;
    state.stats.dirty = true;
}

void ui::cancelFilter(AppState &state) { retireJob(state.filter); }

float ui::filterProgress(const AppState &state) {
    const auto &job = state.filter.job;
    if (!job) return -1.0f;
    return job->total ? static_cast<float>(static_cast<double>(job->done.load(std::memory_order_relaxed)) / static_cast<double>(job->total)) : 0.0f;
}

void ui::pollFilter(AppState &state) {
    auto &f = state.filter;
    f.retired.erase(std::remove_if(f.retired.begin(), f.retired.end(), [](const std::shared_ptr<FilterJob> &j) { return j->finished.load(); }),
                    f.retired.end());
    if (!f.job || !f.job->finished) return;
    std::shared_ptr<FilterJob> job = std::move(f.job);
    f.job.reset();
    job->thread.join();
    if (job->failed) return; // keep the previous result

    commit(state, job->filter, job->text, std::move(job->visible));
    // a live capture went on while the job ran: catch up on the rows it did not see
    if (state.packets.size() > job->total || !job->lateAmended.empty()) extendFilter(state, job->total, job->lateAmended);
}

void ui::waitForFilter(AppState &state) {
    while (state.filter.job) {
        pollFilter(state);
        if (state.filter.job) std::this_thread::sleep_for(std::chrono::milliseconds(1));
    }
}

bool ui::applyFilterNow(AppState &state, const std::string &text) {
    const bool ok = applyFilter(state, text);
    waitForFilter(state);
    return ok;
}

bool ui::extendFilter(AppState &state, size_t from, const std::vector<uint32_t> &amended) {
    auto &f = state.filter;
    if (f.job) {
        // a filter is being evaluated over an older snapshot: remember what changed, pollFilter catches up when it is done
        for (uint32_t i: amended) if (i < f.job->total) f.job->lateAmended.push_back(i);
        return false;
    }
    if (!f.active) return false;
    filter::Context context;
    context.captureStartEpoch = state.captureStartEpoch;
    context.ethernet = state.ethernetAddresses();
    context.ipsec = state.ipsecHeaders();
    bool changed = false;
    // earlier rows whose summary was edited in place: their result may differ now (rows >= from are evaluated below)
    for (uint32_t i: amended) {
        if (i >= from || i >= state.packets.size()) continue;
        context.previous = i ? &state.packets[i - 1] : nullptr;
        const bool matches = f.applied.matches(state.packets[i], context);
        const auto it = std::lower_bound(f.visible.begin(), f.visible.end(), i);
        const bool shown = it != f.visible.end() && *it == i;
        if (matches && !shown) {
            f.visible.insert(it, i);
            changed = true;
        } else if (!matches && shown) {
            f.visible.erase(it);
            changed = true;
            if (state.selectedPacket == static_cast<int>(i)) state.clearSelection();   // as refilter(): only displayed rows stay selected
        }
    }
    for (size_t i = from; i < state.packets.size(); ++i) {
        context.previous = i ? &state.packets[i - 1] : nullptr;
        if (f.applied.matches(state.packets[i], context)) f.visible.push_back(static_cast<uint32_t>(i));
    }
    if (from < state.packets.size() || changed) state.stats.dirty = true;
    return changed;
}

void ui::drawFilterBar(AppState &state) {
    auto &f = state.filter;
    pollFilter(state);

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

    if (f.job) {
        const float progress = std::max(0.0f, filterProgress(state));
        char label[48];
        std::snprintf(label, sizeof(label), "Filtering... %d%%", static_cast<int>(progress * 100.0f));
        ImGui::ProgressBar(progress, ImVec2(220, 0), label);
        ImGui::SameLine();
        if (ImGui::Button("Stop")) cancelFilter(state);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Cancel the filter; the previous result stays");
    }
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
                           "(eq ne lt gt le ge), contains, matches (PCRE2 regular expression, Perl-compatible like Wireshark; prefix (?i) to ignore case; a pattern too complex to evaluate counts as no match) and "
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
