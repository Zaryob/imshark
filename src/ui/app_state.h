#pragma once

#include <memory>
#include <string>
#include <vector>

#include <filter/filter.h>
#include <packet/packet_info.h>
#include <stats/statistics.h>

#include "color_rules.h"
#include "find.h"
#include "follow_view.h"
#include "settings.h"

namespace ui {
    struct LoadJob;    // background load in progress (loader.cpp)
    struct SearchJob;  // background byte search in progress (find_bar.cpp)
    struct FollowJob;  // background stream reassembly in progress (follow_window.cpp)

    /// The display filter bar: what is typed, what is applied, and which packets pass.
    struct FilterState {
        std::string text;                  // contents of the filter bar (edited live)
        std::string previewText;           // `text` the preview below was compiled from
        bool previewOk = true;             // does `text` compile?
        filter::Error previewError;
        std::string appliedText;           // the filter that is active
        filter::Filter applied;
        bool active = false;               // a non-empty filter is applied
        std::vector<uint32_t> visible;     // indices of packets that pass (valid when active)
        bool focusRequested = false;       // put the keyboard cursor into the bar next frame
        bool showHelp = false;
        std::string helpSearch;            // search box of the reference window
    };

    /// The "Find Packet" bar (Ctrl+F).
    struct FindState {
        bool open = false;
        bool focusRequested = false;
        FindMode mode = FindMode::Text;
        std::string text;
        std::string message;      // result of the last search ("Found ...", "No match", filter error)
        bool messageIsError = false;
        std::shared_ptr<SearchJob> job;   // non-null while a byte search runs in the background
    };

    /// The Statistics windows and their cached results (recomputed lazily when `dirty`).
    struct StatsState {
        bool showHierarchy = false, showConversations = false, showEndpoints = false, showExpert = false;
        bool limitToDisplayed = true;      // count only the packets that pass the display filter
        bool dirty = true;                 // capture or filter changed: caches are stale
        int tab = 0;                       // AddressKind tab that was drawn last in the Conversations / Endpoints windows
        int selectTab = -1;                // request to switch to this tab (then reset)

        std::vector<stats::ExpertItem> expert;
        bool expertValid = false;
        stats::HierarchyNode hierarchy;
        bool hierarchyValid = false;
        std::vector<stats::Conversation> conversations[4];
        bool conversationsValid[4] = {false, false, false, false};
        std::vector<stats::Endpoint> endpoints[4];
        bool endpointsValid[4] = {false, false, false, false};
    };

    /// The Follow Stream window.
    struct FollowState {
        bool open = false;
        std::shared_ptr<FollowJob> job;    // non-null while the stream is being reassembled
        bool valid = false;                // `stream` holds a result
        stream::Stream stream;
        std::string title;
        std::string error;
        FollowView view = FollowView::Ascii;
        FollowDirection direction = FollowDirection::Both;
        std::vector<FollowLine> lines;     // what is drawn (rebuilt when stream/direction/view change)
        bool linesDirty = true;
    };

    /// Everything the UI needs to remember between frames.
    struct AppState {
        std::vector<packet::PacketInfo> packets;

        // Load status
        std::string currentFile;   // path of the capture that is shown (empty if none)
        std::string loadMessage;   // problem reported by the last load (empty when clean)
        bool loadFailed = false;   // the last load produced no usable capture
        bool openLoadError = false; // show the error popup on the next frame

        std::shared_ptr<LoadJob> loadJob;   // non-null while a capture is being loaded in the background

        bool loading() const { return loadJob != nullptr; }

        // Selection
        int selectedPacket = -1;                        // index into `packets`, -1 = none
        // Full view (raw bytes + field tree) of the selected packet, rebuilt from the file when the selection
        // changes; `packets` only holds summaries. `detailIndex` is the packet `detail` was built for.
        packet::PacketInfo detail;
        int detailIndex = -1;
        bool detailOk = false;
        const packet::Field *selectedField = nullptr;    // field picked in the details tree (points into the packet)
        int selectionStart = -1;                         // highlighted byte range in the hex view (inclusive)
        int selectionEnd = -1;
        bool revealSelectedField = false;                // expand the tree down to `selectedField` next frame

        // Coloring rules in effect (compiled from settings.colorRules or the defaults) and the editor window
        CompiledColorRules colors;
        bool showColorRules = false;
        bool colorRulesWereOpen = false;        // editor window state: to detect "just opened"
        std::vector<ColorRule> colorRuleEdit;   // working copy while the editor is open

        // Display filter and packet list presentation
        FilterState filter;
        FindState find;
        StatsState stats;
        FollowState follow;
        double captureStartEpoch = 0;       // UTC epoch seconds of the first packet
        bool orderDirty = true;             // `order` must be rebuilt (new capture or new filter)
        std::vector<uint32_t> order;        // displayed order: indices into `packets` (rebuilt by the list)
        bool scrollToSelection = false;      // bring the selected row into view (keyboard navigation)

        // Preferences, persisted to `settingsPath` when `settingsDirty` is set (see saveSettingsIfDirty)
        Settings settings;
        std::string settingsPath;   // empty = do not persist
        bool settingsDirty = false;

        // Layout
        float listHeight = 300.0f;                       // height of the packet list (user-adjustable splitter)

        size_t displayedCount() const { return filter.active ? filter.visible.size() : packets.size(); }

        bool hasSelection() const { return selectionStart >= 0 && selectionEnd >= selectionStart; }
        bool isSelected(int byte) const { return hasSelection() && byte >= selectionStart && byte <= selectionEnd; }

        const packet::PacketInfo *currentPacket() const {
            return selectedPacket >= 0 && selectedPacket < static_cast<int>(packets.size()) ? &packets[selectedPacket]
                                                                                            : nullptr;
        }

        void clearSelection() {
            selectedPacket = -1;
            detailIndex = -1;
            detailOk = false;
            detail = packet::PacketInfo();
            selectedField = nullptr;
            selectionStart = selectionEnd = -1;
            revealSelectedField = false;
            scrollToSelection = false;
        }

        /// Selects a packet (no-op if it is already selected) and resets the field/byte selection.
        void selectPacket(int index) {
            if (index == selectedPacket) return;
            selectedPacket = index;
            selectedField = nullptr;
            selectionStart = selectionEnd = -1;
        }
    };
} // namespace ui
