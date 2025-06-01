#pragma once

#include <memory>
#include <string>
#include <vector>

#include <filter/filter.h>
#include <packet/packet_info.h>

#include "settings.h"

namespace ui {
    struct LoadJob; // background load in progress (loader.cpp)

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

        // Display filter and packet list presentation
        FilterState filter;
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
