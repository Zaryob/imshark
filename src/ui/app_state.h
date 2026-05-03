#pragma once

#include <memory>
#include <string>
#include <vector>

#include <packet/packet_info.h>

namespace ui {
    struct LoadJob; // background load in progress (loader.cpp)

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

        // Layout
        float listHeight = 300.0f;                       // height of the packet list (user-adjustable splitter)

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
        }
    };
} // namespace ui
