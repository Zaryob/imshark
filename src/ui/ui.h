#pragma once

#include <string>

#include "app_state.h"

namespace ui {
    // loader.cpp
    /// Starts loading a pcap/pcapng file on a background thread. The currently shown capture stays
    /// visible until the new one is complete. A load that is already running is cancelled first.
    void startLoad(AppState &state, const std::string &path);
    /// Closes the open capture: stops background work, drops the packets and removes temporary files.
    void closeCapture(AppState &state);
    /// Call once per frame: publishes a finished load (packets, status, error popup request).
    void pollLoad(AppState &state);
    /// Asks the running load to stop; it is reported as "Cancelled" by the next pollLoad.
    void cancelLoad(AppState &state);
    /// Path of the capture being loaded (empty if none).
    std::string loadingPath(const AppState &state);
    /// Blocking variant of startLoad (used by tests and tools).
    void loadCapture(AppState &state, const std::string &path);

    // settings (settings.cpp): load at start-up, save when something changed
    void initSettings(AppState &state, const std::string &path);
    void saveSettingsIfDirty(AppState &state);
    void applyTheme(bool dark);

    // chrome.cpp: menu bar, file dialog, status bar and the load error popup
    void drawMenuAndDialogs(AppState &state);
    void drawStatusBar(const AppState &state);
    void drawLoadErrorPopup(AppState &state);
    void drawLoadProgressPopup(AppState &state);
    float statusBarHeight();

    // filter_bar.cpp
    /// Compiles `text` and, if valid, makes it the active filter and recomputes the visible packets.
    /// Returns false (and leaves the previous filter active) if it does not compile; the error is in
    /// state.filter.previewError.
    bool applyFilter(AppState &state, const std::string &text);
    /// Re-evaluates the active filter (after a capture was loaded).
    void refilter(AppState &state);
    void drawFilterBar(AppState &state);
    void drawFilterHelp(AppState &state);

    // color_editor.cpp
    /// (Re)compiles the coloring rules from the settings (or the defaults).
    void recompileColorRules(AppState &state);
    void drawColorRulesWindow(AppState &state);

    // stats_windows.cpp
    void drawStatsWindows(AppState &state);

    // export_dialog.cpp
    /// Packet indices an export of `range` covers: capture order for all/displayed/selected packets.
    std::vector<uint32_t> exportIndices(const AppState &state, ExportState::Range range);
    /// Starts exporting in the background. Returns false if there is nothing to export.
    bool startExport(AppState &state, ExportState::Range range, exporter::Format format, const std::string &path);
    void drawExportDialog(AppState &state);

    // follow_window.cpp
    /// Starts following the TCP/UDP conversation that packet `packetIndex` belongs to. Returns false if the
    /// packet is not TCP/UDP. The result appears in the Follow Stream window when the background job ends.
    bool startFollow(AppState &state, int packetIndex);
    void drawFollowWindow(AppState &state);
    /// Stops background readers of the capture file (search, follow); required before packets change.
    void cancelBackgroundJobs(AppState &state);

    // capture_info_window.cpp
    void drawCaptureInfoWindow(AppState &state);

    // find_bar.cpp
    /// Searches from the selected row (or from the start) and selects the match; updates state.find.message.
    bool findAndSelect(AppState &state, bool forward);
    void drawFindBar(AppState &state);
    /// Publishes a finished background byte search (selects the match, sets the message). Called every frame.
    void pollSearch(AppState &state);
    /// Stops a running byte search and waits for its thread (must happen before `state.packets` changes).
    void cancelSearch(AppState &state);

    // packet_list.cpp
    void drawPacketList(AppState &state, float height);

    enum class SortColumn : int { Number, Time, Source, Destination, Protocol, Length, Info };
    /// Sorts the indices already in `order` by `column` (stable: ties keep the existing order).
    void sortOrder(std::vector<uint32_t> &order, const std::vector<packet::PacketInfo> &packets, SortColumn column, bool ascending);
    /// Fills `order` with all packet indices, sorted by `column` (stable: ties keep capture order).
    void sortPacketOrder(std::vector<uint32_t> &order, const std::vector<packet::PacketInfo> &packets, SortColumn column,
                         bool ascending);

    // details.cpp: protocol tree and hex view of the selected packet
    void drawPacketDetails(AppState &state);
    /// Makes sure `state.detail` belongs to the selected packet (reads it from the capture file).
    /// Returns false if there is no selection or the packet could not be read.
    bool ensureDetail(AppState &state);

    // main_window.cpp
    void drawMainWindow(AppState &state);
} // namespace ui
