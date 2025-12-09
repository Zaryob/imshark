#pragma once

#include <string>

#include "app_state.h"

namespace ui {
    // loader.cpp
    /// Starts loading a pcap/pcapng file on a background thread. The currently shown capture stays
    /// visible until the new one is complete. A load that is already running is cancelled first.
    void startLoad(AppState &state, const std::string &path);
    /// Closes the open capture: stops background work, drops the packets and removes temporary files.
    /// A running live capture is stopped and discarded.
    void closeCapture(AppState &state);
    /// The part of closeCapture that clears the packet view and removes the temporary file; it leaves a live
    /// capture device alone (a new capture is started before the old view is dropped).
    void clearCapture(AppState &state);
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

    // preferences.cpp: the TLS key log setting and the Preferences window
    /// Reads the key log file of the settings (start-up; no reload). A file that cannot be read leaves the keys empty and
    /// says why in state.tlsKeyStatus.
    void loadTlsKeyLog(AppState &state);
    /// Makes `path` the TLS key log file ("" = none): the file is read (malformed lines are counted, not fatal), the setting is
    /// remembered and the open capture is loaded again with the new keys. A live capture keeps what it decoded: the keys
    /// apply to the packets that arrive after the change. Returns false if the file could not be read (the keys are then empty
    /// and state.tlsKeyStatus says why).
    bool setTlsKeyLogFile(AppState &state, const std::string &path);
    void drawPreferencesWindow(AppState &state);

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
    /// Live capture: evaluates the active filter for the rows appended since `from` and again for the earlier rows
    /// in `amended` (their summaries were edited in place by reassembly), keeping `filter.visible` sorted. Returns
    /// true if an earlier row appeared in or vanished from the visible set (the displayed order must be rebuilt).
    bool extendFilter(AppState &state, size_t from, const std::vector<uint32_t> &amended);
    void drawFilterBar(AppState &state);
    void drawFilterHelp(AppState &state);

    // color_editor.cpp
    /// (Re)compiles the coloring rules from the settings (or the defaults).
    void recompileColorRules(AppState &state);
    void drawColorRulesWindow(AppState &state);

    // decode_as.cpp
    /// A registry made of the built-in dissectors plus `rules`; null with `error` set if a rule cannot be applied.
    std::shared_ptr<const dissect::Registry> buildRegistry(const std::vector<DecodeAsRule> &rules, std::string &error);
    /// Makes `rules` the Decode As rules and reloads the open capture with them. False (state unchanged) if a rule is invalid.
    bool applyDecodeAs(AppState &state, const std::vector<DecodeAsRule> &rules);
    void drawDecodeAsWindow(AppState &state);

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
    /// Stops background readers of the capture file (search, follow, export). Jobs hold their own snapshot
    /// of the packets, so this is no longer needed for memory safety; it avoids useless work for a capture
    /// that is going away and releases the file (a temporary copy must be deleted, which Windows refuses
    /// while it is open).
    void cancelBackgroundJobs(AppState &state);

    // live_capture.cpp: Capture menu, Interfaces dialog and the live session
    /// Starts a live capture (the previous capture is replaced once the new one runs; a failure keeps it and is
    /// reported through state.live.error + the error popup). Remembers the options in the settings. No confirmation:
    /// see requestStartCapture for the interactive path.
    bool startCapture(AppState &state, const capture::CaptureOptions &options);
    /// Test seam: begins a session that is fed with state.live.device->injectPacket() instead of a device (works in
    /// every build). Everything else (poll, stop, filter, details, export) is the real code path.
    bool startInjectedCapture(AppState &state, uint32_t linkType, uint32_t snaplen, const std::string &name);
    /// Stops the capture, takes over the packets that are still queued and keeps the capture open as a file.
    void stopCapture(AppState &state);
    /// Call once per frame: appends the packets that arrived (bounded work per call), keeps the filter and the list
    /// up to date and finishes a capture that ended on its own (device or write error).
    void pollCapture(AppState &state);
    /// Stops a running capture and forgets the live session; the caller removes AppState::tempFile.
    void discardLiveCapture(AppState &state);
    /// A live capture whose packets were not exported yet (they would be lost by closing/replacing it).
    bool liveUnsaved(const AppState &state);
    /// Interactive entry points: ask first when an unsaved live capture would be lost.
    void requestStartCapture(AppState &state);      // Capture > Start / Ctrl+E (opens the dialog if no interface is chosen)
    void requestRestartCapture(AppState &state);
    void requestOpen(AppState &state, const std::string &path);
    void requestClose(AppState &state);
    void requestQuit(AppState &state);
    enum class UnsavedChoice { Export, Discard, Cancel };
    /// The answer to the "unsaved capture" popup (exposed for tests).
    void resolveUnsaved(AppState &state, UnsavedChoice choice);
    /// "Capturing on en0 - 120 packets, 0 dropped" / "Live capture on en0 (stopped) | 120 packets"; empty without a session.
    std::string captureStatusText(const AppState &state);
    /// Why the Capture menu is disabled (empty if live capture works in this build).
    std::string captureUnavailableReason();
    void drawCaptureMenu(AppState &state);
    void handleCaptureShortcuts(AppState &state);
    void drawCaptureDialogs(AppState &state);

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
