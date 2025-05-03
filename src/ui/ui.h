#pragma once

#include <string>

#include "app_state.h"

namespace ui {
    // loader.cpp
    /// Starts loading a pcap/pcapng file on a background thread. The currently shown capture stays
    /// visible until the new one is complete. A load that is already running is cancelled first.
    void startLoad(AppState &state, const std::string &path);
    /// Call once per frame: publishes a finished load (packets, status, error popup request).
    void pollLoad(AppState &state);
    /// Asks the running load to stop; it is reported as "Cancelled" by the next pollLoad.
    void cancelLoad(AppState &state);
    /// Path of the capture being loaded (empty if none).
    std::string loadingPath(const AppState &state);
    /// Blocking variant of startLoad (used by tests and tools).
    void loadCapture(AppState &state, const std::string &path);

    // chrome.cpp: menu bar, file dialog, status bar and the load error popup
    void drawMenuAndDialogs(AppState &state);
    void drawStatusBar(const AppState &state);
    void drawLoadErrorPopup(AppState &state);
    void drawLoadProgressPopup(AppState &state);
    float statusBarHeight();

    // packet_list.cpp
    void drawPacketList(AppState &state, float height);

    // details.cpp: protocol tree and hex view of the selected packet
    void drawPacketDetails(AppState &state);
    /// Makes sure `state.detail` belongs to the selected packet (reads it from the capture file).
    /// Returns false if there is no selection or the packet could not be read.
    bool ensureDetail(AppState &state);

    // main_window.cpp
    void drawMainWindow(AppState &state);
} // namespace ui
