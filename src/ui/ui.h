#pragma once

#include <string>

#include "app_state.h"

namespace ui {
    // loader.cpp
    /// Loads a pcap/pcapng file into `state.packets` and updates the status / error fields.
    void loadCapture(AppState &state, const std::string &path);

    // chrome.cpp: menu bar, file dialog, status bar and the load error popup
    void drawMenuAndDialogs(AppState &state);
    void drawStatusBar(const AppState &state);
    void drawLoadErrorPopup(AppState &state);
    float statusBarHeight();

    // packet_list.cpp
    void drawPacketList(AppState &state, float height);

    // details.cpp: protocol tree and hex view of the selected packet
    void drawPacketDetails(AppState &state);

    // main_window.cpp
    void drawMainWindow(AppState &state);
} // namespace ui
