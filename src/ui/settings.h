#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "color_rules.h"
#include "time_format.h"

namespace ui {
    /// User preferences that survive restarts. Stored as a small key=value text file.
    struct Settings {
        static constexpr size_t kMaxRecentFiles = 10;

        static constexpr size_t kMaxFilterHistory = 15;

        std::vector<std::string> recentFiles; // most recent first
        std::vector<std::string> filterHistory; // applied display filters, most recent first
        bool darkTheme = true;
        TimeFormat timeFormat = TimeFormat::SinceCaptureStart; // Time column
        bool colorize = true;                  // color packet list rows by the coloring rules
        std::vector<ColorRule> colorRules;     // user's rules; empty = use the built-in defaults
        float listHeight = 300.0f;             // height of the packet list (splitter position)
        std::string tlsKeyLogFile;             // TLS (Pre)-Master-Secret log file (SSLKEYLOGFILE format); empty = none
        bool showToolbar = true;               // View > Toolbar
        // Main window geometry (screen coordinates of the content area); 0 = never saved
        int windowWidth = 0, windowHeight = 0;
        int windowX = 0, windowY = 0;
        bool hasWindowPos = false;
        bool espNullHeuristic = false;         // dissect ESP payloads that look unencrypted (ESP-NULL, a guess); off by default

        // Live capture (Capture > Interfaces): what the last capture used
        static constexpr uint32_t kMinSnaplen = 64, kMaxSnaplen = 262144;
        std::string captureInterface;          // empty = none chosen yet
        std::string captureFilter;             // BPF capture filter
        uint32_t captureSnaplen = kMaxSnaplen;
        bool capturePromiscuous = true;

        // Filled in by loadSettings, not persisted
        int loadedVersion = 0;                 // format version found in the file (0 = legacy, no version key)
        bool fromNewerVersion = false;         // the file was written by a newer ImShark; saveSettings leaves it untouched
    };

    /// Current settings file format version, written as `settings_version=` on every save.
    /// 0 = legacy files without the key (migrated to 1 on load: no key changed, so the migration is the identity).
    constexpr int kSettingsVersion = 1;

    /// A rectangle in screen coordinates (window geometry, monitor work area).
    struct WindowRect {
        int x = 0, y = 0, w = 0, h = 0;
    };

    /// The window geometry to create the main window with: the saved size (at least `minW` x `minH`, at most the work area)
    /// and, if a position was saved, that position moved so that the window lies inside `workArea`. Returns false when no
    /// valid size was saved (the caller keeps its default).
    bool restoreWindowRect(const Settings &settings, const WindowRect &workArea, int minW, int minH, WindowRect &out, bool &hasPos);

    /// Per-user location of the settings file (platform config directory).
    std::string defaultSettingsPath();

    /// Reads `path`; a missing or damaged file yields defaults, unknown keys are ignored (and dropped on the next save,
    /// except for files of a newer version, which are never rewritten). Sets `loadedVersion` / `fromNewerVersion`.
    Settings loadSettings(const std::string &path);

    /// Writes `settings` to `path` atomically (temporary file in the same directory, then rename), creating the
    /// directory if needed. Returns false on failure, leaving any existing file intact. Two cases leave the file alone:
    ///  - it was written by a newer ImShark (version > kSettingsVersion): nothing is written and true is returned;
    ///  - it is unreadable as a settings file (corrupt): a copy `<path>.bak-<timestamp>` is made first, and the save
    ///    fails if that copy cannot be made.
    bool saveSettings(const Settings &settings, const std::string &path);

    /// Moves `path` to the front of the recent files (no duplicates, capped at kMaxRecentFiles).
    void addRecentFile(Settings &settings, const std::string &path);

    /// Remembers an applied display filter (most recent first, no duplicates, capped).
    void addFilterHistory(Settings &settings, const std::string &filterText);
} // namespace ui
