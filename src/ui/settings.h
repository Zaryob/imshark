#pragma once

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
    };

    /// Per-user location of the settings file (platform config directory).
    std::string defaultSettingsPath();

    /// Reads `path`; a missing or damaged file yields defaults, unknown keys are ignored.
    Settings loadSettings(const std::string &path);

    /// Writes `settings` to `path`, creating the directory if needed. Returns false on failure.
    bool saveSettings(const Settings &settings, const std::string &path);

    /// Moves `path` to the front of the recent files (no duplicates, capped at kMaxRecentFiles).
    void addRecentFile(Settings &settings, const std::string &path);

    /// Remembers an applied display filter (most recent first, no duplicates, capped).
    void addFilterHistory(Settings &settings, const std::string &filterText);
} // namespace ui
