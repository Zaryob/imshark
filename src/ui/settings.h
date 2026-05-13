#pragma once

#include <string>
#include <vector>

namespace ui {
    /// User preferences that survive restarts. Stored as a small key=value text file.
    struct Settings {
        static constexpr size_t kMaxRecentFiles = 10;

        std::vector<std::string> recentFiles; // most recent first
        bool darkTheme = true;
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
} // namespace ui
