#include "settings.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>

namespace {
    namespace fs = std::filesystem;

    std::string env(const char *name) {
        const char *value = std::getenv(name);
        return value ? value : "";
    }

    fs::path pathFromUtf8(const std::string &utf8) {
        return fs::path(std::u8string(reinterpret_cast<const char8_t *>(utf8.data()), utf8.size()));
    }
} // namespace

std::string ui::defaultSettingsPath() {
    fs::path dir;
#if defined(_WIN32)
    dir = env("APPDATA");
#elif defined(__APPLE__)
    if (!env("HOME").empty()) dir = fs::path(env("HOME")) / "Library" / "Application Support";
#else
    if (!env("XDG_CONFIG_HOME").empty()) dir = env("XDG_CONFIG_HOME");
    else if (!env("HOME").empty()) dir = fs::path(env("HOME")) / ".config";
#endif
    if (dir.empty()) return "imshark-settings.ini"; // no home directory: keep it next to the working directory
    return (dir / "imshark" / "settings.ini").string();
}

ui::Settings ui::loadSettings(const std::string &path) {
    Settings settings;
    std::ifstream file(pathFromUtf8(path));
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        const auto eq = line.find('=');
        if (eq == std::string::npos) continue;
        const std::string key = line.substr(0, eq);
        const std::string value = line.substr(eq + 1);
        if (key == "time_format") {
            settings.timeFormat = timeFormatFromKey(value);
        } else if (key == "colorize") {
            settings.colorize = value != "0";
        } else if (key == "colorrule") {
            ColorRule rule;
            if (parseColorRule(value, rule)) settings.colorRules.push_back(rule);
        } else if (key == "theme") {
            settings.darkTheme = value != "light";
        } else if (key == "list_height") {
            try {
                const float h = std::stof(value);
                if (h >= 50.0f && h <= 5000.0f) settings.listHeight = h;
            } catch (...) { /* damaged value: keep the default */ }
        } else if (key == "filter" && !value.empty() && settings.filterHistory.size() < Settings::kMaxFilterHistory) {
            settings.filterHistory.push_back(value);
        } else if (key == "recent" && !value.empty() && settings.recentFiles.size() < Settings::kMaxRecentFiles) {
            settings.recentFiles.push_back(value);
        }
    }
    return settings;
}

bool ui::saveSettings(const Settings &settings, const std::string &path) {
    std::error_code ec;
    const fs::path file = pathFromUtf8(path);
    if (file.has_parent_path()) fs::create_directories(file.parent_path(), ec);

    std::ofstream out(file, std::ios::trunc);
    if (!out) return false;
    out << "theme=" << (settings.darkTheme ? "dark" : "light") << "\n";
    out << "time_format=" << timeFormatKey(settings.timeFormat) << "\n";
    out << "colorize=" << (settings.colorize ? 1 : 0) << "\n";
    out << "list_height=" << settings.listHeight << "\n";
    for (const auto &rule: settings.colorRules) out << "colorrule=" << serializeColorRule(rule) << "\n";
    for (const auto &recent: settings.recentFiles) out << "recent=" << recent << "\n";
    for (const auto &f: settings.filterHistory) out << "filter=" << f << "\n";
    return static_cast<bool>(out);
}

void ui::addRecentFile(Settings &settings, const std::string &path) {
    auto &r = settings.recentFiles;
    r.erase(std::remove(r.begin(), r.end(), path), r.end());
    r.insert(r.begin(), path);
    if (r.size() > Settings::kMaxRecentFiles) r.resize(Settings::kMaxRecentFiles);
}

void ui::addFilterHistory(Settings &settings, const std::string &filterText) {
    if (filterText.empty() || filterText.find('\n') != std::string::npos) return;
    auto &h = settings.filterHistory;
    h.erase(std::remove(h.begin(), h.end(), filterText), h.end());
    h.insert(h.begin(), filterText);
    if (h.size() > Settings::kMaxFilterHistory) h.resize(Settings::kMaxFilterHistory);
}
