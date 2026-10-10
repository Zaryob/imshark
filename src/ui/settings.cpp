#include "settings.h"

#include <algorithm>
#include <charconv>
#include <cstdio>
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
                size_t consumed = 0;
                const float h = std::stof(value, &consumed);
                if (consumed == value.size() && h >= 50.0f && h <= 5000.0f) settings.listHeight = h;
            } catch (...) { /* damaged value: keep the default */ }
        } else if (key == "toolbar") {
            settings.showToolbar = value != "0";
        } else if (key == "window_size") {
            int w = 0, h = 0;
            char tail = 0;
            if (std::sscanf(value.c_str(), "%dx%d%c", &w, &h, &tail) == 2 && w > 0 && h > 0 && w <= 100000 && h <= 100000) {  // NOLINT(cert-err34-c): the result count and a trailing sentinel are checked
                settings.windowWidth = w;
                settings.windowHeight = h;
            }
        } else if (key == "window_pos") {
            int x = 0, y = 0;
            char tail = 0;
            if (std::sscanf(value.c_str(), "%d,%d%c", &x, &y, &tail) == 2 && std::abs(x) <= 1000000 && std::abs(y) <= 1000000) {  // NOLINT(cert-err34-c): the result count and a trailing sentinel are checked
                settings.windowX = x;
                settings.windowY = y;
                settings.hasWindowPos = true;
            }
        } else if (key == "tls_keylog") {
            settings.tlsKeyLogFile = value;
        } else if (key == "esp_null") {
            settings.espNullHeuristic = value == "1";
        } else if (key == "capture_interface") {
            settings.captureInterface = value;
        } else if (key == "capture_filter") {
            settings.captureFilter = value;
        } else if (key == "capture_snaplen") {
            uint32_t n = 0;
            const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), n);
            if (error == std::errc{} && end == value.data() + value.size() && n >= Settings::kMinSnaplen && n <= Settings::kMaxSnaplen) {
                settings.captureSnaplen = n;
            }
        } else if (key == "capture_promiscuous") {
            settings.capturePromiscuous = value != "0";
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
    out << "toolbar=" << (settings.showToolbar ? 1 : 0) << "\n";
    if (settings.windowWidth > 0 && settings.windowHeight > 0) out << "window_size=" << settings.windowWidth << "x" << settings.windowHeight << "\n";
    if (settings.hasWindowPos) out << "window_pos=" << settings.windowX << "," << settings.windowY << "\n";
    // one line per value: a line break in the filter text would corrupt the file
    auto oneLine = [](std::string text) {
        for (char &c: text) if (c == '\n' || c == '\r') c = ' ';
        return text;
    };
    if (!settings.tlsKeyLogFile.empty()) out << "tls_keylog=" << oneLine(settings.tlsKeyLogFile) << "\n";
    if (settings.espNullHeuristic) out << "esp_null=1\n";
    if (!settings.captureInterface.empty()) out << "capture_interface=" << oneLine(settings.captureInterface) << "\n";
    if (!settings.captureFilter.empty()) out << "capture_filter=" << oneLine(settings.captureFilter) << "\n";
    out << "capture_snaplen=" << settings.captureSnaplen << "\n";
    out << "capture_promiscuous=" << (settings.capturePromiscuous ? 1 : 0) << "\n";
    for (const auto &rule: settings.colorRules) out << "colorrule=" << serializeColorRule(rule) << "\n";
    for (const auto &recent: settings.recentFiles) out << "recent=" << oneLine(recent) << "\n";
    for (const auto &f: settings.filterHistory) out << "filter=" << oneLine(f) << "\n";
    out.close(); // report buffered write errors as well as failures opening the file
    return static_cast<bool>(out);
}

void ui::addRecentFile(Settings &settings, const std::string &path) {
    auto &r = settings.recentFiles;
    r.erase(std::remove(r.begin(), r.end(), path), r.end());
    r.insert(r.begin(), path);
    if (r.size() > Settings::kMaxRecentFiles) r.resize(Settings::kMaxRecentFiles);
}

void ui::addFilterHistory(Settings &settings, const std::string &filterText) {
    if (filterText.empty() || filterText.find_first_of("\r\n") != std::string::npos) return;
    auto &h = settings.filterHistory;
    h.erase(std::remove(h.begin(), h.end(), filterText), h.end());
    h.insert(h.begin(), filterText);
    if (h.size() > Settings::kMaxFilterHistory) h.resize(Settings::kMaxFilterHistory);
}

bool ui::restoreWindowRect(const Settings &settings, const WindowRect &workArea, int minW, int minH, WindowRect &out, bool &hasPos) {
    hasPos = false;
    if (settings.windowWidth <= 0 || settings.windowHeight <= 0 || workArea.w <= 0 || workArea.h <= 0) return false;
    out.w = std::min(std::max(settings.windowWidth, minW), std::max(workArea.w, minW));
    out.h = std::min(std::max(settings.windowHeight, minH), std::max(workArea.h, minH));
    out.x = settings.windowX;
    out.y = settings.windowY;
    if (settings.hasWindowPos) {
        hasPos = true;
        out.x = std::max(workArea.x, std::min(out.x, workArea.x + workArea.w - out.w));
        out.y = std::max(workArea.y, std::min(out.y, workArea.y + workArea.h - out.h));
    }
    return true;
}
