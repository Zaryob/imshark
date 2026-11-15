#include "pcap_library.h"

#ifdef _WIN32

#include <mutex>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace capture {
    namespace {
        // Only full paths below the system directory: the helper that captures runs with administrator rights, so the
        // library must never come from the program's own directory or the current directory.
        bool loadFrom(const std::wstring &directory) {
            const std::wstring path = directory + L"\\wpcap.dll";
            if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) return false;
            // wpcap.dll needs Packet.dll (and, on Arm64, the DLL it forwards to) from the same directory.
            return LoadLibraryExW(path.c_str(), nullptr, LOAD_WITH_ALTERED_SEARCH_PATH) != nullptr;
        }
    } // namespace

    bool ensurePcapLibrary(std::string &error) {
        static std::mutex mutex;
        static bool loaded = false;
        const std::lock_guard<std::mutex> lock(mutex);
        if (!loaded) { // tried again on every call: Npcap may be installed while the program is running
            wchar_t buffer[MAX_PATH] = {0};
            const UINT length = GetSystemDirectoryW(buffer, MAX_PATH);
            if (length > 0 && length < MAX_PATH) {
                const std::wstring system(buffer, length);
                // Npcap's own directory first; the system directory holds a copy in WinPcap API-compatible mode.
                loaded = loadFrom(system + L"\\Npcap") || loadFrom(system);
            }
        }
        if (!loaded) error = kNpcapMissing;
        return loaded;
    }
} // namespace capture

#else

namespace capture {
    bool ensurePcapLibrary(std::string &) { return true; }
} // namespace capture

#endif
