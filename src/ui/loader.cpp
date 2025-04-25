#include "ui.h"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iostream>

#include <core.h>

namespace {
    bool isPcapng(const std::string &filepath) {
        std::ifstream file(core::pathFromUtf8(filepath), std::ios::binary);
        uint32_t magic = 0;
        return file.read(reinterpret_cast<char *>(&magic), sizeof(magic)) && magic == 0x0A0D0D0A;
    }
} // namespace

void ui::loadCapture(AppState &state, const std::string &path) {
    core::FileProcessor processor;

    state.packets.clear();
    state.clearSelection();
    state.currentFile.clear();
    state.loadMessage.clear();
    state.loadFailed = false;

    if (std::filesystem::is_regular_file(core::pathFromUtf8(path))) {
        const bool ok = isPcapng(path) ? processor.processPcapngFile(path, state.packets, state.loadMessage)
                                       : processor.processPcapFile(path, state.packets, state.loadMessage);
        state.loadFailed = !ok;
        if (ok) state.currentFile = path;
        else state.packets.clear();
    } else {
        state.loadFailed = true;
        state.loadMessage = "Not a regular file: " + path;
    }

    if (!state.loadMessage.empty()) {
        std::cerr << path << ": " << state.loadMessage << std::endl;
        state.openLoadError = true;
    }
}
