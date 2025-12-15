// The TLS key log setting: the path is kept in the settings file, the secrets are read into AppState::tlsKeys (UI thread only)
// and every load gets its own copy, so changing them never races with the load pass or with detail building.
#include "ui.h"

#include <imgui.h>

#include <ImGuiFileDialog.h>

#include <tls/crypto.h>

#include "text_input.h"

namespace {
    // "123 secrets for 4 connections; 2 lines ignored (line 7: ...)"
    std::string describe(const tls::KeyStore &store, const tls::KeyLogStats &stats) {
        std::string text = std::to_string(store.secretCount()) + " secret(s) for " + std::to_string(store.entryCount()) + " connection(s)";
        if (stats.malformed > 0) {
            text += "; " + std::to_string(stats.malformed) + " malformed line(s) ignored";
            if (!stats.errors.empty()) text += " (" + stats.errors.front() + ")";
        }
        if (stats.dropped > 0) text += "; " + std::to_string(stats.dropped) + " secret(s) dropped: the key store is full";
        return text;
    }

    // Reads `path` into state.tlsKeys and fills the status line. False if the file cannot be read.
    bool readKeyLog(ui::AppState &state, const std::string &path) {
        state.tlsKeys.clear();
        state.tlsKeyStatus.clear();
        state.tlsKeyStatusIsError = false;
        if (path.empty()) return true;
        tls::KeyStore store;
        tls::KeyLogStats stats;
        std::string error;
        if (!store.loadFile(path, stats, error)) {
            state.tlsKeyStatus = "The TLS key log file could not be read: " + error;
            state.tlsKeyStatusIsError = true;
            return false;
        }
        state.tlsKeys = std::move(store);
        state.tlsKeyStatus = "TLS key log: " + describe(state.tlsKeys, stats);
        return true;
    }
} // namespace

void ui::loadTlsKeyLog(AppState &state) { readKeyLog(state, state.settings.tlsKeyLogFile); }

bool ui::setTlsKeyLogFile(AppState &state, const std::string &path) {
    state.settings.tlsKeyLogFile = path;
    state.settingsDirty = true;
    state.preferences.tlsKeyLogEdit = path;
    const bool ok = readKeyLog(state, path);
    if (state.live.processor) {
        // a live capture cannot decode what it already dissected again: the new keys count from the next packet on
        state.live.processor->sessions().tlsExternalKeys() = state.tlsKeys;
        if (ok && !state.tlsKeyStatus.empty()) state.tlsKeyStatus += " (applies to the packets captured from now on)";
    } else if (state.loading()) {
        // a load is in flight (it took a copy of the old keys): start it again, not the capture on screen
        startLoad(state, loadingPath(state));
    } else if (!state.displayName.empty() && !state.currentFile.empty()) {
        startLoad(state, state.displayName);   // the decryption is decided while loading: load the open capture again
    }
    return ok;
}

void ui::drawPreferencesWindow(AppState &state) {
    auto &p = state.preferences;
    if (!p.open) { p.wasOpen = false; return; }
    if (!p.wasOpen) { p.tlsKeyLogEdit = state.settings.tlsKeyLogFile; p.wasOpen = true; }

    ImGui::SetNextWindowSize(ImVec2(560, 220), ImGuiCond_FirstUseEver);
    if (ImGui::Begin("Preferences", &p.open)) {
        ImGui::SeparatorText("Protocols > TLS");
        ImGui::TextWrapped("(Pre)-Master-Secret log file (the file SSLKEYLOGFILE points to). Captures are decrypted with it while "
                           "they load; secrets inside a pcapng file are used automatically. Changing the file loads the open capture again.");
        const float browseWidth = ImGui::CalcTextSize("Browse...").x + ImGui::GetStyle().FramePadding.x * 2 + ImGui::GetStyle().ItemSpacing.x;
        ImGui::SetNextItemWidth(-browseWidth);
        inputText("##tlskeylog", "path of the key log file", p.tlsKeyLogEdit);
        ImGui::SameLine();
        if (ImGui::Button("Browse...")) {
            IGFD::FileDialogConfig config;
            config.path = ".";
            config.flags = ImGuiFileDialogFlags_Modal;
            ImGuiFileDialog::Instance()->OpenDialog("ChooseTlsKeyLogDlg", "Choose the TLS key log file", ".log,.txt,.keys,.*", config);
        }
        const bool changed = p.tlsKeyLogEdit != state.settings.tlsKeyLogFile;
        if (ImGui::Button(changed ? "Apply" : "Reload")) setTlsKeyLogFile(state, p.tlsKeyLogEdit);
        ImGui::SameLine();
        if (ImGui::Button("Clear")) setTlsKeyLogFile(state, "");
        if (!state.tlsKeyStatus.empty()) {
            ImGui::TextColored(state.tlsKeyStatusIsError ? ImVec4(1.0f, 0.4f, 0.4f, 1.0f) : ImVec4(0.6f, 0.85f, 0.6f, 1.0f), "%s", state.tlsKeyStatus.c_str());
        }
        if (!tls::crypto::available()) {
            ImGui::TextColored(ImVec4(1.0f, 0.8f, 0.3f, 1.0f), "TLS decryption is not available in this build (no OpenSSL).");
        }
    }
    ImGui::End();

    if (ImGuiFileDialog::Instance()->Display("ChooseTlsKeyLogDlg")) {
        if (ImGuiFileDialog::Instance()->IsOk()) setTlsKeyLogFile(state, ImGuiFileDialog::Instance()->GetFilePathName());
        ImGuiFileDialog::Instance()->Close();
    }
}
