#pragma once

#include <string>

#include <imgui.h>

namespace ui {
    namespace detail {
        inline int resizeCallback(ImGuiInputTextCallbackData *data) {
            if (data->EventFlag == ImGuiInputTextFlags_CallbackResize) {
                auto *str = static_cast<std::string *>(data->UserData);
                str->resize(static_cast<size_t>(data->BufTextLen));
                data->Buf = str->data();
            }
            return 0;
        }
    } // namespace detail

    /// ImGui text field that edits a std::string directly.
    inline bool inputText(const char *label, const char *hint, std::string &value, ImGuiInputTextFlags flags = 0) {
        flags |= ImGuiInputTextFlags_CallbackResize;
        return ImGui::InputTextWithHint(label, hint, value.data(), value.capacity() + 1, flags, detail::resizeCallback, &value);
    }
} // namespace ui
