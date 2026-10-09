#include "theme.h"

#include <algorithm>

#include <imgui.h>

#include "color_rules.h"

namespace {
    float gDpiScale = 1.0f;

    ImVec4 rgb(unsigned hex, float alpha = 1.0f) {
        return ImVec4(((hex >> 16) & 0xFF) / 255.0f, ((hex >> 8) & 0xFF) / 255.0f, (hex & 0xFF) / 255.0f, alpha);
    }

    ImVec4 accentColor(bool dark, float alpha = 1.0f) {
        return dark ? rgb(0x34B3CF, alpha) : rgb(0x0E7490, alpha);
    }
} // namespace

void ui::setDpiScale(float scale) { gDpiScale = std::max(0.5f, std::min(scale, 4.0f)); }

float ui::dpiScale() { return gDpiScale; }

void ui::applyThemeStyle(bool dark) {
    ImGuiStyle &s = ImGui::GetStyle();
    s = ImGuiStyle();

    // Shape: compact but not cramped, softly rounded.
    s.WindowPadding = ImVec2(8, 8);
    s.FramePadding = ImVec2(8, 4);
    s.CellPadding = ImVec2(6, 2);
    s.ItemSpacing = ImVec2(8, 5);
    s.ItemInnerSpacing = ImVec2(6, 4);
    s.IndentSpacing = 18;
    s.ScrollbarSize = 13;
    s.GrabMinSize = 10;
    s.WindowBorderSize = 1;
    s.ChildBorderSize = 1;
    s.PopupBorderSize = 1;
    s.FrameBorderSize = 0;
    s.TabBorderSize = 0;
    s.WindowRounding = 5;
    s.ChildRounding = 4;
    s.FrameRounding = 4;
    s.PopupRounding = 5;
    s.ScrollbarRounding = 6;
    s.GrabRounding = 3;
    s.TabRounding = 4;
    s.WindowTitleAlign = ImVec2(0.5f, 0.5f);
    s.SeparatorTextBorderSize = 1;
    s.SeparatorTextPadding = ImVec2(16, 3);
    s.ScaleAllSizes(gDpiScale);       // spacing and rounding follow the DPI scale; the font does so through FontScaleDpi
    s.FontSizeBase = 14.0f;
    s.FontScaleDpi = gDpiScale;

    ImVec4 *c = s.Colors;
    if (dark) {
        c[ImGuiCol_Text] = rgb(0xDDE3EA);
        c[ImGuiCol_TextDisabled] = rgb(0x7B8794);
        c[ImGuiCol_WindowBg] = rgb(ui::kDarkWindowBg);
        c[ImGuiCol_ChildBg] = rgb(0x000000, 0.0f);
        c[ImGuiCol_PopupBg] = rgb(0x1C2127, 0.98f);
        c[ImGuiCol_Border] = rgb(0x2C333C);
        c[ImGuiCol_BorderShadow] = rgb(0x000000, 0.0f);
        c[ImGuiCol_FrameBg] = rgb(0x20262D);
        c[ImGuiCol_FrameBgHovered] = rgb(0x28303A);
        c[ImGuiCol_FrameBgActive] = rgb(0x303945);
        c[ImGuiCol_TitleBg] = rgb(0x12151A);
        c[ImGuiCol_TitleBgActive] = rgb(0x1A2027);
        c[ImGuiCol_TitleBgCollapsed] = rgb(0x12151A, 0.8f);
        c[ImGuiCol_MenuBarBg] = rgb(0x1A1F25);
        c[ImGuiCol_ScrollbarBg] = rgb(0x000000, 0.0f);
        c[ImGuiCol_ScrollbarGrab] = rgb(0x3A434E);
        c[ImGuiCol_ScrollbarGrabHovered] = rgb(0x4B5764);
        c[ImGuiCol_ScrollbarGrabActive] = rgb(0x5D6B7A);
        c[ImGuiCol_Button] = rgb(0x2A323B);
        c[ImGuiCol_ButtonHovered] = accentColor(true, 0.45f);
        c[ImGuiCol_ButtonActive] = accentColor(true, 0.70f);
        c[ImGuiCol_Header] = accentColor(true, 0.28f);
        c[ImGuiCol_HeaderHovered] = accentColor(true, 0.42f);
        c[ImGuiCol_HeaderActive] = accentColor(true, 0.58f);
        c[ImGuiCol_Separator] = rgb(0x2C333C);
        c[ImGuiCol_Tab] = rgb(0x1A2027);
        c[ImGuiCol_TabHovered] = accentColor(true, 0.55f);
        c[ImGuiCol_TabSelected] = rgb(0x24404B);
        c[ImGuiCol_TabSelectedOverline] = accentColor(true);
        c[ImGuiCol_TabDimmed] = rgb(0x151A20);
        c[ImGuiCol_TabDimmedSelected] = rgb(0x1E2E36);
        c[ImGuiCol_TabDimmedSelectedOverline] = accentColor(true, 0.5f);
        c[ImGuiCol_TableHeaderBg] = rgb(0x1F252C);
        c[ImGuiCol_TableBorderStrong] = rgb(0x2C333C);
        c[ImGuiCol_TableBorderLight] = rgb(0x242A31);
        c[ImGuiCol_TableRowBg] = rgb(0x000000, 0.0f);
        c[ImGuiCol_TableRowBgAlt] = rgb(0xFFFFFF, 0.025f);
    } else {
        c[ImGuiCol_Text] = rgb(0x1B2530);
        c[ImGuiCol_TextDisabled] = rgb(0x7A8591);
        c[ImGuiCol_WindowBg] = rgb(0xF4F6F8);
        c[ImGuiCol_ChildBg] = rgb(0x000000, 0.0f);
        c[ImGuiCol_PopupBg] = rgb(0xFFFFFF, 0.98f);
        c[ImGuiCol_Border] = rgb(0xCCD3DA);
        c[ImGuiCol_BorderShadow] = rgb(0x000000, 0.0f);
        c[ImGuiCol_FrameBg] = rgb(0xFFFFFF);
        c[ImGuiCol_FrameBgHovered] = rgb(0xEAF3F6);
        c[ImGuiCol_FrameBgActive] = rgb(0xD8E9EF);
        c[ImGuiCol_TitleBg] = rgb(0xE4E8EC);
        c[ImGuiCol_TitleBgActive] = rgb(0xD8DEE4);
        c[ImGuiCol_TitleBgCollapsed] = rgb(0xE4E8EC, 0.8f);
        c[ImGuiCol_MenuBarBg] = rgb(0xE9EDF0);
        c[ImGuiCol_ScrollbarBg] = rgb(0x000000, 0.0f);
        c[ImGuiCol_ScrollbarGrab] = rgb(0xB7C0C9);
        c[ImGuiCol_ScrollbarGrabHovered] = rgb(0x9DA9B5);
        c[ImGuiCol_ScrollbarGrabActive] = rgb(0x84929F);
        c[ImGuiCol_Button] = rgb(0xE1E6EB);
        c[ImGuiCol_ButtonHovered] = accentColor(false, 0.30f);
        c[ImGuiCol_ButtonActive] = accentColor(false, 0.50f);
        c[ImGuiCol_Header] = accentColor(false, 0.20f);
        c[ImGuiCol_HeaderHovered] = accentColor(false, 0.32f);
        c[ImGuiCol_HeaderActive] = accentColor(false, 0.45f);
        c[ImGuiCol_Separator] = rgb(0xCCD3DA);
        c[ImGuiCol_Tab] = rgb(0xDDE3E8);
        c[ImGuiCol_TabHovered] = accentColor(false, 0.45f);
        c[ImGuiCol_TabSelected] = rgb(0xFFFFFF);
        c[ImGuiCol_TabSelectedOverline] = accentColor(false);
        c[ImGuiCol_TabDimmed] = rgb(0xE6EAEE);
        c[ImGuiCol_TabDimmedSelected] = rgb(0xF4F6F8);
        c[ImGuiCol_TabDimmedSelectedOverline] = accentColor(false, 0.5f);
        c[ImGuiCol_TableHeaderBg] = rgb(0xE6EAEE);
        c[ImGuiCol_TableBorderStrong] = rgb(0xCCD3DA);
        c[ImGuiCol_TableBorderLight] = rgb(0xDDE2E7);
        c[ImGuiCol_TableRowBg] = rgb(0x000000, 0.0f);
        c[ImGuiCol_TableRowBgAlt] = rgb(0x000000, 0.03f);
    }
    c[ImGuiCol_CheckMark] = accentColor(dark);
    c[ImGuiCol_SliderGrab] = accentColor(dark, 0.85f);
    c[ImGuiCol_SliderGrabActive] = accentColor(dark);
    c[ImGuiCol_SeparatorHovered] = accentColor(dark, 0.75f);
    c[ImGuiCol_SeparatorActive] = accentColor(dark);
    c[ImGuiCol_ResizeGrip] = accentColor(dark, 0.20f);
    c[ImGuiCol_ResizeGripHovered] = accentColor(dark, 0.60f);
    c[ImGuiCol_ResizeGripActive] = accentColor(dark, 0.90f);
    c[ImGuiCol_TextLink] = accentColor(dark);
    c[ImGuiCol_TextSelectedBg] = accentColor(dark, 0.35f);
    c[ImGuiCol_DragDropTarget] = accentColor(dark);
    c[ImGuiCol_NavCursor] = accentColor(dark);
    c[ImGuiCol_PlotLines] = accentColor(dark);
    c[ImGuiCol_PlotHistogram] = accentColor(dark, 0.85f);
    c[ImGuiCol_ModalWindowDimBg] = rgb(0x000000, dark ? 0.55f : 0.30f);
}

void ui::drawSplitterLine() {
    const bool active = ImGui::IsItemActive();
    const bool hovered = ImGui::IsItemHovered();
    if (hovered || active) ImGui::SetMouseCursor(ImGuiMouseCursor_ResizeNS);
    const ImVec2 min = ImGui::GetItemRectMin();
    const ImVec2 max = ImGui::GetItemRectMax();
    const bool dark = ImGui::GetStyle().Colors[ImGuiCol_WindowBg].x < 0.5f;
    const float y = (min.y + max.y) * 0.5f;
    const float thickness = (active || hovered ? 2.0f : 1.0f) * std::max(1.0f, gDpiScale);
    const ImVec4 color = active ? accentColor(dark) : hovered ? accentColor(dark, 0.75f) : ImGui::GetStyle().Colors[ImGuiCol_Border];
    ImGui::GetWindowDrawList()->AddLine(ImVec2(min.x, y), ImVec2(max.x, y), ImGui::GetColorU32(color), thickness);
}
