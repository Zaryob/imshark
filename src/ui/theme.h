#pragma once

namespace ui {
    /// Extra scale of the interface on top of the framebuffer scale (window system scaling on Windows/Linux; 1 on macOS,
    /// where the framebuffer scale already covers Retina). Call before applyTheme().
    void setDpiScale(float scale);
    float dpiScale();

    /// Fills the ImGui style (sizes, fonts scale and colors) for the dark or light theme. Used by applyTheme().
    void applyThemeStyle(bool dark);

    /// Draws the line of a splitter bar: call right after the InvisibleButton of the splitter. A faint rule at rest, the
    /// accent color and a resize cursor while hovered or dragged.
    void drawSplitterLine();
} // namespace ui
