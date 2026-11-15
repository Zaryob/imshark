#pragma once

#include <memory>
#include <string>

#include <imgui.h>

struct GLFWwindow;

/// The graphics API behind the main window. OpenGL 3.2 is the first choice on every platform. On Windows, machines
/// without an OpenGL 3.2 driver (virtual machines, remote desktops, x64 emulation on Arm) fall back to Direct3D 11,
/// first on the graphics card and then on WARP, the software rasterizer that ships with Windows and needs no 3D
/// acceleration at all.
class RenderBackend {
public:
    virtual ~RenderBackend() = default;

    /// Short name for messages: "OpenGL 3.2", "Direct3D 11" or "Direct3D 11 (software)".
    virtual const char *name() const = 0;
    /// Starts the ImGui platform and renderer backends for the window. The ImGui context must exist.
    virtual bool initImGui(GLFWwindow *window) = 0;
    /// Stops what initImGui() started and frees the textures made by createTexture().
    virtual void shutdownImGui() = 0;
    /// Per-frame start of the renderer backend; call before ImGui_ImplGlfw_NewFrame().
    virtual void newFrame() = 0;
    /// Uploads a width x height RGBA8 image. Returns 0 when the texture cannot be created.
    virtual ImTextureID createTexture(const unsigned char *rgba, int width, int height) = 0;
    /// Clears the window, draws the ImGui frame and shows it (vsync).
    virtual void present(GLFWwindow *window, ImDrawData *drawData) = 0;
};

/// The window together with the backend that draws into it. `window` is null when no backend could be started; `error`
/// then says why.
struct RenderWindow {
    GLFWwindow *window = nullptr;
    std::unique_ptr<RenderBackend> backend;
    std::string error;
};

/// Creates the main window with the first backend that works. GLFW must be initialised. The environment variable
/// IMSHARK_RENDERER restricts the choice: "opengl", "d3d11" (graphics card, then software) or "software" (WARP only);
/// the last two exist on Windows only. Unset or any other value tries everything in order.
RenderWindow createRenderWindow(int width, int height, const char *title);

#ifdef _WIN32
/// Direct3D 11 backend for a window created without a client API. With allowHardware the graphics card is tried
/// first; WARP is the software fallback. Returns null and fills `error` when no device can be created.
std::unique_ptr<RenderBackend> createD3D11Backend(GLFWwindow *window, bool allowHardware, std::string &error);
#endif
