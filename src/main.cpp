#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>
#include <vector>

#include <GLFW/glfw3.h>

#include <imgui.h>
#include <imgui_impl_glfw.h>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

#include <capture/capture_worker.h>
#include <filter/fields.h>

#include "render_backend.h"
#include "ui/theme.h"
#include "ui/ui.h"
#include "version.h"
#include "brand_assets.h"

#define STB_IMAGE_IMPLEMENTATION
#define STBI_ONLY_PNG
#define STBI_NO_STDIO
#include <stb_image.h>

namespace {
    ImTextureID loadTextureFromMemory(RenderBackend &backend, const unsigned char *data, size_t size) {
        int width = 0, height = 0, channels = 0;
        unsigned char *pixels = stbi_load_from_memory(data, static_cast<int>(size),
                                                     &width, &height, &channels, STBI_rgb_alpha);
        if (!pixels) {
            std::cerr << "Cannot decode the embedded logo: " << stbi_failure_reason() << std::endl;
            return 0;
        }
        const ImTextureID texture = backend.createTexture(pixels, width, height);
        stbi_image_free(pixels);
        return texture;
    }

    // A program started by double-click has no console: without this the user would see nothing at all.
    void reportStartupFailure(const std::string &message) {
        std::cerr << message << std::endl;
#ifdef _WIN32
        MessageBoxA(nullptr, message.c_str(), "ImShark", MB_OK | MB_ICONERROR);
#endif
    }

    void setWindowIcon(GLFWwindow *window) {
#ifndef __APPLE__
        // macOS uses the .icns resource in the application bundle; GLFW supplies Windows/Linux title-bar icons.
        int channels = 0;
        GLFWimage icon{};
        icon.pixels = stbi_load_from_memory(brand::kIconPng, static_cast<int>(sizeof(brand::kIconPng)),
                                           &icon.width, &icon.height, &channels, STBI_rgb_alpha);
        if (icon.pixels) {
            glfwSetWindowIcon(window, 1, &icon);
            stbi_image_free(icon.pixels);
        }
#else
        (void) window;
#endif
    }

    std::string captureWindowTitle(const ui::AppState &state) {
        if (state.displayName.empty()) return "ImShark";
        std::string name = state.displayName;
        if (!state.live.session) {
            const auto filename = core::pathFromUtf8(name).filename().u8string();
            name.assign(filename.begin(), filename.end());
        }
        return name + " (" + std::to_string(state.packets.size()) + " packets) - ImShark";
    }

    void printUsage(std::ostream &out) {
        out << "Usage: imshark [OPTIONS] [CAPTURE_FILE]\n"
               "\nOpen a capture file or start the graphical packet analyzer.\n"
               "\nOptions:\n"
               "  -h, --help     Show this help and exit\n"
               "  -V, --version  Show the version and exit\n"
               "  --capture-worker ...  Internal: the capture helper started with administrator rights (see\n"
               "                 docs/CAPTURE_PRIVILEGES.md); not meant to be run by hand\n"
               "  --             Treat the next argument as a capture file\n";
    }
} // namespace

int main(int argc, char **argv) {
    // The privileged capture worker (started by the GUI through pkexec / osascript) must not initialise anything of the
    // window system or the UI: it opens the device, drops its privileges and streams packets (docs/CAPTURE_PRIVILEGES.md).
    if (argc > 1 && std::string_view(argv[1]) == "--capture-worker") {
        return capture::worker::runCaptureWorker(std::vector<std::string>(argv + 2, argv + argc));
    }

    // Handle command-line queries before touching the window system so they also work headless.
    const char *capturePath = nullptr;
    if (argc > 1) {
        const std::string_view arg(argv[1]);
        if (argc == 2 && (arg == "--help" || arg == "-h")) {
            printUsage(std::cout);
            return EXIT_SUCCESS;
        }
        if (argc == 2 && (arg == "--version" || arg == "-V")) {
            std::cout << "imshark " << IMSHARK_VERSION << " (" << IMSHARK_GIT_DESCRIBE << ")" << std::endl;
            return EXIT_SUCCESS;
        }
        if (arg == "--" && argc == 3) {
            capturePath = argv[2];
        } else if (argc == 2 && !arg.empty() && arg.front() != '-') {
            capturePath = argv[1];
        } else {
            std::cerr << "Invalid arguments.\n\n";
            printUsage(std::cerr);
            return EXIT_FAILURE;
        }
    }
    // The display filter field table is built here, before the UI exists and before any loader thread starts.
    filter::initFields();
    glfwSetErrorCallback([](int code, const char *description) {
        std::cerr << "GLFW error " << code << ": " << description << std::endl;
    });
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return EXIT_FAILURE;
    }

    // Size and position of the last session, moved into the work area of the monitor they were on
    constexpr int kMinWidth = 640, kMinHeight = 400;
    int windowWidth = 1280, windowHeight = 720, windowX = 0, windowY = 0;
    bool placeWindow = false;
    {
        const ui::Settings saved = ui::loadSettings(ui::defaultSettingsPath());
        int count = 0;
        GLFWmonitor **monitors = glfwGetMonitors(&count);
        GLFWmonitor *best = glfwGetPrimaryMonitor();
        long long bestOverlap = -1;
        for (int i = 0; saved.hasWindowPos && monitors && i < count; ++i) {
            int mx, my, mw, mh;
            glfwGetMonitorWorkarea(monitors[i], &mx, &my, &mw, &mh);
            const long long ox = std::max(0, std::min(saved.windowX + saved.windowWidth, mx + mw) - std::max(saved.windowX, mx));
            const long long oy = std::max(0, std::min(saved.windowY + saved.windowHeight, my + mh) - std::max(saved.windowY, my));
            if (ox * oy > bestOverlap) {
                bestOverlap = ox * oy;
                best = monitors[i];
            }
        }
        if (best) {
            ui::WindowRect area;
            glfwGetMonitorWorkarea(best, &area.x, &area.y, &area.w, &area.h);
            ui::WindowRect rect;
            if (ui::restoreWindowRect(saved, area, kMinWidth, kMinHeight, rect, placeWindow)) {
                windowWidth = rect.w;
                windowHeight = rect.h;
                windowX = rect.x;
                windowY = rect.y;
            }
        }
    }

    // OpenGL 3.2, or on Windows Direct3D 11 when the machine has no OpenGL driver (render_backend.h)
    RenderWindow renderWindow = createRenderWindow(windowWidth, windowHeight, "ImShark");
    GLFWwindow *window = renderWindow.window;
    if (window == nullptr) {
        glfwTerminate();
        reportStartupFailure("ImShark cannot open its window: " + renderWindow.error + ".\n\n"
#ifdef _WIN32
                             "It needs OpenGL 3.2 or Direct3D 11. Update the graphics driver, or turn on 3D acceleration "
                             "if this is a virtual machine."
#else
                             "It needs a desktop session with OpenGL 3.2."
#endif
        );
        return EXIT_FAILURE;
    }
    RenderBackend &backend = *renderWindow.backend;
    setWindowIcon(window);
    if (placeWindow) glfwSetWindowPos(window, windowX, windowY);
    glfwSetWindowSizeLimits(window, kMinWidth, kMinHeight, GLFW_DONT_CARE, GLFW_DONT_CARE);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().IniFilename = nullptr; // do not litter the working directory with imgui.ini
    {
        // Crisp text on scaled displays: the backend already covers the framebuffer scale (Retina), the window system
        // scale on top of it (Windows/Linux) is applied through the style's font scale and sizes.
        float contentScaleX = 1.0f, contentScaleY = 1.0f;
        glfwGetWindowContentScale(window, &contentScaleX, &contentScaleY);
        int logicalWidth = 0, framebufferWidth = 0, unused = 0;
        glfwGetWindowSize(window, &logicalWidth, &unused);
        glfwGetFramebufferSize(window, &framebufferWidth, &unused);
        const float framebufferScale = logicalWidth > 0 ? static_cast<float>(framebufferWidth) / logicalWidth : 1.0f;
        ui::setDpiScale(framebufferScale > 0.0f ? contentScaleX / framebufferScale : 1.0f);
        ImFontConfig fontConfig;
        fontConfig.SizePixels = 14.0f;
        ImGui::GetIO().Fonts->AddFontDefaultVector(&fontConfig);
    }

    if (!backend.initImGui(window)) {
        ImGui::DestroyContext();
        const std::string backendName = backend.name();
        renderWindow.backend.reset(); // before the window it draws into
        glfwDestroyWindow(window);
        glfwTerminate();
        reportStartupFailure("ImShark cannot start its " + backendName + " renderer.");
        return EXIT_FAILURE;
    }

    const ImTextureID logoForLightMode = loadTextureFromMemory(backend, brand::kLogoPng, sizeof(brand::kLogoPng));
    const ImTextureID logoForDarkMode = loadTextureFromMemory(backend, brand::kLogoLightPng, sizeof(brand::kLogoLightPng));
    ui::AppState state;
    ui::initSettings(state, ui::defaultSettingsPath());
    ui::applyTheme(state.settings.darkTheme);

    // Dropping a file on the window opens it
    glfwSetWindowUserPointer(window, &state);
    glfwSetDropCallback(window, [](GLFWwindow *w, int count, const char **paths) {
        ui::openDroppedFiles(*static_cast<ui::AppState *>(glfwGetWindowUserPointer(w)), count, paths);
    });
    // Closing the window asks about an unsaved live capture first; the loop ends when state.quitRequested is set
    glfwSetWindowCloseCallback(window, [](GLFWwindow *w) {
        glfwSetWindowShouldClose(w, GLFW_FALSE);
        ui::requestQuit(*static_cast<ui::AppState *>(glfwGetWindowUserPointer(w)));
    });

    if (capturePath) ui::startLoad(state, capturePath);
    std::string windowTitle = "ImShark";

    while (!state.quitRequested) {
        glfwPollEvents();

        backend.newFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ui::pollLoad(state);
        ui::pollCapture(state);
        const std::string nextTitle = captureWindowTitle(state);
        if (nextTitle != windowTitle) {
            windowTitle = nextTitle;
            glfwSetWindowTitle(window, windowTitle.c_str());
        }
        ui::drawMenuAndDialogs(state);
        const ImTextureID currentLogoTexture = state.settings.darkTheme ? logoForDarkMode : logoForLightMode;
        ui::drawMainWindow(state, ImTextureRef(currentLogoTexture));
        ui::drawStatusBar(state);
        ui::drawLoadErrorPopup(state);
        ui::drawLoadProgressPopup(state);
        ui::saveSettingsIfDirty(state);

        ImGui::Render();
        backend.present(window, ImGui::GetDrawData());
        // A minimized window may not be throttled by vsync; keep background capture/load jobs responsive at 10 Hz.
        if (glfwGetWindowAttrib(window, GLFW_ICONIFIED)) glfwWaitEventsTimeout(0.1);
    }

    // Remember the window geometry (not while minimized or maximized: those sizes are not the user's own)
    if (!glfwGetWindowAttrib(window, GLFW_ICONIFIED) && !glfwGetWindowAttrib(window, GLFW_MAXIMIZED)) {
        int w = 0, h = 0, x = 0, y = 0;
        glfwGetWindowSize(window, &w, &h);
        glfwGetWindowPos(window, &x, &y);
        if (w > 0 && h > 0 && (w != state.settings.windowWidth || h != state.settings.windowHeight || !state.settings.hasWindowPos ||
                                x != state.settings.windowX || y != state.settings.windowY)) {
            state.settings.windowWidth = w;
            state.settings.windowHeight = h;
            state.settings.windowX = x;
            state.settings.windowY = y;
            state.settings.hasWindowPos = true;
            state.settingsDirty = true;
        }
    }
    ui::saveSettingsIfDirty(state);

    backend.shutdownImGui(); // also frees the logo textures
    ImGui::DestroyContext();
    renderWindow.backend.reset(); // before the window it draws into
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
