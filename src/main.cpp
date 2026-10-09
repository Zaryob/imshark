#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <string>
#include <string_view>

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

#include <filter/fields.h>

#include "ui/theme.h"
#include "ui/ui.h"
#include "version.h"

namespace {
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
               "  --             Treat the next argument as a capture file\n";
    }
} // namespace

int main(int argc, char **argv) {
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
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); // 3.2+ only
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

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

    GLFWwindow *window = glfwCreateWindow(windowWidth, windowHeight, "ImShark", nullptr, nullptr);
    if (window == nullptr) {
        glfwTerminate();
        std::cerr << "Failed to create GLFW window" << std::endl;
        return EXIT_FAILURE;
    }
    if (placeWindow) glfwSetWindowPos(window, windowX, windowY);
    glfwSetWindowSizeLimits(window, kMinWidth, kMinHeight, GLFW_DONT_CARE, GLFW_DONT_CARE);
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

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

    if (!ImGui_ImplGlfw_InitForOpenGL(window, true)) {
        std::cerr << "Failed to initialize the ImGui GLFW backend" << std::endl;
        ImGui::DestroyContext();
        glfwDestroyWindow(window);
        glfwTerminate();
        return EXIT_FAILURE;
    }
    if (!ImGui_ImplOpenGL3_Init("#version 150")) {
        std::cerr << "Failed to initialize the ImGui OpenGL backend" << std::endl;
        ImGui_ImplGlfw_Shutdown();
        ImGui::DestroyContext();
        glfwDestroyWindow(window);
        glfwTerminate();
        return EXIT_FAILURE;
    }

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

        ImGui_ImplOpenGL3_NewFrame();
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
        ui::drawMainWindow(state);
        ui::drawStatusBar(state);
        ui::drawLoadErrorPopup(state);
        ui::drawLoadProgressPopup(state);
        ui::saveSettingsIfDirty(state);

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
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

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
