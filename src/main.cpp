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

    GLFWwindow *window = glfwCreateWindow(1280, 720, "ImShark", nullptr, nullptr);
    if (window == nullptr) {
        glfwTerminate();
        std::cerr << "Failed to create GLFW window" << std::endl;
        return EXIT_FAILURE;
    }
    glfwSetWindowSizeLimits(window, 640, 400, GLFW_DONT_CARE, GLFW_DONT_CARE);
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui::GetIO().IniFilename = nullptr; // do not litter the working directory with imgui.ini

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
        if (count > 0) ui::requestOpen(*static_cast<ui::AppState *>(glfwGetWindowUserPointer(w)), paths[0]);
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

    ui::saveSettingsIfDirty(state);

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
