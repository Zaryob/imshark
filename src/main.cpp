#include <iostream>
#include <string_view>

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

#include <filter/fields.h>

#include "ui/ui.h"
#include "version.h"

int main(int argc, char **argv) {
    // Handled before any window system call so it works headless (and in the packaged app, see ctest imshark_version).
    if (argc > 1 && (std::string_view(argv[1]) == "--version" || std::string_view(argv[1]) == "-V")) {
        std::cout << "imshark " << IMSHARK_VERSION << " (" << IMSHARK_GIT_DESCRIBE << ")" << std::endl;
        return 0;
    }
    // The display filter field table is built here, before the UI exists and before any loader thread starts.
    filter::initFields();
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return -1;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); // 3.2+ only
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

    GLFWwindow *window = glfwCreateWindow(1280, 720, "ImShark", nullptr, nullptr);
    if (window == nullptr) {
        glfwTerminate();
        std::cerr << "Failed to create GLFW window" << std::endl;
        return -1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::StyleColorsDark();
    ImGui::GetIO().IniFilename = nullptr; // do not litter the working directory with imgui.ini

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 150");

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

    if (argc > 1) ui::startLoad(state, argv[1]); // imshark <capture file>

    while (!state.quitRequested) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        ui::pollLoad(state);
        ui::pollCapture(state);
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
    }

    ui::saveSettingsIfDirty(state);

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}
