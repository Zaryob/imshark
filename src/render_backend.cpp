#include "render_backend.h"

#include <cstdlib>
#include <iostream>
#include <string_view>
#include <vector>

#include <GLFW/glfw3.h>

// Windows only declares OpenGL 1.1 in its <GL/gl.h>; the value is fixed by the OpenGL 1.2 specification.
#ifndef GL_CLAMP_TO_EDGE
#define GL_CLAMP_TO_EDGE 0x812F
#endif
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

namespace {
    class OpenGLBackend final : public RenderBackend {
    public:
        const char *name() const override { return "OpenGL 3.2"; }

        bool initImGui(GLFWwindow *window) override {
            if (!ImGui_ImplGlfw_InitForOpenGL(window, true)) return false;
            if (!ImGui_ImplOpenGL3_Init("#version 150")) {
                ImGui_ImplGlfw_Shutdown();
                return false;
            }
            return true;
        }

        void shutdownImGui() override {
            if (!textures_.empty()) glDeleteTextures(static_cast<GLsizei>(textures_.size()), textures_.data());
            textures_.clear();
            ImGui_ImplOpenGL3_Shutdown();
            ImGui_ImplGlfw_Shutdown();
        }

        void newFrame() override { ImGui_ImplOpenGL3_NewFrame(); }

        ImTextureID createTexture(const unsigned char *rgba, int width, int height) override {
            GLint previousTexture = 0;
            glGetIntegerv(GL_TEXTURE_BINDING_2D, &previousTexture);
            GLuint texture = 0;
            glGenTextures(1, &texture);
            glBindTexture(GL_TEXTURE_2D, texture);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_CLAMP_TO_EDGE);
            glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_CLAMP_TO_EDGE);
            glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, width, height, 0, GL_RGBA, GL_UNSIGNED_BYTE, rgba);
            glBindTexture(GL_TEXTURE_2D, static_cast<GLuint>(previousTexture));
            if (texture) textures_.push_back(texture);
            return static_cast<ImTextureID>(texture);
        }

        void present(GLFWwindow *window, ImDrawData *drawData) override {
            int width = 0, height = 0;
            glfwGetFramebufferSize(window, &width, &height);
            glViewport(0, 0, width, height);
            glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
            glClear(GL_COLOR_BUFFER_BIT);
            ImGui_ImplOpenGL3_RenderDrawData(drawData);
            glfwSwapBuffers(window);
        }

    private:
        std::vector<GLuint> textures_;
    };

    GLFWwindow *createOpenGLWindow(int width, int height, const char *title) {
        glfwDefaultWindowHints();
        glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
        glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
        glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); // 3.2+ only
        glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
        GLFWwindow *window = glfwCreateWindow(width, height, title, nullptr, nullptr);
        if (!window) return nullptr;
        glfwMakeContextCurrent(window);
        glfwSwapInterval(1); // Enable vsync
        return window;
    }
} // namespace

RenderWindow createRenderWindow(int width, int height, const char *title) {
    RenderWindow result;
#ifdef _WIN32
    const char *requested = std::getenv("IMSHARK_RENDERER");
    const std::string_view choice = requested ? requested : "";
    const bool tryOpenGL = choice != "d3d11" && choice != "software";
    const bool tryDirect3D = choice != "opengl";
#else
    const bool tryOpenGL = true;
#endif

    if (tryOpenGL) {
        result.window = createOpenGLWindow(width, height, title);
        if (result.window) {
            result.backend = std::make_unique<OpenGLBackend>();
            return result;
        }
        result.error = "OpenGL 3.2 is not available";
    }
#ifdef _WIN32
    if (tryDirect3D) {
        if (tryOpenGL) std::cerr << "OpenGL 3.2 is not available; trying Direct3D 11" << std::endl;
        glfwDefaultWindowHints();
        glfwWindowHint(GLFW_CLIENT_API, GLFW_NO_API); // Direct3D owns the window surface
        GLFWwindow *window = glfwCreateWindow(width, height, title, nullptr, nullptr);
        if (!window) {
            result.error += result.error.empty() ? "Cannot create the window" : "; cannot create the window for Direct3D 11";
            return result;
        }
        std::string direct3DError;
        result.backend = createD3D11Backend(window, choice != "software", direct3DError);
        if (result.backend) {
            result.window = window;
            result.error.clear();
            return result;
        }
        glfwDestroyWindow(window);
        if (!result.error.empty()) result.error += "; ";
        result.error += direct3DError;
    }
#endif
    return result;
}
