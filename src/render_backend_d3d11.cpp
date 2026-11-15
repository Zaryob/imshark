// Direct3D 11 fallback for Windows machines without an OpenGL 3.2 driver (see render_backend.h).
#include "render_backend.h"

#ifdef _WIN32 // the file is in the Windows build only; the guard keeps tools that read every source file working

#include <cstdint>
#include <iostream>
#include <vector>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

#include <d3d11.h>
#include <dxgi.h>

#define GLFW_EXPOSE_NATIVE_WIN32
#include <GLFW/glfw3.h>
#include <GLFW/glfw3native.h>

#include <imgui_impl_dx11.h>
#include <imgui_impl_glfw.h>

namespace {
    template<typename T>
    void release(T *&object) {
        if (object) object->Release();
        object = nullptr;
    }

    class D3D11Backend final : public RenderBackend {
    public:
        ~D3D11Backend() override {
            for (auto *texture: textures_) texture->Release();
            release(target_);
            release(swapChain_);
            release(context_);
            release(device_);
        }

        /// Creates the device and the swap chain of the window. Tries the graphics card when allowed, then WARP.
        bool create(GLFWwindow *window, bool allowHardware, std::string &error) {
            DXGI_SWAP_CHAIN_DESC desc{};
            desc.BufferCount = 2;
            desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
            desc.OutputWindow = glfwGetWin32Window(window);
            desc.SampleDesc.Count = 1;
            desc.Windowed = TRUE;
            const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};

            // The graphics card first when allowed, then WARP: the software rasterizer that is part of Windows and
            // works without a graphics driver. For each, the flip model (Windows 10 and later, the one the desktop
            // compositor is built for) before the older blit model.
            HRESULT hr = E_FAIL;
            const D3D_DRIVER_TYPE drivers[] = {D3D_DRIVER_TYPE_HARDWARE, D3D_DRIVER_TYPE_WARP};
            const DXGI_SWAP_EFFECT effects[] = {DXGI_SWAP_EFFECT_FLIP_DISCARD, DXGI_SWAP_EFFECT_DISCARD};
            for (const auto driver: drivers) {
                if (driver == D3D_DRIVER_TYPE_HARDWARE && !allowHardware) continue;
                for (const auto effect: effects) {
                    desc.SwapEffect = effect;
                    hr = D3D11CreateDeviceAndSwapChain(nullptr, driver, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &desc,
                                                       &swapChain_, &device_, nullptr, &context_);
                    if (SUCCEEDED(hr)) {
                        software_ = driver == D3D_DRIVER_TYPE_WARP;
                        flipModel_ = effect == DXGI_SWAP_EFFECT_FLIP_DISCARD;
                        break;
                    }
                }
                if (SUCCEEDED(hr)) break;
            }
            if (FAILED(hr)) {
                error = "Direct3D 11 is not available (error 0x" + hex(static_cast<unsigned long>(hr)) + ")";
                return false;
            }
            // GLFW handles the keyboard; DXGI must not switch to full screen on Alt+Enter by itself.
            IDXGIFactory *factory = nullptr;
            if (SUCCEEDED(swapChain_->GetParent(__uuidof(IDXGIFactory), reinterpret_cast<void **>(&factory)))) {
                factory->MakeWindowAssociation(desc.OutputWindow, DXGI_MWA_NO_ALT_ENTER);
                factory->Release();
            }
            glfwGetFramebufferSize(window, &width_, &height_);
            if (!createTarget()) {
                error = "Cannot create the Direct3D 11 render target";
                return false;
            }
            return true;
        }

        const char *name() const override { return software_ ? "Direct3D 11 (software)" : "Direct3D 11"; }

        bool initImGui(GLFWwindow *window) override {
            if (!ImGui_ImplGlfw_InitForOther(window, true)) return false;
            if (!ImGui_ImplDX11_Init(device_, context_)) {
                ImGui_ImplGlfw_Shutdown();
                return false;
            }
            return true;
        }

        void shutdownImGui() override {
            for (auto *texture: textures_) texture->Release();
            textures_.clear();
            ImGui_ImplDX11_Shutdown();
            ImGui_ImplGlfw_Shutdown();
        }

        void newFrame() override { ImGui_ImplDX11_NewFrame(); }

        ImTextureID createTexture(const unsigned char *rgba, int width, int height) override {
            D3D11_TEXTURE2D_DESC desc{};
            desc.Width = static_cast<UINT>(width);
            desc.Height = static_cast<UINT>(height);
            desc.MipLevels = 1;
            desc.ArraySize = 1;
            desc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
            desc.SampleDesc.Count = 1;
            desc.Usage = D3D11_USAGE_DEFAULT;
            desc.BindFlags = D3D11_BIND_SHADER_RESOURCE;
            D3D11_SUBRESOURCE_DATA data{};
            data.pSysMem = rgba;
            data.SysMemPitch = desc.Width * 4;
            ID3D11Texture2D *texture = nullptr;
            if (FAILED(device_->CreateTexture2D(&desc, &data, &texture))) return 0;
            ID3D11ShaderResourceView *view = nullptr;
            const HRESULT hr = device_->CreateShaderResourceView(texture, nullptr, &view);
            texture->Release(); // the view keeps the texture alive
            if (FAILED(hr)) return 0;
            textures_.push_back(view);
            return static_cast<ImTextureID>(reinterpret_cast<uintptr_t>(view));
        }

        void present(GLFWwindow *window, ImDrawData *drawData) override {
            int width = 0, height = 0;
            glfwGetFramebufferSize(window, &width, &height);
            if (width <= 0 || height <= 0) return; // minimized
            if (width != width_ || height != height_ || !target_) {
                context_->OMSetRenderTargets(0, nullptr, nullptr);
                release(target_);
                const HRESULT resized = swapChain_->ResizeBuffers(0, static_cast<UINT>(width), static_cast<UINT>(height), DXGI_FORMAT_UNKNOWN, 0);
                if (FAILED(resized)) return reportOnce("resize its buffers", resized);
                width_ = width;
                height_ = height;
                if (!createTarget()) return reportOnce("create its render target", E_FAIL);
            }
            const float clearColor[4] = {0.45f, 0.55f, 0.60f, 1.00f};
            context_->OMSetRenderTargets(1, &target_, nullptr); // every frame: the flip model unbinds it on Present
            context_->ClearRenderTargetView(target_, clearColor);
            ImGui_ImplDX11_RenderDrawData(drawData);
            const HRESULT presented = swapChain_->Present(1, 0); // vsync
            if (FAILED(presented)) reportOnce("present a frame", presented);
        }

        /// One line for the console: what the swap chain ended up as.
        std::string description() const {
            return std::string(name()) + (flipModel_ ? ", flip model" : ", blit model") + ", " + std::to_string(width_) + "x" + std::to_string(height_);
        }

    private:
        bool createTarget() {
            ID3D11Texture2D *backBuffer = nullptr;
            if (FAILED(swapChain_->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<void **>(&backBuffer)))) return false;
            const HRESULT hr = device_->CreateRenderTargetView(backBuffer, nullptr, &target_);
            backBuffer->Release();
            return SUCCEEDED(hr);
        }

        // A failure repeats every frame; say it once.
        void reportOnce(const char *what, HRESULT hr) {
            if (reported_) return;
            reported_ = true;
            std::cerr << "Direct3D 11 cannot " << what << " (error 0x" << hex(static_cast<unsigned long>(hr)) << ")" << std::endl;
        }

        static std::string hex(unsigned long value) {
            static const char digits[] = "0123456789ABCDEF";
            std::string text(8, '0');
            for (int i = 7; i >= 0; --i, value >>= 4) text[static_cast<size_t>(i)] = digits[value & 0xF];
            return text;
        }

        ID3D11Device *device_ = nullptr;
        ID3D11DeviceContext *context_ = nullptr;
        IDXGISwapChain *swapChain_ = nullptr;
        ID3D11RenderTargetView *target_ = nullptr;
        std::vector<ID3D11ShaderResourceView *> textures_;
        int width_ = 0, height_ = 0;
        bool software_ = false;
        bool flipModel_ = false;
        bool reported_ = false;
    };
} // namespace

std::unique_ptr<RenderBackend> createD3D11Backend(GLFWwindow *window, bool allowHardware, std::string &error) {
    auto backend = std::make_unique<D3D11Backend>();
    if (!backend->create(window, allowHardware, error)) return nullptr;
    std::cerr << "Using " << backend->description() << std::endl;
    return backend;
}

#endif // _WIN32
