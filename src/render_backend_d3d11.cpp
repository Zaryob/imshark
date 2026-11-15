// Direct3D 11 fallback for Windows machines without an OpenGL 3.2 driver (see render_backend.h).
#include "render_backend.h"

#include <cstdint>
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
            desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;
            const D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};

            HRESULT hr = E_FAIL;
            if (allowHardware) {
                hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2, D3D11_SDK_VERSION,
                                                   &desc, &swapChain_, &device_, nullptr, &context_);
            }
            if (FAILED(hr)) {
                // WARP: the software rasterizer that is part of Windows; works without a graphics driver.
                hr = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2, D3D11_SDK_VERSION,
                                                   &desc, &swapChain_, &device_, nullptr, &context_);
                software_ = SUCCEEDED(hr);
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
                if (FAILED(swapChain_->ResizeBuffers(0, static_cast<UINT>(width), static_cast<UINT>(height), DXGI_FORMAT_UNKNOWN, 0))) return;
                width_ = width;
                height_ = height;
                if (!createTarget()) return;
            }
            const float clearColor[4] = {0.45f, 0.55f, 0.60f, 1.00f};
            context_->OMSetRenderTargets(1, &target_, nullptr);
            context_->ClearRenderTargetView(target_, clearColor);
            ImGui_ImplDX11_RenderDrawData(drawData);
            swapChain_->Present(1, 0); // vsync
        }

    private:
        bool createTarget() {
            ID3D11Texture2D *backBuffer = nullptr;
            if (FAILED(swapChain_->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<void **>(&backBuffer)))) return false;
            const HRESULT hr = device_->CreateRenderTargetView(backBuffer, nullptr, &target_);
            backBuffer->Release();
            return SUCCEEDED(hr);
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
    };
} // namespace

std::unique_ptr<RenderBackend> createD3D11Backend(GLFWwindow *window, bool allowHardware, std::string &error) {
    auto backend = std::make_unique<D3D11Backend>();
    if (!backend->create(window, allowHardware, error)) return nullptr;
    return backend;
}
