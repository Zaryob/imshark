#include <imgui.h>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <pcap/pcap_global_header.h>
#include <pcap/pcap_packet_header.h>

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>


void HexView(const char* title, const char* mem, size_t len) {
    if (ImGui::Begin(title, nullptr, ImGuiWindowFlags_NoCollapse)) {
        for (size_t i = 0; i < len; i += 16) {

            ImGui::Text("%08X ", i);
            for (size_t j = 0; j < 16 && i + j < len; ++j) {
                ImGui::SameLine();
                ImGui::Text("%02X ", (unsigned char)mem[i + j]);
            }
        }
    }
    ImGui::End();
}

int main() {
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return -1;
    }

    GLFWwindow* window = glfwCreateWindow(1280, 720, "PCAP Hex Viewer", nullptr, nullptr);
    if (window == nullptr) {
        glfwTerminate();
        std::cerr << "Failed to create GLFW window" << std::endl;
        return -1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    std::ifstream file("/home/suleymanpoyraz/Downloads/udp.pcap", std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error opening file" << std::endl;
        return 1;
    }

    // Read the global header
    PcapGlobalHeader gHeader;
    file.read(reinterpret_cast<char*>(&gHeader), sizeof(PcapGlobalHeader));

    std::vector<char> buffer(sizeof(PcapGlobalHeader));
    memcpy(buffer.data(), &gHeader, sizeof(PcapGlobalHeader));

    // Read packets
    while (file.peek() != EOF) {
        PcapPacketHeader pHeader;
        file.read(reinterpret_cast<char*>(&pHeader), sizeof(PcapPacketHeader));
        std::vector<char> packetData(pHeader.incl_len);
        file.read(packetData.data(), pHeader.incl_len);

        buffer.insert(buffer.end(), reinterpret_cast<char*>(&pHeader), reinterpret_cast<char*>(&pHeader) + sizeof(PcapPacketHeader));
        buffer.insert(buffer.end(), packetData.begin(), packetData.end());
    }

    file.close();

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        HexView("PCAP File Hex Viewer", buffer.data(), buffer.size());

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);
        glClearColor(0.45f, 0.55f, 0.60f, 1.00f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        glfwSwapBuffers(window);
    }

    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}

