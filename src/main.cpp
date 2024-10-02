#include <imgui/imgui.h>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <pcap/pcap_global_header.h>
#include <pcap/pcap_packet_header.h>

#include <pcap/block_header.h>
#include <ip/ethernet_header.h>

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

#include <GLFW/glfw3.h>
#include <imgui.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>
#include <arpa/inet.h>



struct PacketInfo {
    int number;
    double time;
    std::string source;
    std::string destination;
    std::string protocol;
    uint32_t length;
    std::string info;
    PacketInfo(int num) : number(num){}

    PacketInfo(int num, double t, const std::string& src, const std::string& dest,
               const std::string& proto, uint32_t len, const std::string& inf)
        : number(num), time(t), source(src), destination(dest), protocol(proto), length(len), info(inf) {}
};


void displayPackets(const std::vector<PacketInfo>& packets) {
    if (ImGui::BeginChild("Packet List")) {
        if (ImGui::BeginTable("Packets", 7, ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable)) {
            ImGui::TableSetupColumn("No.");
            ImGui::TableSetupColumn("Time");
            ImGui::TableSetupColumn("Source");
            ImGui::TableSetupColumn("Destination");
            ImGui::TableSetupColumn("Protocol");
            ImGui::TableSetupColumn("Length");
            ImGui::TableSetupColumn("Info");
            ImGui::TableHeadersRow();

            for (const auto& packet : packets) {
                ImGui::TableNextRow();
                ImGui::TableSetColumnIndex(0);
                ImGui::Text("%d", packet.number);
                ImGui::TableSetColumnIndex(1);
                ImGui::Text("%.6lf", packet.time);
                ImGui::TableSetColumnIndex(2);
                ImGui::Text("%s", packet.source.c_str());
                ImGui::TableSetColumnIndex(3);
                ImGui::Text("%s", packet.destination.c_str());
                ImGui::TableSetColumnIndex(4);
                ImGui::Text("%s", packet.protocol.c_str());
                ImGui::TableSetColumnIndex(5);
                ImGui::Text("%u", packet.length);
                ImGui::TableSetColumnIndex(6);
                ImGui::Text("%s", packet.info.c_str());
            }

            ImGui::EndTable();
        }
        ImGui::EndChild();
    }
}

void HexView(const char* title, const char* mem, size_t len,  std::vector<PacketInfo>& packets) {
    if (ImGui::Begin(title)) {
        /*for (size_t i = 0; i < len; i += 16) {
            ImGui::Text("%08X ", i);
            for (size_t j = 0; j < 16 && i + j < len; ++j) {
                ImGui::SameLine();
                ImGui::Text("%02X ", (unsigned char)mem[i + j]);
            }
            ImGui::SameLine(400);
            for (size_t j = 0; j < 16 && i + j < len; ++j) {
                char c = isprint((unsigned char)mem[i + j]) ? mem[i + j] : '.';
                ImGui::Text("%c", c);
            }
        }*/
        displayPackets(packets);
    }
    ImGui::End();
}

bool isPcapng(const std::string& filepath) {
    std::ifstream file(filepath, std::ios::binary);
    uint32_t magic_number;
    if (file.read(reinterpret_cast<char*>(&magic_number), sizeof(magic_number))) {
        // Check against PCAPNG magic numbers
        return (magic_number == 0x0A0D0D0A);
    }
    return false;
}

std::string getMACAddressString(const uint8_t sender_hw_addr[6]) {
    std::ostringstream ss;
    for (int i = 0; i < 6; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(sender_hw_addr[i]);
        if (i < 5) // Don't add a colon after the last byte
            ss << ":";
    }
    return ss.str();
}

void processPcapFile(const std::string& filepath, std::vector<char>& buffer, std::vector<PacketInfo>& packets) {
    std::ifstream file(filepath, std::ios::binary);
    PcapGlobalHeader gHeader;
    file.read(reinterpret_cast<char*>(&gHeader), sizeof(PcapGlobalHeader));

    static int packetNumber = 0;

    if (gHeader.magic_number != 0xa1b2c3d4) {
        std::cerr << "Incompatible PCAP file format" << std::endl;
        return;
    }

    uint32_t tsTimeOffset=0;
    uint32_t usTimeOffset=0;

    while (file.peek() != EOF) {
        PcapPacketHeader pHeader = {0};
        file.read(reinterpret_cast<char*>(&pHeader), sizeof(PcapPacketHeader));

        std::vector<char> packetData(pHeader.incl_len);
        file.read(packetData.data(), pHeader.incl_len);

        PacketInfo pack(++packetNumber);

        if(tsTimeOffset == 0){
            tsTimeOffset = pHeader.ts_sec;
        }
        if(usTimeOffset == 0){
            usTimeOffset = pHeader.ts_usec;
        }

        pack.time = (pHeader.ts_sec ) + 10e-7*(pHeader.ts_usec) - (tsTimeOffset + 10e-7*(usTimeOffset));

        EthernetHeader* ethHeader = reinterpret_cast<EthernetHeader*>(packetData.data());
        if (ntohs(ethHeader->type) == 0x0800) { // IP packet
            IPHeader* ipHeader = reinterpret_cast<IPHeader*>(packetData.data() + sizeof(EthernetHeader));

            struct in_addr dest_addr;
            dest_addr.s_addr = ipHeader->daddr;
            struct in_addr src_addr;
            src_addr.s_addr = ipHeader->saddr;

            std::string destination(inet_ntoa(dest_addr));
            std::string source(inet_ntoa(src_addr));

            pack.destination= destination;
            pack.source = source;


            switch (ipHeader->protocol) {
                case 6: { // TCP
                    TCPHeader* tcpHeader = reinterpret_cast<TCPHeader*>(packetData.data() + sizeof(EthernetHeader) + (ipHeader->ihl * 4));
                    //std::cout << "TCP Packet: Src Port: " << ntohs(tcpHeader->src_port)
                    //          << ", Dest Port: " << ntohs(tcpHeader->dest_port) << std::endl;
                    pack.protocol="TCP";

                    pack.length = pHeader.incl_len;
                    pack.info = std::to_string(ntohs(tcpHeader->src_port)) + " -> " + std::to_string(ntohs(tcpHeader->dest_port));

                    break;
                }
                case 17: { // UDP
                    UDPHeader* udpHeader = reinterpret_cast<UDPHeader*>(packetData.data() + sizeof(EthernetHeader) + (ipHeader->ihl * 4));
                    //std::cout << "UDP Packet: Src Port: " << ntohs(udpHeader->src_port)
                    //          << ", Dest Port: " << ntohs(udpHeader->dest_port) << std::endl;
                    pack.protocol="UDP";
                    pack.length = pHeader.incl_len;
                    pack.info = std::to_string(ntohs(udpHeader->src_port)) + " -> " + std::to_string(ntohs(udpHeader->dest_port));
                    break;
                }
                default:
                    std::cout << "Other IP Protocol: " << static_cast<int>(ipHeader->protocol) << std::endl;
                    pack.protocol="Other";
                    pack.length = pHeader.incl_len;

            }
        } else if (ntohs(ethHeader->type) == 0x0806) { // ARP packet
            ARPHeader* arpHeader = reinterpret_cast<ARPHeader*>(packetData.data() + sizeof(EthernetHeader));
            std::cout << "ARP Packet: Opcode " << ntohs(arpHeader->opcode) << std::endl;
            pack.protocol="ARP";
            pack.destination=getMACAddressString(arpHeader->target_hw_addr);
            pack.source = getMACAddressString(arpHeader->sender_hw_addr);
            pack.length = pHeader.incl_len;
        }

        packets.emplace_back(pack);
    }

    file.close();
}

void processPcapngFile(const std::string& filepath) {
    // Processing logic specific to PCAPNG files
}

int main() {
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return -1;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); // 3.2+ only
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

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
    ImGui_ImplOpenGL3_Init("#version 150");

    std::string filepath = "/Users/zaryob/Downloads/pcapgui/udp.pcap";  // Example file path
    std::vector<char> buffer;
    std::vector<PacketInfo> packets;

    if (isPcapng(filepath)) {
        processPcapngFile(filepath);
    } else {
        processPcapFile(filepath, buffer, packets);
    }

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        HexView("PCAP File Hex Viewer", buffer.data(), buffer.size(),packets);

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


