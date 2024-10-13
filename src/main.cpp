#include <imgui/imgui.h>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>
#include <unordered_map>
#include <filesystem>

#include <GLFW/glfw3.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>



#include <core.h>
#include <map>
#include <arpa/inet.h>

#include <packet/packet_parser.h>
#include <packet/packet_info.h>

#include <network/utils.h>

std::map<std::string, std::vector<std::string> > packetState;

int selectedPacket = -1; // Index of the selected packet
int oldSelectedPacket = -1; // Index of the selected packet


std::tuple<std::string, std::string> toHexString(const std::vector<char> &data, size_t offset, size_t length) {
    std::ostringstream hexStream, charStream;
    std::string hexDisplay, textDisplay;
    size_t end = offset + length;
    int bytesPerLine = 16;

    for (size_t i = 0; i < data.size(); ++i) {
        unsigned char byte = data[i];
        hexStream << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte) << " ";
        charStream << (std::isprint(byte) ? static_cast<char>(byte) : '.');

        if ((i + 1) % bytesPerLine == 0 || i == data.size() - 1) {
            // Align the last line by filling spaces if it's shorter than the rest
            if (i == data.size() - 1 && (i + 1) % bytesPerLine != 0) {
                int remainingBytes = bytesPerLine - (i + 1) % bytesPerLine;
                for (int j = 0; j < remainingBytes; ++j) {
                    hexStream << "   "; // Fill with spaces for missing hex bytes
                }
            }

            // Append current line to the final display
            hexDisplay += hexStream.str() + "\n";
            textDisplay += charStream.str() + "\n";
            hexStream.str("");
            charStream.str("");
        }
    }

    return std::make_tuple(hexDisplay, textDisplay);
}

// Function to process the l2 header
void processL2(const packet::PacketInfo &packet) {
    packetState["L2"] = {};

    std::visit([](auto &&header) {
        using T = std::decay_t<decltype(header)>;
        if constexpr (std::is_same_v<T, network::EthernetHeader>) {
            packetState["L2"] = {
                "Destination MAC: " + network::getMACAddressString(header.dest_mac),
                "Source MAC: " +  network::getMACAddressString(header.src_mac),
                "Type: " + std::to_string(header.type)
            };
        }
    }, packet.l2_header);
}

// Function to process the l3 header
void processL3(const packet::PacketInfo &packet) {
    packetState["L3"] = {};
    std::visit([](auto &&header) {
        using T = std::decay_t<decltype(header)>;
        if constexpr (std::is_same_v<T, network::ARPHeader>) {
            packetState["L3"] = {"ARP Packet"};
        } else if constexpr (std::is_same_v<T, network::IPHeader>) {
            struct in_addr dest_addr;
            dest_addr.s_addr = header.dst_addr;
            struct in_addr src_addr;
            src_addr.s_addr = header.src_addr;
            packetState["L3"] = {
                "Version: " + std::to_string(header.version),
                "IHL: " + std::to_string(header.ihl),
                "Total Length: " + std::to_string(header.tot_length),
                "Identification: " + std::to_string(header.id),
                "Flags: " + std::to_string(header.flags),
                "Fragment Offset: " + std::to_string(header.frag_off),
                "TTL: " + std::to_string(header.ttl),
                "Protocol: " + std::to_string(header.protocol),
                "Header Checksum: " + std::to_string(header.check),
                "Source IP: " + std::string(inet_ntoa(src_addr)),
                "Destination IP: " + std::string(inet_ntoa(dest_addr))
            };
        } else if constexpr (std::is_same_v<T, network::IPv6Header>) {
            packetState["L3"] = {
                "Version: " + std::to_string(header.version),
                "Traffic Class: " + std::to_string(header.traffic_class),
                "Flow Label: " + std::to_string(header.flow_label),
                "Payload Length: " + std::to_string(header.payload_len),
                "Next Header: " + std::to_string(header.next_header),
                "Hop Limit: " + std::to_string(header.hop_limit)
            };
        }
    }, packet.l3_header);
}

// Function to process the l4 header
void processL4(const packet::PacketInfo &packet) {
    packetState["L4"] = {};
    std::visit([](auto &&header) {
        using T = std::decay_t<decltype(header)>;
        if constexpr (std::is_same_v<T, network::ICMPHeader>) {
            packetState["L4"] = {"ICMP Header"};
        } else if constexpr (std::is_same_v<T, network::TCPHeader>) {
            packetState["L4"] = {
                "TCP Header",
                "Source Port: " + std::to_string(header.src_port),
                "Destination Port: " + std::to_string(header.dest_port),
                "Sequence Number: " + std::to_string(header.seq_num),
                "Acknowledgement Number: " + std::to_string(header.ack_num),
                "Data Offset: " + std::to_string(header.data_offset),
                "Flags: " + std::to_string(header.flags),
                "Window Size: " + std::to_string(header.window),
                "Checksum: " + std::to_string(header.checksum),
                "Urgent Pointer: " + std::to_string(header.urgent_pointer)
            };
        } else if constexpr (std::is_same_v<T, network::UDPHeader>) {
            packetState["L4"] = {
                "Source Port: " + std::to_string(header.src_port),
                "Destination Port: " + std::to_string(header.dest_port),
                "Length: " + std::to_string(header.len),
                "Checksum: " + std::to_string(header.checksum)
            };
        }
    }, packet.l4_header);
}

// Function to process the l7 header
void processL7(const packet::PacketInfo &packet) {
    std::visit([](auto &&header) {
        using T = std::decay_t<decltype(header)>;
        if constexpr (std::is_same_v<T, network::DHCPHeader>) {
            ImGui::TextUnformatted("DHCP Header");
        } else if constexpr (std::is_same_v<T, network::DNSHeader>) {
            ImGui::TextUnformatted("DNS Header");
        }
    }, packet.l7_header);
}

int selected_byte_start = -1; // Track the start of the selection range
int selected_byte_end = -1;   // Track the end of the selection range
bool is_selecting = false;    // Track whether the user is selecting a range

void RenderHexEditor(std::vector<char> memory_buffer)
{
    ImGui::BeginChild("Hex Editor");

    const int bytes_per_row = 16; // Number of bytes per row

    // Create two separate regions for Hex and ASCII
    ImGui::BeginChild("HexArea", ImVec2(ImGui::GetContentRegionAvail().x * 0.7f, ImGui::GetContentRegionAvail().y), true);

    // Display column numbers for the hex section
    bool b;

    ImGui::Selectable("Address : ", &b, ImGuiSelectableFlags_Disabled, ImVec2(70, 20)); // Empty space to align column numbers with the hex values
    ImGui::SameLine();

    for (int col = 0; col < bytes_per_row; ++col)
    {
        char hex_str[3]; // Two characters for hex and one for null-terminator
        snprintf(hex_str, sizeof(hex_str), "%02X", col);

        ImGui::Selectable(hex_str, &b, ImGuiSelectableFlags_Disabled, ImVec2(20, 20));

        ImGui::SameLine();
    }
    ImGui::NewLine();
    // Loop over rows for hex values
    for (int row = 0; row < (int(memory_buffer.size()) + bytes_per_row - 1) / bytes_per_row; ++row)
    {
        // Draw address offset
        char addr_str[10]; // Two characters for hex and one for null-terminator
        snprintf(addr_str, sizeof(addr_str), "%08X: ", row * bytes_per_row);
        ImGui::Selectable(addr_str, &b, ImGuiSelectableFlags_Disabled, ImVec2(70, 20));

        ImGui::SameLine();

        //std::cout<<"S:"<<selected_byte_start<<" E:"<<selected_byte_end<<std::endl;

        // Draw hex values for each row
        for (int col = 0; col < bytes_per_row; ++col)
        {
            int index = row * bytes_per_row + col;
            if (index < memory_buffer.size())
            {
                ImGui::PushID(index); // Ensure unique ID for each byte

                // Get the byte value and format it as hex
                unsigned char byte = memory_buffer[index];
                char hex_str[3]; // Two characters for hex and one for null-terminator
                snprintf(hex_str, sizeof(hex_str), "%02X", byte);

                //  std::cout << "Byte: " << byte << " Hex: " << hex_str << " sel_start " <<selected_byte_start<<" sel_end "<<selected_byte_end<<  std::endl;

                // Determine if this byte is within the selected range
                bool is_selected = (selected_byte_start != -1 && selected_byte_end != -1 &&
                                    ((index >= selected_byte_start && index <= selected_byte_end) ||
                                    (index >= selected_byte_end && index <= selected_byte_start)));

                // Highlight selected bytes
                if (is_selected)
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f)); // Text color for selected byte
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.6f, 0.9f, 1.0f)); // Background color for selected byte
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.7f, 1.0f, 1.0f)); // Hover color for selected byte
                }

                // Make the hex value selectable
                if (ImGui::Selectable(hex_str, is_selected, ImGuiSelectableFlags_None, ImVec2(20, 20)))
                {
                    selected_byte_start = index; // Set start of selection
                    // Optional: Handle byte selection actions, like copying to clipboard
                    ImGui::SetClipboardText(hex_str); // Copy hex value to clipboard
                }

                if (is_selected)
                {
                    ImGui::PopStyleColor(3); // Restore original style
                }

                // Handle mouse events
                if (ImGui::IsItemHovered() && ImGui::IsMouseDown(ImGuiMouseButton_Left) && !is_selecting) // Mouse click to start selection
                {
                    selected_byte_end = index;   // End starts at the same place initially
                    is_selecting = true;
                }

                if (ImGui::IsItemHovered() && ImGui::IsMouseDown(ImGuiMouseButton_Left) && is_selecting) // Mouse is being dragged
                {
                    selected_byte_end = index; // Update the end of the selection range
                }
                else if (ImGui::IsMouseReleased(ImGuiMouseButton_Left) && is_selecting) // Mouse button released
                {
                    is_selecting = false; // Stop selecting after release
                }


                ImGui::PopID(); // Restore ID

                if (col < bytes_per_row - 1)
                    ImGui::SameLine(); // Keep hex values in the same row
            }
            else
            {
                ImGui::Text("   "); // Empty space for unused bytes
            }
        }
    }

    ImGui::EndChild(); // End Hex area

    // ASCII Area
    ImGui::SameLine();
    ImGui::BeginChild("ASCIIArea", ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y), true);

    // Display column numbers for the ASCII section
    ImGui::Selectable( "ASCII", &b, ImGuiSelectableFlags_Disabled|ImGuiSelectableFlags_Highlight, ImVec2(205, 20)); // Empty space to align column numbers with the hex values

    // Loop over rows for ASCII characters
    for (int row = 0; row < (int(memory_buffer.size()) + bytes_per_row - 1) / bytes_per_row; ++row)
    {
        // Draw address offset
        ImGui::Text("%08X: ", row * bytes_per_row);
        ImGui::SameLine();

        for (int col = 0; col < bytes_per_row; ++col)
        {
            int index = row * bytes_per_row + col;
            if (index < memory_buffer.size())
            {
                // Convert byte to printable ASCII (or dot for non-printable)
                char c = memory_buffer[index];
                std::string ascii_str(1, (c >= 32 && c <= 126) ? c : '.');

                // Highlight ASCII part if the byte is within the selected range
                bool is_selected = (selected_byte_start != -1 && selected_byte_end != -1 &&
                                    ((index >= selected_byte_start && index <= selected_byte_end) ||
                                    (index >= selected_byte_end && index <= selected_byte_start)));

                if (is_selected)
                {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f)); // Text color for selected byte
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.6f, 0.9f, 1.0f)); // Background color for selected byte
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.7f, 1.0f, 1.0f)); // Hover color for selected byte
                }

                if (ImGui::Selectable(ascii_str.c_str(), is_selected, ImGuiSelectableFlags_None, ImVec2(10, 20)))
                {
                    ImGui::SetClipboardText(ascii_str.c_str()); // Copy ASCII character to clipboard
                }

                if (is_selected)
                {
                    ImGui::PopStyleColor(3); // Restore original style
                }

                if (col < bytes_per_row - 1)
                    ImGui::SameLine(0, 3.0f); // Adjust spacing between ASCII characters
            }
            else
            {
                ImGui::Text(" "); // Empty space for unused bytes
            }
        }
    }

    ImGui::EndChild(); // End ASCII area

    ImGui::EndChild(); // End Hex Editor window
}


static float splitter_size = 5.0f;
static float top_height = 300.0f; // Adjust this value as needed to set the initial height of the packet list

void displayPackets(const std::vector<packet::PacketInfo> &packets) {
    // Get Available Window Size
    ImVec2 windowSize = ImGui::GetContentRegionAvail();

    if (selectedPacket != -1) {
        top_height = windowSize.y / 2;
    } else {
        top_height = windowSize.y;
    }
    // Top window: Packet list
    ImGui::BeginChild("Packet List", ImVec2(0, top_height), true, ImGuiWindowFlags_AlwaysUseWindowPadding);
    if (ImGui::BeginTable("Packets", 7,
                          ImGuiTableFlags_Resizable | ImGuiTableFlags_Reorderable | ImGuiTableFlags_Hideable)) {
        ImGui::TableSetupColumn("No.");
        ImGui::TableSetupColumn("Time");
        ImGui::TableSetupColumn("Source");
        ImGui::TableSetupColumn("Destination");
        ImGui::TableSetupColumn("Protocol");
        ImGui::TableSetupColumn("Length");
        ImGui::TableSetupColumn("Info");
        ImGui::TableHeadersRow();

        for (const auto &packet: packets) {
            ImGui::TableNextRow();
            ImGui::TableSetColumnIndex(0);
            //ImGui::Text("%d", packet.number);
            if (ImGui::Selectable(std::to_string(packet.number).c_str(), selectedPacket == packet.number,
                                  ImGuiSelectableFlags_SpanAllColumns)) {
                selectedPacket = packet.number;
            }
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

    // Packet data window
    if (selectedPacket != -1 && selectedPacket != oldSelectedPacket) {
        oldSelectedPacket = selectedPacket;
        packetState.clear();
        packet::PacketInfo packet = packets.at(selectedPacket - 1);
        processL2(packet);
        processL3(packet);
        processL4(packet);
    }

    if (selectedPacket != -1) {
        // Handle splitter resizing
        if (ImGui::IsItemActive()) {
            top_height -= ImGui::GetIO().MouseDelta.y;
        }

        // Bottom window: Packet details
        ImGui::BeginChild("Packet Details", ImVec2(0, windowSize.y - top_height - 10), true,
                          ImGuiWindowFlags_AlwaysUseWindowPadding);

        //if(ImGui::Begin("Packet Details")){
        packet::PacketInfo packet = packets.at(selectedPacket - 1);
        ImGui::Text("Packet Info: %s", packet.info.c_str());
        ImGui::Separator();


        // Frame Details
        if (ImGui::TreeNode("Frame Details")) {
            std::string frameInfo = "Frame Number: " + std::to_string(packet.number) + "\n";
            ImGui::TextUnformatted(frameInfo.c_str());
            //ImGui::TextUnformatted(packet.frameInfo.c_str());
            ImGui::TreePop();
        }

        // Data Link Layer Details
        if (ImGui::TreeNode("Data Link Layer")) {
            for (const auto &value: packetState["L2"]) {
                ImGui::TextUnformatted(value.c_str());
            }
            //ImGui::TextUnformatted(packet.linkLayerInfo.c_str());
            ImGui::TreePop();
        }

        // Network Layer Details
        if (ImGui::TreeNode("Network Layer")) {
            for (const auto &value: packetState["L3"]) {
                ImGui::TextUnformatted(value.c_str());
            }
            //ImGui::TextUnformatted(packet.networkLayerInfo.c_str());
            ImGui::TreePop();
        }

        // Transport Layer Details
        if (ImGui::TreeNode("Transport Layer")) {
            for (const auto &value: packetState["L4"]) {
                ImGui::TextUnformatted(value.c_str());
            }
            //ImGui::TextUnformatted(packet.transportLayerInfo.c_str());
            ImGui::TreePop();
        }

        if (!packet.raw_data.empty()) {
            RenderHexEditor(packet.raw_data);
            /*
            // Convert raw data to hex and text format
            std::string hexStr, textStr;
            std::tie(hexStr, textStr) = toHexString(packet.raw_data, 0, packet.raw_data.size());

            // Start the first column for Hex
            ImGui::BeginChild("HexWindow", ImVec2(ImGui::GetContentRegionAvail().x * 0.5f, 0), true);
            ImGui::InputTextMultiline("##hex_data", &hexStr[0], hexStr.size(),
                                      ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 16), ImGuiInputTextFlags_ReadOnly);
            ImGui::EndChild();

            ImGui::SameLine(); // Place the next column on the same line

            // Start the second column for Text
            ImGui::BeginChild("TextWindow", ImVec2(ImGui::GetContentRegionAvail().x * 0.5f, 0), true);
            ImGui::InputTextMultiline("##text_data", &textStr[0], textStr.size(),
                                      ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 16), ImGuiInputTextFlags_ReadOnly);
            ImGui::EndChild();
            */
        }
        ImGui::EndChild();
    }
}

void HexView(const char *title, const char *mem, size_t len, std::vector<packet::PacketInfo> &packets) {
#ifdef IMGUI_HAS_VIEWPORT
    ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->GetWorkPos());
    ImGui::SetNextWindowSize(viewport->GetWorkSize());
    ImGui::SetNextWindowViewport(viewport->ID);
#else
    ImGui::SetNextWindowPos(ImVec2(0.0f, 0.0f));
    ImGui::SetNextWindowSize(ImGui::GetIO().DisplaySize);
#endif
    //ImGui::PushStyleVar(ImGuiStyleVar_WindowRounding, 0.0f);

    bool show = true;
    if (ImGui::Begin(title)) {
        //,&show,ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse)) {
        displayPackets(packets);
    }
    ImGui::End();
    //ImGui::PopStyleVar(2);
}

bool isPcapng(const std::string &filepath) {
    std::ifstream file(filepath, std::ios::binary);
    uint32_t magic_number;
    if (file.read(reinterpret_cast<char *>(&magic_number), sizeof(magic_number))) {
        // Check against PCAPNG magic numbers
        return (magic_number == 0x0A0D0D0A);
    }
    return false;
}

#include <set>

// Global state to store selected hex values
std::set<size_t> selectedIndices;


int main() {
    core::FileProcessor fileProcessor;
    if (!glfwInit()) {
        std::cerr << "Failed to initialize GLFW" << std::endl;
        return -1;
    }
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE); // 3.2+ only
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);

    GLFWwindow *window = glfwCreateWindow(1280, 720, "PCAP Hex Viewer", nullptr, nullptr);
    if (window == nullptr) {
        glfwTerminate();
        std::cerr << "Failed to create GLFW window" << std::endl;
        return -1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // Enable vsync

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO &io = ImGui::GetIO();
    (void) io;
    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 150");

    //std::string filepath = "/Users/zaryob/Downloads/udp.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/netlink-nflog.pcap";  // Example file path
    std::string filepath = "/Users/zaryob/Downloads/iperf3-udp.pcapng";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/ipv4frags.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/dhcp.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/telnet-raw.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/bgpsec.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/smtp.pcap"; // Example file path
    //std::string filepath =  "/home/suleymanpoyraz/Downloads/nn.pcapng";
    std::vector<char> buffer;
    std::vector<packet::PacketInfo> packets;

    // std::cout <<"Sizeof Vector"<<sizeof(std::vector<char>)<<std::endl<<
    //           "Sizeof BlockHeader "<<sizeof(BlockHeader)<<std::endl<<
    //           "Sizeof Interface Description Block "<<sizeof(InterfaceDescriptionBlock)<<std::endl<<
    //           "Sizeof Simple Packet Block "<<sizeof(SimplePacketBlock)<<std::endl<<
    //           "Sizeof Section Header Block "<<sizeof(SectionHeaderBlock)<<std::endl;

    if (std::filesystem::is_regular_file(filepath)) {
        if (isPcapng(filepath)) {
            fileProcessor.processPcapngFile(filepath, packets);
        } else {
            fileProcessor.processPcapFile(filepath, packets);
        }
    } else {
        std::cerr << "Invalid file path: " << filepath << std::endl;
    }

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        HexView("PCAP File Viewer", buffer.data(), buffer.size(), packets);


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


