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
#include <imgui_internal.h>
#include <map>
#include <arpa/inet.h>

#include <packet/packet_parser.h>
#include <packet/packet_info.h>

#include <network/utils.h>

std::map<std::string, std::pair<std::vector<std::string>, std::vector<std::pair<int, int> > > > packetState;

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
                {
                    "Destination MAC: " + network::getMACAddressString(header.dest_mac),
                    "Source MAC: " + network::getMACAddressString(header.src_mac),
                    "Type: " + std::to_string(header.type)
                },
                {{0, 5}, {6, 11}, {12, 13}}
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
            packetState["L3"] = {{"ARP Packet"}, {{0, 27}}};
        } else if constexpr (std::is_same_v<T, network::IPHeader>) {
            struct in_addr dest_addr;
            dest_addr.s_addr = header.dst_addr;
            struct in_addr src_addr;
            src_addr.s_addr = header.src_addr;
            packetState["L3"] = {
                {
                    "Version: " + std::to_string(header.version),
                    "IHL: " + std::to_string(header.ihl),
                    "Type of Service: " + std::to_string(header.tos),
                    "Total Length: " + std::to_string(header.tot_length),
                    "Identification: " + std::to_string(header.id),
                    "Flags: " + std::to_string(header.flags),
                    "Fragment Offset: " + std::to_string(header.frag_off),
                    "TTL: " + std::to_string(header.ttl),
                    "Protocol: " + std::to_string(header.protocol),
                    "Header Checksum: " + std::to_string(header.check),
                    "Source IP: " + std::string(inet_ntoa(src_addr)),
                    "Destination IP: " + std::string(inet_ntoa(dest_addr))
                },
                {{0, 0}, {0, 0}, {1, 1}, {2, 3}, {4, 5}, {6, 6}, {7, 7}, {8, 8}, {9, 9}, {10, 11}, {12, 15}, {16, 19}}
            };
        } else if constexpr (std::is_same_v<T, network::IPv6Header>) {
            packetState["L3"] = {
                {
                    "Version: " + std::to_string(header.version),
                    "Traffic Class: " + std::to_string(header.traffic_class),
                    "Flow Label: " + std::to_string(header.flow_label),
                    "Payload Length: " + std::to_string(header.payload_len),
                    "Next Header: " + std::to_string(header.next_header),
                    "Hop Limit: " + std::to_string(header.hop_limit),
                    "Source IP: " + network::getIPv6AddressString(header.src_addr),
                    "Destination IP: " + network::getIPv6AddressString(header.dst_addr)
                },
                {{0, 3}, {0, 3}, {0, 3}, {4, 5}, {6, 6}, {7, 7}, {8, 23}, {24, 39}}
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
            packetState["L4"] = {{"ICMP Header"}, {{0, 7}}};
        } else if constexpr (std::is_same_v<T, network::TCPHeader>) {
            packetState["L4"] = {
                {
                    "Source Port: " + std::to_string(header.src_port),
                    "Destination Port: " + std::to_string(header.dest_port),
                    "Sequence Number: " + std::to_string(header.seq_num),
                    "Acknowledgement Number: " + std::to_string(header.ack_num),
                    "Data Offset: " + std::to_string(header.data_offset),
                    "Flags: " + std::to_string(header.flags),
                    "Window Size: " + std::to_string(header.window),
                    "Checksum: " + std::to_string(header.checksum),
                    "Urgent Pointer: " + std::to_string(header.urgent_pointer)
                },
                {{0, 1}, {2, 3}, {4, 7}, {8, 11}, {12, 12}, {13, 13}, {14, 15}, {16, 17}, {18, 19}}
            };
        } else if constexpr (std::is_same_v<T, network::UDPHeader>) {
            packetState["L4"] = {
                {
                    "Source Port: " + std::to_string(header.src_port),
                    "Destination Port: " + std::to_string(header.dest_port),
                    "Length: " + std::to_string(header.len),
                    "Checksum: " + std::to_string(header.checksum)
                },
                {{0, 1}, {2, 3}, {4, 5}, {6, 7}}
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
int selected_byte_end = -1; // Track the end of the selection range
//bool is_selecting = false; // Track whether the user is selecting a range

int selected_byte = -1;

void RenderHexEditor(std::vector<char> memory_buffer) {
    ImGui::BeginChild("Hex Editor");

    const int bytes_per_row = 16; // Number of bytes per row

    // Create two separate regions for Hex and ASCII
    ImGui::BeginChild("HexArea", ImVec2(ImGui::GetContentRegionAvail().x * 0.7f, ImGui::GetContentRegionAvail().y),
                      true);

    // Display column numbers for the hex section
    bool b;

    ImGui::Selectable("Address : ", &b, ImGuiSelectableFlags_Disabled, ImVec2(70, 20));
    // Empty space to align column numbers with the hex values
    ImGui::SameLine();

    for (int col = 0; col < bytes_per_row; ++col) {
        char hex_str[3]; // Two characters for hex and one for null-terminator
        snprintf(hex_str, sizeof(hex_str), "%02X", col);

        ImGui::Selectable(hex_str, &b, ImGuiSelectableFlags_Disabled, ImVec2(20, 20));

        ImGui::SameLine();
    }
    ImGui::NewLine();

    // Loop over rows for hex values
    for (int row = 0; row < (int(memory_buffer.size()) + bytes_per_row - 1) / bytes_per_row; ++row) {
        // Draw address offset
        char addr_str[10]; // Two characters for hex and one for null-terminator
        snprintf(addr_str, sizeof(addr_str), "%08X: ", row * bytes_per_row);
        ImGui::Selectable(addr_str, &b, ImGuiSelectableFlags_Disabled, ImVec2(70, 20));

        ImGui::SameLine();

        //std::cout<<"S:"<<selected_byte_start<<" E:"<<selected_byte_end<<std::endl;

        // Draw hex values for each row
        for (int col = 0; col < bytes_per_row; ++col) {
            int index = row * bytes_per_row + col;
            if (index < memory_buffer.size()) {
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
                if (is_selected) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
                    // Text color for selected byte
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.6f, 0.9f, 1.0f));
                    // Background color for selected byte
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.7f, 1.0f, 1.0f));
                    // Hover color for selected byte
                }

                // Make the hex value selectable
                if (ImGui::Selectable(hex_str, is_selected, ImGuiSelectableFlags_None, ImVec2(20, 20))) {
                    selected_byte = index; // Set start of selection
                    // Optional: Handle byte selection actions, like copying to clipboard
                    ImGui::SetClipboardText(hex_str); // Copy hex value to clipboard
                }

                if (is_selected) {
                    ImGui::PopStyleColor(3); // Restore original style
                }

                // Handle mouse events
                //if (ImGui::IsItemHovered() && ImGui::IsMouseDown(ImGuiMouseButton_Left) && !is_selecting)
                // Mouse click to start selection
                //{
                //    selected_byte_end = index; // End starts at the same place initially
                //    is_selecting = true;
                //}

                //if (ImGui::IsItemHovered() && ImGui::IsMouseDown(ImGuiMouseButton_Left) && is_selecting)
                // Mouse is being dragged
                //{
                //    selected_byte_end = index; // Update the end of the selection range
                //} else if (ImGui::IsMouseReleased(ImGuiMouseButton_Left) && is_selecting) // Mouse button released
                //{
                //    is_selecting = false; // Stop selecting after release
                //}


                ImGui::PopID(); // Restore ID

                if (col < bytes_per_row - 1)
                    ImGui::SameLine(); // Keep hex values in the same row
            } else {
                ImGui::Text("   "); // Empty space for unused bytes
            }
        }
    }

    ImGui::EndChild(); // End Hex area

    // ASCII Area
    ImGui::SameLine();
    ImGui::BeginChild("ASCIIArea", ImVec2(ImGui::GetContentRegionAvail().x, ImGui::GetContentRegionAvail().y), true);

    // Display column numbers for the ASCII section
    ImGui::Selectable("ASCII", &b, ImGuiSelectableFlags_Disabled | ImGuiSelectableFlags_Highlight, ImVec2(205, 20));
    // Empty space to align column numbers with the hex values

    // Loop over rows for ASCII characters
    for (int row = 0; row < (int(memory_buffer.size()) + bytes_per_row - 1) / bytes_per_row; ++row) {
        // Draw address offset
        ImGui::Text("%08X: ", row * bytes_per_row);
        ImGui::SameLine();

        for (int col = 0; col < bytes_per_row; ++col) {
            int index = row * bytes_per_row + col;
            if (index < memory_buffer.size()) {
                // Convert byte to printable ASCII (or dot for non-printable)
                char c = memory_buffer[index];
                std::string ascii_str(1, (c >= 32 && c <= 126) ? c : '.');

                // Highlight ASCII part if the byte is within the selected range
                bool is_selected = (selected_byte_start != -1 && selected_byte_end != -1 &&
                                    ((index >= selected_byte_start && index <= selected_byte_end) ||
                                     (index >= selected_byte_end && index <= selected_byte_start)));

                if (is_selected) {
                    ImGui::PushStyleColor(ImGuiCol_Text, ImVec4(1.0f, 1.0f, 1.0f, 1.0f));
                    // Text color for selected byte
                    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.2f, 0.6f, 0.9f, 1.0f));
                    // Background color for selected byte
                    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.3f, 0.7f, 1.0f, 1.0f));
                    // Hover color for selected byte
                }

                if (ImGui::Selectable(ascii_str.c_str(), is_selected, ImGuiSelectableFlags_None, ImVec2(10, 20))) {
                    selected_byte = index; // Set start of selection
                    ImGui::SetClipboardText(ascii_str.c_str()); // Copy ASCII character to clipboard
                }

                if (is_selected) {
                    ImGui::PopStyleColor(3); // Restore original style
                }

                if (col < bytes_per_row - 1)
                    ImGui::SameLine(0, 3.0f); // Adjust spacing between ASCII characters
            } else {
                ImGui::Text(" "); // Empty space for unused bytes
            }
        }
    }

    ImGui::EndChild(); // End ASCII area

    ImGui::EndChild(); // End Hex Editor window
}

static float splitter_size = 20.0f; // Height of the splitter bar
static float top_height = 300.0f; // Adjust this value as needed to set the initial height of the packet list

void displayPackets(const std::vector<packet::PacketInfo> &packets) {
    // Get Available Window Size
    ImVec2 windowSize = ImGui::GetContentRegionAvail();

    if (selectedPacket == -1) {
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


    if (selectedPacket != -1) {
        // Handle the splitter interaction between "Packet List" and "Packet Details"
        //ImGui::Separator(); // Optional visual separator for the splitter bar
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() - splitter_size);  // Position the splitter bar correctly
        ImGui::InvisibleButton("##splitter", ImVec2(-1, 2*splitter_size));  // Create an invisible button for the splitter bar
        if (ImGui::IsItemActive()) {
            top_height += ImGui::GetIO().MouseDelta.y;  // Adjust the height of the top window when dragging
        }

        // Constrain the top_height to prevent it from being too small or too large
        top_height = ImClamp(top_height, 100.0f, windowSize.y - 100.0f);
    }
    // Packet data window
    if (selectedPacket != -1 && selectedPacket != oldSelectedPacket) {
        oldSelectedPacket = selectedPacket;
        packetState.clear();
        packet::PacketInfo packet = packets.at(selectedPacket - 1);
        processL2(packet);
        processL3(packet);
        processL4(packet);
        selected_byte = -1;
        selected_byte_start = -1;
        selected_byte_end = -1;
    }

    if (selectedPacket != -1) {

        // Second child window: "Packet Details"
        ImGui::BeginChild("Packet Details", ImVec2(0, windowSize.y - top_height - splitter_size), true, ImGuiWindowFlags_AlwaysUseWindowPadding);
        // Render packet details here

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

        int data_link_i = 0;
        // Data Link Layer Details
        bool isHoveredDLL = ImGui::TreeNode("Data Link Layer");

        for (int i = 0; i < packetState["L2"].first.size(); i++) {
            std::string value = packetState["L2"].first[i];
            bool raise_text= false;
            if (selected_byte != -1 &&
                selected_byte >= packetState["L2"].second[i].first &&
                selected_byte <= packetState["L2"].second[i].second) {
                raise_text=true;
                selected_byte_start = packetState["L2"].second[i].first;
                selected_byte_end = packetState["L2"].second[i].second;

            }
            else if(packetState["L2"].second[i].first == selected_byte_start){
                raise_text=true;
            }
            data_link_i = packetState["L2"].second[i].second;


            if (isHoveredDLL) {
                if(raise_text) {
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0,255,0,255));
                    ImGui::TextUnformatted(" -> ");
                    ImGui::SameLine();
                }
                ImGui::TextUnformatted(value.c_str());
                if(raise_text) {
                    ImGui::PopStyleColor();
                }
                if (ImGui::IsItemHovered()) {
                    if (ImGui::IsMouseDown(0)) {
                        selected_byte = -1;
                        selected_byte_start = packetState["L2"].second[i].first;
                        selected_byte_end = packetState["L2"].second[i].second;
                    }
                }
            }
        }
        if (isHoveredDLL) {
            //ImGui::TextUnformatted(packet.linkLayerInfo.c_str());
            ImGui::TreePop();
        }

        int network_i = 0;

        // Network Layer Details
        bool isHoveredNL = ImGui::TreeNode("Network Layer");
        for (int i = 0; i < packetState["L3"].first.size(); i++) {
            std::string value = packetState["L3"].first[i];
            network_i = packetState["L3"].second[i].second;
            bool raise_text= false;
            if (selected_byte != -1 &&
                selected_byte >= data_link_i + 1 + packetState["L3"].second[i].first &&
                selected_byte <= data_link_i + 1 + packetState["L3"].second[i].second) {
                raise_text=true;
                selected_byte_start = packetState["L3"].second[i].first + 1 + data_link_i;
                selected_byte_end = packetState["L3"].second[i].second + 1 + data_link_i;
            } else if (packetState["L3"].second[i].first + 1 + data_link_i == selected_byte_start){
                raise_text=true;
            }
            if (isHoveredNL) {
                if(raise_text) {
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0,255,0,255));
                    ImGui::TextUnformatted(" -> ");
                    ImGui::SameLine();
                }
                ImGui::TextUnformatted(value.c_str());
                if(raise_text) {
                    ImGui::PopStyleColor();
                }
                if (ImGui::IsItemHovered()) {
                    if (ImGui::IsMouseDown(0)) {
                        selected_byte = -1;
                        selected_byte_start = packetState["L3"].second[i].first + 1 + data_link_i;
                        selected_byte_end = packetState["L3"].second[i].second + 1 + data_link_i;
                    }
                }
            }
        }

        if (isHoveredNL) {
            //ImGui::TextUnformatted(packet.linkLayerInfo.c_str());
            ImGui::TreePop();
        }

        // Transport Layer Details
        int transport_i = 0;
        bool isHoveredTL = ImGui::TreeNode("Transport Layer");
        for (int i = 0; i < packetState["L4"].first.size(); i++) {
            std::string value = packetState["L4"].first[i];
            transport_i = packetState["L4"].second[i].second;
            bool raise_text= false;
            if (selected_byte != -1 &&
                selected_byte >= data_link_i + network_i + 2 + packetState["L4"].second[i].first &&
                selected_byte <= data_link_i + network_i + 2 + packetState["L4"].second[i].second) {
                raise_text=true;
                selected_byte_start = packetState["L4"].second[i].first + network_i + 2 + data_link_i;
                selected_byte_end = packetState["L4"].second[i].second + network_i + 2 + data_link_i;
            } else if(packetState["L4"].second[i].first + 2 + data_link_i + network_i == selected_byte_start){
                raise_text=true;
            }
            if (isHoveredTL) {
                if(raise_text) {
                    ImGui::PushStyleColor(ImGuiCol_Text, IM_COL32(0,255,0,255));
                    ImGui::TextUnformatted(" -> ");
                    ImGui::SameLine();
                }
                ImGui::TextUnformatted(value.c_str());
                if(raise_text) {
                    ImGui::PopStyleColor();
                }
                if (ImGui::IsItemHovered()) {
                    if (ImGui::IsMouseDown(0)) {
                        selected_byte = -1;
                        selected_byte_start = packetState["L4"].second[i].first + 2 + data_link_i + network_i;
                        selected_byte_end = packetState["L4"].second[i].second + 2 + data_link_i + network_i;
                    }
                }
            }
        }
        if (isHoveredTL) {
            //ImGui::TextUnformatted(packet.transportLayerInfo.c_str());
            ImGui::TreePop();
        }

        if(selected_byte!=1 && selected_byte > selected_byte_end){
            selected_byte_start =  transport_i + data_link_i + network_i + 3;
            selected_byte_end = packet.raw_data.size()-1;
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

    std::string filepath = "/Users/zaryob/Downloads/udp.pcap"; // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/netlink-nflog.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/iperf3-udp.pcapng";  // Example file path
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
