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


#include <pcap/global_header.h>
#include <pcap/packet_header.h>

#include <pcapng/block_header.h>
#include <pcapng/interface_description_block.h>
#include <pcapng/section_header_block.h>
#include <pcapng/simple_packet_block.h>
#include <pcapng/enhanced_packet_block.h>
#include <pcapng/interface_statistics_block.h>
#include <pcapng/name_resolution_block.h>

#include <core.h>
#include <map>
#include <arpa/inet.h>

std::map<std::string, std::vector<std::string>> packetState;

int selectedPacket = -1; // Index of the selected packet
int oldSelectedPacket = -1; // Index of the selected packet

std::string toHexString(const std::vector<char>& data, size_t offset, size_t length) {
    std::ostringstream hexStream, charStream;
    std::string finalDisplay;
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

                finalDisplay += hexStream.str() + "     " + charStream.str() + "\n";
                hexStream.str("");
                charStream.str("");
            }
        }

    return finalDisplay;
}


// Function to process the l2 header
void processL2(const PacketInfo& packet) {
    packetState["L2"] = {};

    std::visit([](auto&& header) {
        using T = std::decay_t<decltype(header)>;
        if constexpr (std::is_same_v<T, network::EthernetHeader>) {
            packetState["L2"] = {"Destination MAC: " + getMACAddressString(header.dest_mac),
                                  "Source MAC: " + getMACAddressString(header.src_mac),
                                  "Type: " + std::to_string(header.type)};
        }
    }, packet.l2_header);
}

// Function to process the l3 header
void processL3(const PacketInfo& packet) {
    packetState["L3"] = {};
    std::visit([](auto&& header) {
        using T = std::decay_t<decltype(header)>;
        if constexpr (std::is_same_v<T, network::ARPHeader>) {
            packetState["L3"] = {"ARP Packet"};
        } else if constexpr (std::is_same_v<T, network::IPHeader>) {
            struct in_addr dest_addr;
            dest_addr.s_addr = header.dst_addr;
            struct in_addr src_addr;
            src_addr.s_addr = header.src_addr;
            packetState["L3"] = {"Version: " + std::to_string(header.version),
                                 "IHL: " + std::to_string(header.ihl),
                                 "Total Length: " + std::to_string(header.tot_length),
                                 "Identification: " + std::to_string(header.id),
                                 "Flags: " + std::to_string(header.flags),
                                 "Fragment Offset: " + std::to_string(header.frag_off),
                                 "TTL: " + std::to_string(header.ttl),
                                 "Protocol: " + std::to_string(header.protocol),
                                 "Header Checksum: " + std::to_string(header.check),
                                 "Source IP: " + std::string(inet_ntoa(src_addr)),
                                 "Destination IP: " + std::string(inet_ntoa(dest_addr))};

        } else if constexpr (std::is_same_v<T, network::IPv6Header>) {
            packetState["L3"] = {"Version: " + std::to_string(header.version),
                                 "Traffic Class: " + std::to_string(header.traffic_class),
                                 "Flow Label: " + std::to_string(header.flow_label),
                                 "Payload Length: " + std::to_string(header.payload_len),
                                 "Next Header: " + std::to_string(header.next_header),
                                 "Hop Limit: " + std::to_string(header.hop_limit)};
        }
    }, packet.l3_header);
}

// Function to process the l4 header
void processL4(const PacketInfo& packet) {
    packetState["L4"] = {};
    std::visit([](auto&& header) {
        using T = std::decay_t<decltype(header)>;
        if constexpr (std::is_same_v<T, network::ICMPHeader>) {
            packetState["L4"] = {"ICMP Header"};
        } else if constexpr (std::is_same_v<T, network::TCPHeader>) {

            packetState["L4"] = { "TCP Header",
                                    "Source Port: " + std::to_string(header.src_port),
                                    "Destination Port: " + std::to_string(header.dest_port),
                                    "Sequence Number: " + std::to_string(header.seq_num),
                                    "Acknowledgement Number: " + std::to_string(header.ack_num),
                                    "Data Offset: " + std::to_string(header.data_offset),
                                    "Flags: " + std::to_string(header.flags),
                                    "Window Size: " + std::to_string(header.window),
                                    "Checksum: " + std::to_string(header.checksum),
                                    "Urgent Pointer: " + std::to_string(header.urgent_pointer)};
        } else if constexpr (std::is_same_v<T, network::UDPHeader>) {
            packetState["L4"] = {"Source Port: " + std::to_string(header.src_port),
                                "Destination Port: " + std::to_string(header.dest_port),
                                "Length: " + std::to_string(header.len),
                                "Checksum: " + std::to_string(header.checksum)};
        }
    }, packet.l4_header);
}

// Function to process the l7 header
void processL7(const PacketInfo& packet) {
    std::visit([](auto&& header) {
        using T = std::decay_t<decltype(header)>;
        if constexpr (std::is_same_v<T, network::DHCPHeader>) {
            ImGui::TextUnformatted("DHCP Header");
        } else if constexpr (std::is_same_v<T, network::DNSHeader>) {
            ImGui::TextUnformatted("DNS Header");
        }
    }, packet.l7_header);
}

static float splitter_size = 5.0f;
static float top_height = 300.0f;  // Adjust this value as needed to set the initial height of the packet list

void displayPackets(const std::vector<PacketInfo>& packets) {

    // Get Window Size
    ImVec2 windowSize = ImGui::GetWindowSize();

    if(selectedPacket != -1) {
        top_height = windowSize.y / 2;
    }
    else {
        top_height = windowSize.y;
    }
    // Top window: Packet list
    ImGui::BeginChild("Packet List", ImVec2(0, top_height), true, ImGuiWindowFlags_AlwaysUseWindowPadding);
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
                //ImGui::Text("%d", packet.number);
                if (ImGui::Selectable(std::to_string(packet.number).c_str(), selectedPacket == packet.number, ImGuiSelectableFlags_SpanAllColumns)) {
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
        if(selectedPacket != -1 && selectedPacket != oldSelectedPacket) {
            oldSelectedPacket = selectedPacket;
            packetState.clear();
            PacketInfo packet = packets.at(selectedPacket-1);
            processL2(packet);
            processL3(packet);
            processL4(packet);
        }

        if (selectedPacket != -1 ) {
            // Handle splitter resizing
            if (ImGui::IsItemActive()) {
                top_height -= ImGui::GetIO().MouseDelta.y;
            }

            // Bottom window: Packet details
            ImGui::BeginChild("Packet Details", ImVec2(0, windowSize.y- top_height), true, ImGuiWindowFlags_AlwaysUseWindowPadding);

            //if(ImGui::Begin("Packet Details")){
            PacketInfo packet = packets.at(selectedPacket-1);
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
                for (const auto& value : packetState["L2"]) {
                    ImGui::TextUnformatted(value.c_str());
                }
                //ImGui::TextUnformatted(packet.linkLayerInfo.c_str());
                ImGui::TreePop();
            }

            // Network Layer Details
            if (ImGui::TreeNode("Network Layer")) {
                for (const auto& value : packetState["L3"]) {
                    ImGui::TextUnformatted(value.c_str());
                }
                //ImGui::TextUnformatted(packet.networkLayerInfo.c_str());
                ImGui::TreePop();
            }

            // Transport Layer Details
            if (ImGui::TreeNode("Transport Layer")) {
                for (const auto& value : packetState["L4"]) {
                    ImGui::TextUnformatted(value.c_str());
                }
                //ImGui::TextUnformatted(packet.transportLayerInfo.c_str());
                ImGui::TreePop();
            }
            if (!packet.raw_data.empty()) {
                ImGui::Text("Raw Data:");
                std::string data_str = toHexString(packet.raw_data, 0, packet.raw_data.size());
                ImGui::InputTextMultiline("##data", &data_str[0], data_str.size(), ImVec2(-FLT_MIN, ImGui::GetTextLineHeight() * 16), ImGuiInputTextFlags_ReadOnly);
            }
            
            ImGui::EndChild();
    }


}

void HexView(const char* title, const char* mem, size_t len,  std::vector<PacketInfo>& packets) {

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

    bool show=true;
    if (ImGui::Begin(title)) {//,&show,ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse)) {
        displayPackets(packets);
    }
    ImGui::End();
    //ImGui::PopStyleVar(2);

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

/// PCAP FILE PROCESSING

void processPcapFile(const std::string& filepath, std::vector<PacketInfo>& packets,connectionStateMap& connectionMap) {
    std::ifstream file(filepath, std::ios::binary);
    pcap::GlobalHeader gHeader;
    file.read(reinterpret_cast<char*>(&gHeader), sizeof(pcap::GlobalHeader));

    if (gHeader.magic_number != 0xa1b2c3d4) {
        std::cerr << "Incompatible PCAP file format" << std::endl;
        return;
    }

    uint32_t tsTimeOffset = 0;
    uint32_t usTimeOffset = 0;
    int packetNumber = 0;

    while (file.peek() != EOF) {
        pcap::PacketHeader pHeader = {0};
        file.read(reinterpret_cast<char*>(&pHeader), sizeof(pcap::PacketHeader));

        std::vector<char> packetData(pHeader.incl_len);
        file.read(packetData.data(), pHeader.incl_len);

        PacketInfo pack(++packetNumber);
        pack.time = (pHeader.ts_sec) + 10e-7 * (pHeader.ts_usec) - (tsTimeOffset + 10e-7 * (usTimeOffset));
        // Process the packet data using the shared packet processor
        pack.raw_data = packetData;
        processPacket(pack, packetData, connectionMap);

        packets.emplace_back(pack);
    }

    file.close();
}

/// PCAPNG FILE PROCESSING


void processSectionHeaderBlock(std::ifstream& file, pcapng::SectionHeaderBlock section) {

    // std::cout << "Section Header Block:" << std::endl;
    // std::cout << "Magic Number: " << std::hex << section.magicNumber << std::dec << std::endl;
    // std::cout << "Version: " << section.versionMajor << "." << section.versionMinor << std::endl;
    // std::cout << "Section Length: " << section.sectionLength << std::endl;

    // Verify block length trailer to match header
    if (section.block_total_length != section.block_total_length_redundant) {
        std::cerr<< "Mismatched block length at end of block. Expected: " <<section.block_total_length <<", Got: "<< section.block_total_length_redundant<< std::endl;
        file.close();
        return;
    }

}

void processEnhancedPacketBlock(pcapng::EnhancedPacketBlock& section, PacketInfo& pack, uint32_t& tsTimeOffset, uint32_t& usTimeOffset, connectionStateMap& connectionMap) {
    // std::cout << "Process Packet Block" << std::endl;

    // Check for mismatched block length
    if (section.block_total_length != section.block_total_length_redundant) {
        std::cerr << "Mismatched block length at end of block" << std::endl;
        return;
    }

    double timestampResolution = 1.0 / 1000; // Default milliseconds
    uint64_t fullTimestamp = ((uint64_t)section.timestamp_upper << 32) | section.timestamp_lower;
    fullTimestamp *= timestampResolution;
    uint64_t seconds = fullTimestamp / 1'000'000;
    uint64_t milliseconds = fullTimestamp % 1'000'000;

    if (tsTimeOffset == 0) tsTimeOffset = seconds;
    if (usTimeOffset == 0) usTimeOffset = milliseconds;

    pack.time = (seconds + 10e-7 * (milliseconds)) - (tsTimeOffset + 10e-7 * (usTimeOffset));
    pack.raw_data = section.packet_data;
    // Process the packet data using the shared packet processor
    processPacket(pack, section.packet_data, connectionMap);
}

void processInterfaceDescriptionBlock(std::ifstream& file, pcapng::InterfaceDescriptionBlock& idb) {

    // std::cout << "Interface Description Block: " << std::endl;
    // std::cout << "Block Type: " << std::hex << idb.blockType << std::dec << std::endl;
    // std::cout << "Block Total Length: " << idb.blockTotalLength << std::endl;
    // std::cout << "Link Type: " << idb.linkType << std::endl;
    // std::cout << "Snap Length: " << idb.snapLen << std::endl;
    // std::cout << "TL Red Length: " << idb.blockTotalLengthRedundant << std::endl;
    if (idb.block_total_length != idb.block_total_length_redundant) {
        std::cerr<< "Mismatched block length at end of block. Expected: " <<idb.block_total_length <<", Got: "<< idb.block_total_length_redundant<< std::endl;
        file.close();
        return;
    }

}


void processSimplePacketBlock(pcapng::SimplePacketBlock spb, PacketInfo& pack, uint32_t& tsTimeOffset, uint32_t& usTimeOffset) {

    if (spb.block_total_length != spb.block_total_length_redundant) {
        std::cerr<< "Mismatched block length at end of block. Expected: " <<spb.block_total_length <<", Got: "<< spb.block_total_length_redundant<< std::endl;
        exit(0);
        return;
    }
}

// Function to print the statistics data
void printStatistics(pcapng::InterfaceStatisticsBlock isb) {
    if (isb.block_total_length != isb.block_total_length_redundant) {
        std::cerr<< "Mismatched block length at end of block. Expected: " <<isb.block_total_length <<", Got: "<< isb.block_total_length_redundant<< std::endl;
        exit(0);
        return;
    }
    uint64_t fullTimestamp = ((uint64_t)isb.timestamp_high << 32) | isb.timestamp_low;
    // std::cout << "Interface ID: " << isb.interfaceID << std::endl;
    // std::cout << "Timestamp: " << fullTimestamp << " (high: " << isb.timestampHigh << ", low: " << isb.timestampLow << ")" << std::endl;
    // std::cout << "Options Size: " << isb.options.size() << " bytes" << std::endl;

    // Additional parsing of options could be done here (if required).
}

// Function to print the name resolution records
void printNameResolutionRecords(pcapng::NameResolutionBlock nrb) {
    // std::cout << "Name Resolution Records:" << std::endl;
    for (const auto& record : nrb.records) {
        // std::cout << "Address: " << record.address << ", Resolved Name: " << record.resolvedName << std::endl;
    }
}
void processPcapngFile(const std::string& filepath, std::vector<PacketInfo>& packets, connectionStateMap& connectionMap) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr<< "Failed to open file: " << filepath << std:: endl;
        return;
    }

    uint64_t blockIdx = 0;
    uint32_t packetNumber = 0;
    uint32_t tsTimeOffset=0;
    uint32_t usTimeOffset=0;

    while (file.peek() != EOF) {
        pcapng::BlockHeader header;
        header.deserialize(file);
        // std::cout << "Block Type: "<<std::setfill('0') << std::setw(8) << std::hex << header.blockTotalLength << std::dec<< std::endl;
        // std::cout << "Block Length: "<< header.blockTotalLength << std::endl;
        switch (header.block_type) {
            case static_cast<uint32_t>(pcapng::BlockType::SHB):
            {
                pcapng::SectionHeaderBlock section(header);
                // Read SHB fields
                section.deserializeSectionFields(file);
                processSectionHeaderBlock(file, section);
            }
            break;
            case static_cast<uint32_t>(pcapng::BlockType::IDB):
            {
                pcapng::InterfaceDescriptionBlock idb(header);
                idb.deserializeInterfaceFields(file);
                processInterfaceDescriptionBlock(file, idb);
            }
            break;
            case static_cast<uint32_t>(pcapng::BlockType::SPB):
            {
                pcapng::SimplePacketBlock spb(header);

                spb.deserializePacketFields(file);

                PacketInfo pack(++packetNumber);
                processSimplePacketBlock(spb, pack, tsTimeOffset, usTimeOffset);
                packets.emplace_back(pack);
            }
            break;
            case static_cast<uint32_t>(pcapng::BlockType::ISB):
            {
                pcapng::InterfaceStatisticsBlock isb(header);
                isb.deserializeStatisticsFields(file);

                // Process Interface Statistics Block
                printStatistics(isb);
            }
            break;
            case static_cast<uint32_t>(pcapng::BlockType::EPB):
            {
                pcapng::EnhancedPacketBlock pb(header);
                pb.deserializeEnhancedFields(file);
                PacketInfo pack(++packetNumber);
                processEnhancedPacketBlock(pb, pack, tsTimeOffset, usTimeOffset, connectionMap);

                packets.emplace_back(pack);
            }
            break;
            case static_cast<uint32_t>(pcapng::BlockType::NRB):
            {
                pcapng::NameResolutionBlock nrb(header);
                nrb.deserializeNameResolutionFields(file);

                // Process Name Resolution Block
                printNameResolutionRecords(nrb);
            }
            break;
            // Add cases for other block types...
            default:
                // std::cout << "Unhandled block type:" << std::hex << header.blockType << std::dec <<std::endl;
                // Skip unknown block
                file.seekg(header.block_total_length - sizeof(pcapng::BlockHeader), std::ios::cur);
            break;
        }
    }

    // std::cout <<"File processed successfully"<<std::endl;
    file.close();
    return;
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

    //std::string filepath = "/Users/zaryob/Downloads/udp.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/netlink-nflog.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/iperf3-udp.pcapng";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/ipv4frags.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/dhcp.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/telnet-raw.pcap";  // Example file path
    //std::string filepath = "/Users/zaryob/Downloads/bgpsec.pcap";  // Example file path
    std::string filepath = "/Users/zaryob/Downloads/smtp.pcap";  // Example file path
    //std::string filepath =  "/home/suleymanpoyraz/Downloads/nn.pcapng";
    std::vector<char> buffer;
    std::vector<PacketInfo> packets;
    connectionStateMap connectionTable;

    // std::cout <<"Sizeof Vector"<<sizeof(std::vector<char>)<<std::endl<<
    //           "Sizeof BlockHeader "<<sizeof(BlockHeader)<<std::endl<<
    //           "Sizeof Interface Description Block "<<sizeof(InterfaceDescriptionBlock)<<std::endl<<
    //           "Sizeof Simple Packet Block "<<sizeof(SimplePacketBlock)<<std::endl<<
    //           "Sizeof Section Header Block "<<sizeof(SectionHeaderBlock)<<std::endl;

    if(std::filesystem::is_regular_file(filepath))
    {
        if (isPcapng(filepath)) {
            processPcapngFile(filepath, packets, connectionTable);
        } else {
            processPcapFile(filepath, packets, connectionTable);
        }
    }else {
        std::cerr << "Invalid file path: " << filepath << std::endl;
    }

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        HexView("PCAP File Viewer", buffer.data(), buffer.size(),packets);

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


