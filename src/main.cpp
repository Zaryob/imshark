#include <imgui/imgui.h>
#include <vector>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>

#include <GLFW/glfw3.h>
#include <imgui_impl_glfw.h>
#include <imgui_impl_opengl3.h>

#include <ip/ethernet_header.h>
#include <pcap/pcap_global_header.h>
#include <pcap/pcap_packet_header.h>
#include <pcap/pcapng_block_header.h>

#include <arpa/inet.h>

#define BT_SHB 0x0A0D0D0A  // Section Header Block
#define BT_SPB 0x00000003  // Simple Packet Block




struct InterfaceDescriptionBlock {
    uint32_t blockType;          // Block Type, should be 0x00000001 for IDB
    uint32_t blockTotalLength;   // Total block length (including the header and trailer)
    uint16_t linkType;           // Data link type (Ethernet, etc.)
    uint16_t reserved;           // Reserved, must be zero
    uint32_t snaplen;            // Maximum length of captured packets, in octets
    // Optional fields (omitted for simplicity)
    // You could add options like timestamp resolution, etc.
};

struct PcapNGPacketBlock {
    uint32_t blockType;             // Block Type = 0x00000006
    uint32_t blockTotalLength;      // Block Total Length
    uint32_t interfaceID;           // Interface ID
    uint32_t timestampUpper;        // Timestamp Upper (high 32 bits)
    uint32_t timestampLower;        // Timestamp Lower (low 32 bits)
    uint32_t capturedPacketLength;  // Captured Packet Length
    uint32_t originalPacketLength;  // Original Packet Length

};

struct SectionHeaderBlock {
    uint32_t blockType;          // Should be 0x0A0D0D0A for SHB
    uint32_t blockTotalLength;   // Total length of the block
    uint32_t magicNumber;        // Magic number (0x1A2B3C4D)
    uint16_t versionMajor;       // Major version number
    uint16_t versionMinor;       // Minor version number
    int64_t sectionLength;       // Length of the section (can be -1 for unknown)
} section;

struct SimplePacketBlock : public PcapNGPacketBlock {
    uint32_t originalPacketLength; // The original length of the packet
    std::vector<uint8_t> packetData; // The actual captured packet data
};

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

void processSectionHeaderBlock(std::ifstream& file, uint32_t blockTotalLength) {

    // Read SHB fields
    file.read(reinterpret_cast<char*>(&section), sizeof(section));

    std::cout << "Section Header Block:" << std::endl;
    std::cout << "Magic Number: " << std::hex << section.magicNumber << std::dec << std::endl;
    std::cout << "Version: " << section.versionMajor << "." << section.versionMinor << std::endl;
    std::cout << "Section Length: " << section.sectionLength << std::endl;

    // Skip any options and the footer (optional to handle if needed)
    uint32_t remainingBytes = blockTotalLength - sizeof(section) - sizeof(uint32_t);
    file.seekg(remainingBytes, std::ios::cur);
}

void processPacketBlock(std::ifstream& file, PcapNGPacketBlock& section, PacketInfo& pack, uint32_t& tsTimeOffset, uint32_t& usTimeOffset) {
    std::cout<<"Process Packet Block"<<std::endl;
    std::cout<<"Tell:"<<file.tellg()<<std::endl;
    file.read(reinterpret_cast<char*>(&section), sizeof(section));
    std::cout << "PacketBlock: "<< std::endl;
    std::cout << "Block Type: " << std::hex << section.blockType << std::dec << std::endl;
    std::cout << "Block Total Length: " << section.blockTotalLength << std::endl;
    std::cout << "Interface ID: " << section.interfaceID << std::endl;

    if(section.blockType != 0x00000006){
        std::cout << "Invalid Packet Block Type: " << std::hex << section.blockType << std::dec << std::endl;
        std::cout<<"Tell:"<<file.tellg()<<std::endl;
        file.seekg(-1 * sizeof(section), std::ios::cur);
        //int offset = section.blockTotalLength - sizeof(section) - sizeof(uint32_t);
        std::cout<<"Offset: "<<sizeof(section)<<std::endl;
        std::cout<<"Tell:"<<file.tellg()<<std::endl;
        //std::cout<<"Block Total Length: "<<section.blockTotalLength<<std::endl;
        //std::vector<char> packetData(section.blockTotalLength-sizeof(uint32_t));
        //file.read(packetData.data(), section.blockTotalLength-sizeof(uint32_t));
        //std::cout<<"Tell:"<<file.tellg()<<std::endl;
        //uint32_t trailingLength;
        //file.read(reinterpret_cast<char*>(&trailingLength), sizeof(trailingLength));
        //file.seekg(section.blockTotalLength - sizeof(uint32_t), std::ios::cur);
        //std::cout<<"Tr:"<<trailingLength<<std::endl;

        return;
    }

    double timestampResolution = 1.0 / 1000; // Default is milliseconds
    uint64_t fullTimestamp = ((uint64_t)section.timestampUpper << 32) | section.timestampLower;
    // If custom resolution, update timestampResolution
    fullTimestamp *= timestampResolution;  // Adjust timestamp according to resolution
    uint64_t seconds = fullTimestamp / 1'000'000;    // Convert milliseconds to seconds
    uint64_t milliseconds = fullTimestamp % 1'000'000;

    if(tsTimeOffset == 0){
        tsTimeOffset = seconds;
    }
    if(usTimeOffset == 0){
        usTimeOffset = milliseconds;
    }

    pack.time = (seconds + 10e-7* (milliseconds) ) - (tsTimeOffset + 10e-7 * (usTimeOffset));
    std::cout<<"Time: "<<pack.time<<std::endl;

    std::vector<char> packetData(section.capturedPacketLength);
    file.read(packetData.data(), section.capturedPacketLength);
    EthernetHeader* ethHeader = reinterpret_cast<EthernetHeader*>(packetData.data());
    std::cout<<"EthHeader: "<<std::hex<<ethHeader->type<<std::dec<<std::endl<<"Ethernet Packet: Dest MAC: "<<getMACAddressString(ethHeader->dest_mac)<<std::endl;
    if (ntohs(ethHeader->type) == 0x0800) {
        // IP packet

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
            case 6: {
                // TCP

                TCPHeader* tcpHeader = reinterpret_cast<TCPHeader*>(packetData.data() + sizeof(EthernetHeader) + (ipHeader->ihl * 4));
                std::cout << "TCP Packet: Src Port: " << source
                <<", Dest Port: " << destination << std:: endl;
                pack.length = section.capturedPacketLength;
                pack.protocol="TCP";
                pack.info = std::to_string(ntohs(tcpHeader->src_port)) + " -> " + std::to_string(ntohs(tcpHeader->dest_port));

            } break;
            case 17: {
                // UDP
                UDPHeader* udpHeader = reinterpret_cast<UDPHeader*>(packetData.data() + sizeof(EthernetHeader) + (ipHeader->ihl * 4));
                std::cout << "UDP Packet: Src Port: " << source
                << " Dest Port: " <<  destination << std:: endl;
                auto s = ntohs(udpHeader->len) - sizeof(uint32_t) * 2 ;
                pack.length = s;
                pack.protocol="UDP";

                pack.info = std::to_string(ntohs(udpHeader->src_port)) + " -> " + std::to_string(ntohs(udpHeader->dest_port));

            }
            break;

            default:
                std:: cout << "Other IP Protocol: " << static_cast<int>(ipHeader->protocol) << std:: endl;
        }
    }
    else if (ntohs(ethHeader->type) == 0x0806) {
        // ARP packet
        ARPHeader* arpHeader = reinterpret_cast<ARPHeader*>(packetData. data() + sizeof(EthernetHeader));
        std::cout << "ARP Packet: Opcode " << ntohs(arpHeader->opcode) << std::endl;
        pack.protocol="ARP";
        pack.destination=getMACAddressString(arpHeader->target_hw_addr);
        pack.source = getMACAddressString(arpHeader->sender_hw_addr);
        pack.length = section.capturedPacketLength;
    }
    std::cout<< "Process Packet Block complate"<<std::endl;
    file.seekg(-1 * sizeof(section) - section.originalPacketLength, std::ios::cur);

}
void processInterfaceDescriptionBlock(std::ifstream& file, InterfaceDescriptionBlock& section) {
    // Read the fixed-length fields of the Interface Description Block
    file.read(reinterpret_cast<char*>(&section), sizeof(section));

    std::cout << "Interface Description Block: " << std::endl;
    std::cout << "Block Type: " << std::hex << section.blockType << std::dec << std::endl;
    std::cout << "Block Total Length: " << section.blockTotalLength << std::endl;
    std::cout << "Link Type: " << section.linkType << std::endl;
    std::cout << "Snap Length: " << section.snaplen << std::endl;

    // The rest of the block may contain options, such as timestamp resolution
    uint32_t remainingBytes = section.blockTotalLength - sizeof(InterfaceDescriptionBlock)- sizeof(uint32_t);

    // You can read optional fields here, if needed. For now, skip them.
    file.seekg(remainingBytes, std::ios::cur);
}


void processSimplePacketBlock(std::ifstream& file, uint32_t blockTotalLength) {
    SimplePacketBlock spb;
    spb.blockTotalLength = blockTotalLength;

    // Read original packet length
    file.read(reinterpret_cast<char*>(&spb.originalPacketLength), sizeof(spb.originalPacketLength));

    std::cout << "Simple Packet Block:" << std::endl;
    std::cout << "Original Packet Length: " << spb.originalPacketLength << std::endl;

    // Calculate the packet data length (block length - fixed fields)
    uint32_t packetDataLength = blockTotalLength - sizeof(PcapNGPacketBlock) - sizeof(spb.originalPacketLength) - sizeof(uint32_t);

    // Resize packet data vector and read packet data
    spb.packetData.resize(packetDataLength);
    file.read(reinterpret_cast<char*>(spb.packetData.data()), packetDataLength);

    // Print packet data (as hex, optional)
    std::cout << "Packet Data: ";
    for (uint8_t byte : spb.packetData) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;

    // Skip the trailing blockTotalLength (already accounted for)
    uint32_t trailingLength;
    file.read(reinterpret_cast<char*>(&trailingLength), sizeof(trailingLength));

    if (trailingLength != blockTotalLength) {
        std::cerr << "Error: Mismatching block lengths!" << std::endl;
    }
}

void processPcapngFile(const std::string& filepath, std::vector<PacketInfo>& packets) {
    std::ifstream file(filepath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr<< "Failed to open file: " << filepath << std:: endl;
        return;
    }

    PcapNGBlockHeader header;
    file.read(reinterpret_cast<char*>(&header), sizeof(PcapNGBlockHeader));
    //std:: cout << "Header Hex: ";
    //printAsHex(reinterpret_cast<char*>(Sheader), sizeof(header));
    //std:: cout < std:: endl;
    // Debugging: Output the expected block length for verification
    file.seekg(-1 * sizeof(PcapNGBlockHeader), std::ios::cur);
    std::cout<< "Block Length: "<< header.blockTotalLength << std::endl;
    switch (header.blockType) {
        case BT_SHB: // BT_SHB
        processSectionHeaderBlock(file, header.blockTotalLength);
        break;
        case BT_SPB:
        processSimplePacketBlock(file, header.blockTotalLength);
        break;
        // Add cases for other block types...
        default:
        std::cout << "Unhandled block type:" << std::hex << header.blockType << std::dec <<std::endl;
        // Skip unknown block
        file.seekg(header.blockTotalLength - sizeof(PcapNGBlockHeader), std::ios::cur);
        break;
    }
    // Verify block length trailer to match header
    uint32_t blockLenghtTrailer;
    file.read(reinterpret_cast<char*>(&blockLenghtTrailer), sizeof(blockLenghtTrailer));
    if (blockLenghtTrailer != header.blockTotalLength) {
        std::cerr<< "Mismatched block length at end of block. Expected: " <<header.blockTotalLength <<", Got: "<< blockLenghtTrailer<< std::endl;
        file.close();
        return;
    }

    InterfaceDescriptionBlock section;
    processInterfaceDescriptionBlock(file, section);
    // Verify block length trailer to match header
    uint32_t interfaceLenghtTrailer;
    file.read(reinterpret_cast<char*>(&interfaceLenghtTrailer), sizeof(interfaceLenghtTrailer));
    if (interfaceLenghtTrailer != section.blockTotalLength) {
        std:: cerr << "Mismatched interface length at end of block. Expected: " <<header.blockTotalLength << ", Got: "<< blockLenghtTrailer << std::endl;
        file.close ();
        return;
    }
    uint32_t packetNumber = 0;
    uint32_t tsTimeOffset=0;
    uint32_t usTimeOffset=0;

    while (file.peek() != EOF) {
        PcapNGPacketBlock pb;
        PacketInfo pack(++packetNumber);

        processPacketBlock(file, pb, pack, tsTimeOffset, usTimeOffset);

        //size_t read = sizeof(pb);
        //size_t remaining = pb.blockTotalLength - read - sizeof(uint32_t) - pb.capturedPacketLength;
        file.seekg(pb.blockTotalLength-sizeof(uint32_t), std::ios::cur);
        uint32_t packetLenghtTrailer;
        file.read(reinterpret_cast<char*>(&packetLenghtTrailer), sizeof(packetLenghtTrailer));

        if (packetLenghtTrailer != pb.blockTotalLength) {
            std::cout<<"Packet Block Length Mismatch: Expected: "<< pb.blockTotalLength << ", Got: "<< packetLenghtTrailer << std::endl;
            file.close();

            exit(0);
        }
        packets.emplace_back(pack);
    }
    std::cout<<"File processed successfully"<<std::endl;
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

    //std::string filepath = "/Users/zaryob/Downloads/pcapgui/udp.pcap";  // Example file path
    std::string filepath = "/Users/zaryob/Downloads/pcapgui/iperf3-udp.pcapng";  // Example file path
    std::vector<char> buffer;
    std::vector<PacketInfo> packets;

    if (isPcapng(filepath)) {
        processPcapngFile(filepath, packets);
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


