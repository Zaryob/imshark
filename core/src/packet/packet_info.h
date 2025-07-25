//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

#include <string>
#include <vector>



namespace packet {
    /// One node of the protocol tree shown in the packet details pane: a label plus the byte range
    /// of the frame (`raw_data`) it was decoded from. `length == 0` means "no bytes" (derived values).
    struct Field {
        std::string text;
        uint32_t offset = 0;
        uint32_t length = 0;
        std::vector<Field> children;

        Field &add(std::string label, size_t off = 0, size_t len = 0) {
            children.push_back(Field{std::move(label), static_cast<uint32_t>(off), static_cast<uint32_t>(len), {}});
            return children.back();
        }

        bool contains(size_t byte) const { return byte >= offset && byte < size_t(offset) + length; }
    };

    /// One captured packet. While a capture is loaded only the cheap summary is kept in memory (the
    /// columns of the packet list); the raw bytes stay in the file and the field tree is rebuilt on
    /// demand for the selected packet (see core::buildPacketDetails).
    struct PacketInfo {
        int number = 0;
        double time = 0;
        std::string source;
        std::string destination;
        std::string protocol;
        uint32_t length = 0;
        std::string info;

        // Capture link type (LINKTYPE_* from the pcap/pcapng file); 1 = Ethernet.
        uint32_t link_type = 1;
        // Number of link-layer bytes in front of the network header (0 for raw IP).
        uint16_t l2_size = 0;
        // 802.1Q/802.1ad VLAN IDs found in the Ethernet header, outermost first.
        std::vector<uint16_t> vlan_ids;

        // Relative TCP sequence/acknowledgment numbers, computed in capture order while loading
        // (-1 = not applicable); needed again when the field tree is rebuilt for a single packet.
        int64_t tcp_relative_seq = -1;
        int64_t tcp_relative_ack = -1;
        // TCP analysis result (network::TcpAnalysisFlag bits) and the "Dup ACK #n" counter
        uint16_t tcp_analysis = 0;
        uint8_t tcp_dup_ack = 0;

        // Where the captured frame lives in the capture file.
        uint64_t file_offset = 0;
        uint32_t captured_length = 0;
        uint32_t frame_length = 0;   // length on the wire (>= captured_length when the capture was truncated)

        // Compact protocol facts, filled while parsing; the display filter works on these.
        uint16_t ether_type = 0;     // outermost payload type after the link layer / VLAN tags
        uint8_t ip_version = 0;      // 4, 6 or 0 for non-IP frames
        uint8_t ip_protocol = 0;     // IP protocol (IPv6: last next-header) of the transport layer; 0 = none
        uint8_t ttl = 0;             // IPv4 TTL / IPv6 hop limit
        uint8_t tcp_flags = 0;       // raw TCP flag byte
        uint16_t src_port = 0;       // TCP/UDP ports (0 if not applicable)
        uint16_t dst_port = 0;
        bool has_comment = false;    // the capture file attaches a comment to this packet (pcapng)
        uint16_t ip_id = 0;          // IPv4 identification
        uint8_t ip_frag = 0;         // 0 = not fragmented, 1 = fragment that is not the last, 2 = last fragment (datagram reassembled here)
        uint32_t reassembled_in = 0; // for a fragment (ip_frag == 1): number of the frame that completed the datagram
        // Facts of the application protocol, filled by its dissector (meaning depends on `protocol`):
        //   DNS/MDNS: app_text = first question name, app_type = its type, app_flags = flags word, app_code = rcode
        //   HTTP:     app_text = Host, app_text2 = request URI or response Content-Type, app_type = method (1 = GET ...),
        //             app_code = response status code
        //   TLS:      app_text = server name (SNI), app_type = first handshake type, app_code = first record content type,
        //             app_flags = record version
        uint16_t app_type = 0;
        uint16_t app_flags = 0;
        uint16_t app_code = 0;
        std::string app_text;
        std::string app_text2;       //   HTTP: request URI / response content type; TLS: -
        uint32_t payload_offset = 0; // TCP/UDP payload inside the captured frame (0/0 if there is none)
        uint32_t payload_length = 0;

        /// The captured frame. Empty for packets of a loaded capture, filled when details are built.
        std::vector<char> raw_data;

        /// Decoded protocol layers, outermost first (Frame, Ethernet, IP, TCP, ...). Offsets are absolute
        /// positions in `raw_data`. Empty unless the packet was parsed in Full/Replay mode.
        std::vector<Field> fields;

        PacketInfo() = default;
        explicit PacketInfo(int num) : number(num) {}
    };
} // namespace packet
