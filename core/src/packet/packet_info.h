//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

#include <string>
#include <vector>



namespace packet {
    /// link_type of a packet that names a capture interface the file never defined (nothing is guessed for it).
    constexpr uint32_t kUndefinedLinkType = 0xFFFFFFFFu;

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
        // Members are ordered by size (8-byte scalars, strings/vectors, then 4, 2 and 1-byte fields) so the
        // compiler adds no padding: the summary of every packet of a capture stays in memory.
        double time = 0;
        // Relative TCP sequence/acknowledgment numbers, computed in capture order while loading
        // (-1 = not applicable); needed again when the field tree is rebuilt for a single packet.
        int64_t tcp_relative_seq = -1;
        int64_t tcp_relative_ack = -1;
        // Where the captured frame lives in the capture file.
        uint64_t file_offset = 0;
        std::string source;
        std::string destination;
        std::string protocol;
        std::string info;
        // 802.1Q/802.1ad VLAN IDs found in the Ethernet header, outermost first.
        std::vector<uint16_t> vlan_ids;
        std::string app_text;
        std::string app_text2;       //   HTTP: request URI / response content type; TLS: -
        /// The captured frame. Empty for packets of a loaded capture, filled when details are built.
        std::vector<char> raw_data;
        /// Decoded protocol layers, outermost first (Frame, Ethernet, IP, TCP, ...). Offsets are absolute
        /// positions in `raw_data`. Empty unless the packet was parsed in Full/Replay mode.
        std::vector<Field> fields;
        int number = 0;
        uint32_t length = 0;
        // Capture link type (LINKTYPE_* from the pcap/pcapng file); 1 = Ethernet.
        uint32_t link_type = 1;
        uint32_t captured_length = 0;
        uint32_t frame_length = 0;   // length on the wire (>= captured_length when the capture was truncated)
        uint32_t tcp_pdu_start = 0;  // tcp_pdu_state == 2: relative sequence number of the first byte of the reassembled message
        uint32_t tcp_pdu_len = 0;    //                    and its length
        uint32_t tcp_reassembled_in = 0; // tcp_pdu_state == 1: number of the packet that completed the message this segment belongs to
        uint32_t tcp_len = 0;        // TCP payload length on the wire (from the IP length, not the captured bytes)
        uint32_t reassembled_in = 0; // for a fragment (ip_frag == 1): number of the frame that completed the datagram
        uint32_t payload_offset = 0; // TCP/UDP payload position (0/0 if there is none). Relative to the captured frame -
                                     // except when ip_frag == 2: then relative to the reassembled IP payload (see core::reassembleIpPayload)
        uint32_t payload_length = 0;
        // Number of link-layer bytes in front of the network header (0 for raw IP).
        uint16_t l2_size = 0;
        // TCP analysis result (network::TcpAnalysisFlag bits) and the "Dup ACK #n" counter
        uint16_t tcp_analysis = 0;
        // Compact protocol facts, filled while parsing; the display filter works on these.
        uint16_t ether_type = 0;     // outermost payload type after the link layer / VLAN tags
        uint16_t src_port = 0;       // TCP/UDP ports (0 if not applicable)
        uint16_t dst_port = 0;
        uint32_t ip_id = 0;          // IPv4 identification (16 bit) / IPv6 Fragment Header identification (32 bit)
        // Facts of the application protocol, filled by its dissector (meaning depends on `protocol`):
        //   DNS/MDNS: app_text = first question name, app_type = its type, app_flags = flags word, app_code = rcode
        //   HTTP:     app_text = Host, app_text2 = request URI or response Content-Type, app_type = method (1 = GET ...),
        //             app_code = response status code
        //   TLS:      app_text = server name (SNI), app_type = first handshake type, app_code = first record content type,
        //             app_flags = record version
        uint16_t app_type = 0;
        uint16_t app_flags = 0;
        uint16_t app_code = 0;
        uint8_t tcp_dup_ack = 0;
        uint8_t ip_version = 0;      // 4, 6 or 0 for non-IP frames
        uint8_t ip_protocol = 0;     // IP protocol (IPv6: last next-header) of the transport layer; 0 = none
        uint8_t ttl = 0;             // IPv4 TTL / IPv6 hop limit
        uint8_t tcp_flags = 0;       // raw TCP flag byte
        bool has_comment = false;    // the capture file attaches a comment to this packet (pcapng)
        uint8_t fcs_length = 0;      // trailing FCS bytes to exclude from dissection (from the pcap/pcapng header)
        uint8_t tcp_pdu_state = 0;   // 0 = none, 1 = segment of a message reassembled later, 2 = packet that completes a reassembled message
        uint8_t ip_frag = 0;         // 0 = not fragmented, 1 = fragment that is not the last, 2 = last fragment (datagram reassembled here)

        PacketInfo() = default;
        explicit PacketInfo(int num) : number(num) {}
    };
} // namespace packet
