//
// Created by Süleyman Poyraz on 11.10.2024.
//

#pragma once

#include <cstdint>

namespace network {
    // TCP Flag Definitions
    enum class TCPFlags : uint8_t {
        FIN = 0x01,
        SYN = 0x02,
        RST = 0x04,
        PSH = 0x08,
        ACK = 0x10,
        URG = 0x20
    };

    // Helper function to cast enum class to uint8_t
    inline uint8_t operator&(const uint8_t flags, const TCPFlags& flag) {
        return flags & static_cast<uint8_t>(flag);
    }


    struct TCPHeader {
        uint16_t src_port;          // Source Port
        uint16_t dest_port;         // Destination Port
        uint32_t seq_num;           // Sequence Number
        uint32_t ack_num;           // Acknowledgment Number
        uint8_t data_offset;        // Data Offset
        uint8_t flags;              // Flags (look: TCPFlags)
        uint16_t window;            // Window
        uint16_t checksum;          // Checksum
        uint16_t urgent_pointer;    // Urgent Pointer
    };
} // namespace network