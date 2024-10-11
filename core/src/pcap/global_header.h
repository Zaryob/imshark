#pragma once

#include <cstdint>

namespace pcap {
    struct GlobalHeader {
        uint32_t magic_number;   // magic number (0xa1b2c3d4)
        uint16_t version_major;  // major version number
        uint16_t version_minor;  // minor version number
        int32_t thiszone;        // GMT to local correction
        uint32_t sigfigs;        // accuracy of timestamps
        uint32_t snaplen;        // max length of captured packets, in octets
        uint32_t network;        // data link type
    };
} // namespace pcap