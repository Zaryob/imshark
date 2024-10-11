#pragma once

#include <cstdint>

namespace pcap {
    struct PacketHeader {
        uint32_t ts_sec;   // timestamp seconds
        uint32_t ts_usec;  // timestamp microseconds
        uint32_t incl_len; // number of octets of packet saved in file
        uint32_t orig_len; // actual length of packet
    };
} // namespace pcap
