#ifndef PCAP_PACKET_HEADER_H
#define PCAP_PACKET_HEADER_H
#include <cstdint>

struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};

#endif // PCAP_PACKET_HEADER_H
