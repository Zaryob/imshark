#ifndef PCAP_GLOBAL_HEADER_H
#define PCAP_GLOBAL_HEADER_H
#include <cstdint>

struct PcapGlobalHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

#endif // PCAP_GLOBAL_HEADER_H