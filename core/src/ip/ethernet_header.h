#ifndef ETHERNET_HEADER_H
#define ETHERNET_HEADER_H

struct EthernetHeader {
    uint8_t dest_mac[6];
    uint8_t src_mac[6];
    uint16_t type;
};

struct IPHeader {
    uint8_t ihl:4, version:4;
    uint8_t tos;
    uint16_t tot_length;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint32_t saddr;
    uint32_t daddr;
};

struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t check;
};

struct TCPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_pointer;
};

struct ARPHeader {
    uint16_t hw_type;
    uint16_t protocol_type;
    uint8_t hw_addr_len;
    uint8_t protocol_addr_len;
    uint16_t opcode;
    uint8_t sender_hw_addr[6];
    uint8_t sender_protocol_addr[4];
    uint8_t target_hw_addr[6];
    uint8_t target_protocol_addr[4];
};

#endif // ETHERNET_HEADER_H
