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

struct ipv6_addr {
    unsigned char s6_addr[16]; // 128-bit IPv6 address (16 bytes)
};

#pragma pack(1)
struct IPv6Header {
    uint32_t version: 4;
    uint32_t trafficClass: 8;
    uint32_t flowLabel: 20;
    uint16_t payloadLength;  // 16-bit payload length
    uint8_t nextHeader;      // 8-bit next header (protocol)
    uint8_t hopLimit;        // 8-bit hop limit
    struct ipv6_addr srcAddr; // Source IPv6 address (16 bytes)
    struct ipv6_addr dstAddr; // Destination IPv6 address (16 bytes)
};
#pragma pack(reset)

struct UDPHeader {
    uint16_t src_port;
    uint16_t dest_port;
    uint16_t len;
    uint16_t check;
};

// TCP Flag Definitions
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20

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

struct DNSHeader {
    uint16_t transactionID;    // Identification number
    uint16_t flags;            // Flags
    uint16_t questions;        // Number of questions
    uint16_t answerRRs;        // Number of answer resource records
    uint16_t authorityRRs;     // Number of authority resource records
    uint16_t additionalRRs;    // Number of additional resource records
};

struct ICMPHeader {
    uint8_t type;        // ICMP message type
    uint8_t code;        // ICMP message code
    uint16_t checksum;   // ICMP checksum
    uint16_t identifier; // Identifier (for Echo Request/Reply)
    uint16_t sequence;   // Sequence number (for Echo Request/Reply)
};

struct DHCPHeader {
    uint8_t op;               // Message op code / message type
    uint8_t htype;            // Hardware address type
    uint8_t hlen;             // Hardware address length
    uint8_t hops;             // Hops
    uint32_t xid;             // Transaction ID
    uint16_t secs;            // Seconds elapsed since client started
    uint16_t flags;           // Flags
    uint32_t ciaddr;          // Client IP address
    uint32_t yiaddr;          // 'Your' (client) IP address
    uint32_t siaddr;          // Next server IP address
    uint32_t giaddr;          // Relay agent IP address
    uint8_t chaddr[16];       // Client hardware address
    uint8_t sname[64];        // Server host name
    uint8_t file[128];        // Boot file name
    uint8_t options[];        // Optional parameters
};


#endif // ETHERNET_HEADER_H
