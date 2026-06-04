#ifndef HEADERSTRUCTURES_H
#define HEADERSTRUCTURES_H

#include <cstdint>

#pragma pack(push, 1)

// IPv4 HEADER
struct iphdr {
    uint8_t  ver_ihl;     // Version (4 bits) + IHL (4 bits)
    uint8_t  tos;         // Type of Service
    uint16_t tot_len;     // Total Length
    uint16_t id;          // Identification
    uint16_t frag_off;    // Fragment offset + flags
    uint8_t  ttl;         // Time To Live
    uint8_t  protocol;    // Protocol (TCP=6, UDP=17, ICMP=1)
    uint16_t check;       // Header checksum
    uint32_t saddr;       // Source IP
    uint32_t daddr;       // Destination IP
};

// TCP HEADER
struct tcphdr {
    uint16_t source;       // Source port
    uint16_t dest;         // Destination port
    uint32_t seq;          // Sequence number
    uint32_t ack_seq;      // Acknowledgment number
    uint8_t  doff_reserved;// Data offset (4 bits) + reserved (4 bits)
    uint8_t  flags;        // Flags (SYN, ACK, FIN, RST, etc.)
    uint16_t window;       // Window size
    uint16_t check;        // Checksum
    uint16_t urg_ptr;      // Urgent pointer
};

// UDP HEADER
struct udphdr {
    uint16_t source;      // Source port
    uint16_t dest;        // Destination port
    uint16_t len;         // Length
    uint16_t check;       // Checksum
};

// ICMP HEADER
struct icmphdr {
    uint8_t  type;        // ICMP type
    uint8_t  code;        // ICMP code
    uint16_t checksum;    // Checksum
};

#pragma pack(pop)

#endif 
