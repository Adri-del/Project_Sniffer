#ifndef HEADERSTRUCTURES_H
#define HEADERSTRUCTURES_H

#include <cstdint>

#pragma pack(push, 1)

// Header IPv4
struct iphdr {
    uint8_t ver_ihl; // Versión (4 bits) + IHL (4 bits)
    uint8_t tos; // Tipo de servicio
    uint16_t tot_len; // Longitud total
    uint16_t id; // Identificación
    uint16_t frag_off; // Desplazamiento de fragmento y banderas
    uint8_t ttl; // Tiempo de vida
    uint8_t protocol; // Protocolo (TCP=6, UDP=17, ICMP=1)
    uint16_t check; // Checksum de la cabecera
    uint32_t saddr; // Dirección IP origen
    uint32_t daddr; // Dirección IP destino
};

// Header TCP
struct tcphdr {
    uint16_t source; // Puerto origen
    uint16_t dest; // Puerto destino
    uint32_t seq; // Número de secuencia
    uint32_t ack_seq; // Número de acuse de recibo
    uint8_t doff_reserved; // Desplazamiento de datos (4 bits) + reservados (4 bits)
    uint8_t flags; // Banderas (SYN, ACK, FIN, RST, etc.)
    uint16_t window; // Tamaño de ventana
    uint16_t check; // Checksum
    uint16_t urg_ptr; // Puntero urgente
};

// Header UDP
struct udphdr {
    uint16_t source; // Puerto origen
    uint16_t dest; // Puerto destino
    uint16_t len; // Longitud
    uint16_t check; // Checksum
};

// Header ICMP
struct icmphdr {
    uint8_t type; // Tipo ICMP
    uint8_t code; // Código ICMP
    uint16_t checksum; // Checksum
};

#pragma pack(pop)

#endif // HEADERSTRUCTURES_H