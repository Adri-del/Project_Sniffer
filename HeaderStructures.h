// IPv4 header structure
struct iphdr {
    unsigned char ver_ihl; // Version IP (4 bits) + Internet header Length (4 bits)

    unsigned char tos; // Tipo de servicio
    unsigned short tot_len; // Longitud total del paquete IP

    unsigned short id; // Indentificador del paquete, se utiliza para la fragmentacion
    unsigned short frag_off; // Fragmentacion offset y flags de fragmentacion

    unsigned char ttl; // Tiempo de vida del paquete
    unsigned char protocol; // Protocolo encapsulado (TCP, UDP, ICMP, etc.)

    unsigned short check; // Checksum del header IP

    unsigned int saddr; // Direccion Ip de origen
    unsigned int daddr; // Direccion Ip de destino
};

// TCP header structure
struct tcphdr {
    unsigned short source; // Puerto de origen
    unsigned short dest; // Puerto de destino

    unsigned int seq; // Numero de secuencia del paquete TCP
    unsigned int ack_seq; // Numero de confirmacion del paquete TCP (ACK)

    unsigned char reserved : 4; // Bits reservados
    unsigned char doff : 4; // Data Offset (Longitud del header TCP)

    unsigned char flags; // Flags TCP (SYN, ACK, FIN, RST, etc.)

    unsigned short window; // Tamaño de la ventana TCP
    unsigned short check; // Checksum del header TCP
    unsigned short urg_ptr; // Puntero urgente (si el flag URG esta activo)
};

//UDP header structure
struct udphdr {

    unsigned short source; // Puerto de origen
    unsigned short dest; // Puerto de destino

    unsigned short len; // Longitud total del segmento UDP (header + data)
    unsigned short check; // Checksum UDP
};

// ICMP header structure
struct icmphdr {

    unsigned char type; // Tipo de mensaje ICMP (Echo Request, Echo Reply, Destination Unreachable, etc.)
    unsigned char code; // Codigo especifico del mensaje ICMP 

    unsigned short checksum; // Checksum del mensaje ICMP
};
