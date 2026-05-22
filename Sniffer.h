#include <iostream>
#include <vector>
#include <string>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>
#include "Packet.h"
#include "HeaderStructures.h"
#include <thread>
#include <conio.h>
#include <fstream>

// TCP Flags
#define TH_FIN  0x01 // Finaliza la conexion TCP
#define TH_SYN  0x02 // Sincroniza la conexion TCP (inicia la conexion)
#define TH_RST  0x04 // Reinicia/aborta la conexion TCP
#define TH_PUSH 0x08 // Fuerza el envio inmediato de datos
#define TH_ACK  0x10 // Confirma la recepcion de datos (ACK)
#define TH_URG  0x20 // Indica que el campo urg_ptr es valido (datos urgentes)

class Sniffer {
    private:
        WSADATA wsa; // Estructura usada por WinSock
        std::string device;
        char error_buffer[PCAP_ERRBUF_SIZE];
        pcap_t *capDev;
        std::vector<Packet> packets;
        int link_hdr_length = 0;
    public:
        Sniffer() {
            // Inicializar WinSock version 2.2
            WSAStartup(MAKEWORD(2,2), &wsa); 

            // Nombre del adaptador de red y buffer para errores
            device = "\\Device\\NPF_{AB41F0A8-F786-4D11-A216-B0DC96D65634}";

            // Abrir el adaptador para captura de paquetes en modo promiscuo 
            capDev = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, error_buffer);

            // Si capDev es nullptr significa que ocurrio un error al abrir el adaptador
            if(!capDev) {
                WSACleanup();
                throw std::runtime_error(error_buffer);
            }
        }

        ~Sniffer() {
            pcap_close(capDev);
            WSACleanup();
        }
        
        // Funcion principal que maneja la captura de paquetes
        void capturar() {

            while(true) {
                std::cout << "\nAplicar filtro? (s/n): ";
                char apply_filter = _getch();

                // Aplicar filtro
                if(apply_filter == 's' || apply_filter == 'S') {
                    aplicarFiltro(capDev);
                    break;
                }

                // Captura sin filtros
                if(apply_filter == 'n' || apply_filter == 'N' ) {
                    std::cout << "\nCaptura sin filtros...." << std::endl;
                    break;
                }
            };

            // Obtener tipo de header de enlace
            int link_hdr_type = pcap_datalink(capDev);
            
            // Determinar tamano del header de enlace de datos
            switch(link_hdr_type) {
                case DLT_NULL: link_hdr_length = 4; break; // Loopback encapsulation
                case DLT_EN10MB: link_hdr_length = 14; break; // Ethernet encapsulation
                default: link_hdr_length = 0; break; // Otros tipos de enlace
            }

            iniciarCaptura(capDev);
        }

        // Callback function llamada por pcap_loop por cada paquete capturado
        static void call_me(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet_ptr) {
            Sniffer* temp = reinterpret_cast<Sniffer*>(args);
            // Saltar del header de enlace (Ethernet, Loopback) al header IP
            packet_ptr += temp->get_link_hdr_length();
            // Interpretar los bytes actuales como un header IP
            const iphdr *ip_hdr = reinterpret_cast<const iphdr*>(packet_ptr);
            
            if((ip_hdr->ver_ihl >> 4) != 4) {
                return; // No es un paquete IPv4, ignorar
            }

            // Estructuras para almacenar IP origen y destino
            in_addr src_addr;
            in_addr dst_addr;

            // Copiar direccones IP de origen y destino del header IP a las estructuras in_addr
            src_addr.s_addr = ip_hdr->saddr;
            dst_addr.s_addr = ip_hdr->daddr;

            // Buffers para almacenar las IPs como texto
            char src_ip[INET_ADDRSTRLEN];
            char dst_ip[INET_ADDRSTRLEN];

            //  Convertir IP binaria -> texto
            inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

            // Extraer informacion del paquete IP
            int packet_id = ntohs(ip_hdr->id);
            int packet_ttl = ip_hdr->ttl;
            int packet_tos = ip_hdr->tos;
            int packet_len = ntohs(ip_hdr->tot_len);
            // Obtener longitud del header IP
            int packet_hlen = (ip_hdr->ver_ihl & 0x0F) * 4;
            if(packet_hlen < 20) {
                return; // Header IP invalido, ignorar
            }

            // Guardar informacion IP en la estructura Packet
            Packet pkt;
            pkt.setId(packet_id);
            pkt.setSrcIp(src_ip);
            pkt.setDstIp(dst_ip);
            pkt.setTos(packet_tos);
            pkt.setTtl(packet_ttl);
            pkt.setLen(packet_len);

            // Saltar el header IP para llegar al protocolo encapsulado
            packet_ptr += packet_hlen;
            // Obtener protocolo encapsulado
            int protocol_type = ip_hdr->protocol;

            // Punteros para headers de protocolos
            const tcphdr* tcp_header;
            const udphdr* udp_header;
            const icmphdr* icmp_header;

            int src_port, dst_port;

            // Analizar protocolo encapsulado
            switch(protocol_type) {
                // TCP
                case IPPROTO_TCP:
                    // Interpretar bytes como TCP header
                    tcp_header = reinterpret_cast<const tcphdr*>(packet_ptr);
                    // Obtener puertos TCP de origen y destino
                    src_port = ntohs(tcp_header->source);
                    dst_port = ntohs(tcp_header->dest);

                    // Guardar informacion TCP en la estructura Packet
                    pkt.setProtocol("TCP");
                    pkt.setSrcPort(src_port);
                    pkt.setDstPort(dst_port);
                    pkt.getFlags().push_back((tcp_header->flags & TH_SYN) ? 'S' : '-');
                    pkt.getFlags().push_back((tcp_header->flags & TH_ACK) ? 'A' : '-');
                    pkt.getFlags().push_back((tcp_header->flags & TH_URG) ? 'U' : '-');
                    break;
                
                // UDP
                case IPPROTO_UDP:
                    // Interpretar bytes como UDP header
                    udp_header =
                        reinterpret_cast<const udphdr*>(packet_ptr);

                    // Obtener puertos UDP de origen y destino
                    src_port = ntohs(udp_header->source);
                    dst_port = ntohs(udp_header->dest);

                    // Guardar informacion UDP en la estructura Packet
                    pkt.setProtocol("UDP");
                    pkt.setSrcPort(src_port);
                    pkt.setDstPort(dst_port);

                    break;

                // ICMP
                case IPPROTO_ICMP:
                    // Interpretar bytes como ICMP header
                    icmp_header =
                        reinterpret_cast<const icmphdr*>(packet_ptr);

                    // Guardar informacion ICMP en la estructura Packet
                    pkt.setProtocol("ICMP");
                    pkt.setIcmpType(icmp_header->type);
                    pkt.setIcmpCode(icmp_header->code);

                    break;
                // Otros protocolos
                default: std::cout << "PROTO: OTHER" << std::endl; break;
            }

            pkt.mostrarPaquete();
            temp->packets.push_back(pkt);
        }

        // Funcion para aplicar un filtro de captura usando BPF
        void aplicarFiltro(pcap_t *capDev) {
            bpf_program bpf {};
            bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN;

            std::string filter_exp;

            // Solicitar al usuario un filtro
            do{
                std::cout << "\nIngrese un filtro (ej: 'tcp', 'udp', 'icmp', 'port 80', etc.): ";
                std::getline(std::cin, filter_exp);
            }while(filter_exp == "");

            // Compilar filtro usnado BPF
            if(pcap_compile(capDev, &bpf, filter_exp.c_str(), 1, netmask) == PCAP_ERROR) {
                std::cout << "\nSin filtros aplicados. Error al aplicar filtro: " << pcap_geterr(capDev) << std::endl;
                return;
            }

            // Aplicar filtro compilado a la captura
            if ( pcap_setfilter(capDev, &bpf) == PCAP_ERROR ) {
                std::cout << "\nSin filtros aplicados. Error al aplicar filtro: " << pcap_geterr(capDev) << std::endl;
                pcap_freecode(&bpf);
                return;
            }
            pcap_freecode(&bpf);
        }

        // Funcion para guardar la captura en un archivo CSV
        void guardarCaptura() {
            while(true) {
                std::cout << "\nGuardar captura? (s/n): ";
                char save_option =_getch();
                if(save_option == 's' || save_option == 'S') {
                    std::ofstream outfile("captura.csv");
                    outfile << "ID,SRC_IP,DST_IP,TOS,TTL,LEN,PROTOCOLO,PUERTO_ORIGEN, PUERTO_DESTINO,ICMP_TYPE,ICMP_CODE,FLAGS\n";
                    for(auto& pkt : packets) {
                        pkt.guardarPaquete(outfile);
                    }
                    outfile.close();
                    packets.clear();
                    std::cout << "\nCaptura guardada en captura.csv" << std::endl;
                    return;
                }
                            
                if(save_option == 'n' || save_option == 'N') {
                    packets.clear();
                    return;
                }
                            
                std::cout << "\nOpcion invalida";
            }
        }

        // Funcion que inicia la captura y maneja la pausa/reanudar
        void iniciarCaptura(pcap_t *capDev) {
            bool salir = false;
            while(!salir) {
                std::cout << "\nPresiona cuaquier tecla para detener la captura..." << std::endl;
                std::thread stopper([&]() {
                    _getch();
                    pcap_breakloop(capDev);
                });

                // Iniciar captura de paquetes
                if (pcap_loop(capDev, 0, call_me, reinterpret_cast<u_char*>(this)) == -1) {
                    std::cout << "\nERR: pcap_loop() failed!" << std::endl;
                    return;
                }

                stopper.join();

                std::cout << "\n====Captura Pausada====\n";
                std::cout << "1. Continuar captura\n";
                std::cout << "2. Volver al menu\n";
                std::cout << "Seleccione una opcion: ";
                char option = _getch();

                switch(option) {
                    case '1': std::cout << "\nReanudando captura...\n"; break;
                    case '2': std::cout << "\nRegresando al menu principal...\n";
                        salir = true; 
                        guardarCaptura();
                    break;
                    default: std::cout << "\nOpcion no valida. Regresando al menu principal...\n";
                        salir = true; break;
                }

            }
            
        }

        int get_link_hdr_length() const { return link_hdr_length; }

};