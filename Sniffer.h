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
#include <cctype>

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
        int cont_pkt;

        // Validador de cadena numerica
        bool esNumeroValido(const std::string& str) {
            if (str.empty()) return false;
            for (char const &c : str) {
                if (!std::isdigit(c)) return false;
            }
            return true;
        }

        // Validador de formato IPv4
        bool esIpValida(const std::string& ip) {
            unsigned int puntos = 0;
            std::string octeto = "";
            
            if (ip.empty()) return false;
            
            for (size_t i = 0; i < ip.length(); i++) {
                if (ip[i] == '.') {
                    puntos++;
                    if (octeto.empty() || !esNumeroValido(octeto) || std::stoi(octeto) > 255) return false;
                    octeto = "";
                } else if (std::isdigit(ip[i])) {
                    octeto += ip[i];
                } else {
                    return false; // Carácter no permitido (letras, símbolos, etc.)
                }
            }
            // Validar el último octeto
            if (octeto.empty() || !esNumeroValido(octeto) || std::stoi(octeto) > 255) return false;
            
            return puntos == 3;
        }

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
            const u_char* original_packet_ptr = packet_ptr;
            Sniffer* temp = reinterpret_cast<Sniffer*>(args);

            std::string link_type_str;
            char mac_dst[18] = "";
            char mac_src[18] = "";
            if(temp->link_hdr_length == 14) {
                link_type_str = "Ethernet";
                snprintf(mac_dst, sizeof(mac_dst), "%02X:%02X:%02X:%02X:%02X:%02X", packet_ptr[0], packet_ptr[1], packet_ptr[2], packet_ptr[3], packet_ptr[4], packet_ptr[5]);
                snprintf(mac_src, sizeof(mac_src), "%02X:%02X:%02X:%02X:%02X:%02X", packet_ptr[6], packet_ptr[7], packet_ptr[8], packet_ptr[9], packet_ptr[10], packet_ptr[11]);
            } else if(temp->link_hdr_length == 4) {
                link_type_str = "Loopback";
            } else {
                link_type_str = "Otro";
            }
            
            // Saltar del header de enlace (Ethernet, Loopback) al header IP
            packet_ptr += temp->get_link_hdr_length();
            // Interpretar los bytes actuales como un header IP
            const iphdr *ip_hdr = reinterpret_cast<const iphdr*>(packet_ptr);
            
            if((ip_hdr->ver_ihl >> 4) != 4) {
                return; // No es un paquete IPv4
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
            int packet_ip_id = ntohs(ip_hdr->id);
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
            pkt.setId(temp->cont_pkt++);
            pkt.setIP_ID(packet_ip_id);
            pkt.setLinkType(link_type_str);
            pkt.setMacSrc(mac_src);
            pkt.setMacDst(mac_dst);
            pkt.setSrcIp(src_ip);
            pkt.setDstIp(dst_ip);
            pkt.setTos(packet_tos);
            pkt.setTtl(packet_ttl);
            pkt.setLen(packet_len);
            std::vector<unsigned char> rawData(original_packet_ptr, original_packet_ptr + pkthdr->caplen);
            pkt.setRawData(rawData);

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

            pkt.mostrarResumen();
            temp->packets.push_back(pkt);
        }

        // Funcion para aplicar un filtro de captura usando BPF
        void aplicarFiltro(pcap_t *capDev) {
            bpf_program bpf {};
            bpf_u_int32 netmask = PCAP_NETMASK_UNKNOWN;
            std::string filter_exp = "";
            char op_menu;

            do {
                std::cout << "\n=== Menu Filtros ===\n";
                std::cout << "1. Protocolos\n";
                std::cout << "2. Puerto\n";
                std::cout << "3. Ip destino\n";
                std::cout << "4. Ip fuente\n";
                std::cout << "Seleccione una opcion: ";
                op_menu = _getch();
                std::cout << op_menu << std::endl;

                if (op_menu < '1' || op_menu > '4') {
                    std::cout << "Opcion no valida. Intente de nuevo.\n";
                }
            } while (op_menu < '1' || op_menu > '4');

            if (op_menu == '1') {
                char op_proto;
                do {
                    std::cout << "\n--- Opciones de Protocolo ---\n";
                    std::cout << "1. UDP\n";
                    std::cout << "2. TCP\n";
                    std::cout << "3. ICMP\n";
                    std::cout << "Seleccione una opcion: ";
                    op_proto = _getch();
                    std::cout << op_proto << std::endl;

                    switch(op_proto) {
                        case '1': filter_exp = "udp"; break;
                        case '2': filter_exp = "tcp"; break;
                        case '3': filter_exp = "icmp"; break;
                        default: std::cout << "Opcion no valida. Intente de nuevo.\n"; break;
                    }
                } while (op_proto < '1' || op_proto > '3');
            } 
            else if (op_menu == '2') {
                std::string puerto;
                while (true) {
                    std::cout << "\nIngrese el numero de puerto: ";
                    std::getline(std::cin, puerto);
                    if (esNumeroValido(puerto)) {
                        filter_exp = "port " + puerto;
                        break;
                    } else {
                        std::cout << "Error: Solo se permite ingresar numeros.\n";
                    }
                }
            } 
            else if (op_menu == '3') {
                std::string ip_dest;
                while (true) {
                    std::cout << "\nIngrese la IP de destino (ej: 192.168.1.1): ";
                    std::getline(std::cin, ip_dest);
                    if (esIpValida(ip_dest)) {
                        filter_exp = "dst host " + ip_dest;
                        break;
                    } else {
                        std::cout << "Error: Debe ingresar solo numeros en el formato de una ip (X.X.X.X).\n";
                    }
                }
            } 
            else if (op_menu == '4') {
                std::string ip_src;
                while (true) {
                    std::cout << "\nIngrese la IP fuente (ej: 192.168.1.1): ";
                    std::getline(std::cin, ip_src);
                    if (esIpValida(ip_src)) {
                        filter_exp = "src host " + ip_src;
                        break;
                    } else {
                        std::cout << "Error: Debe ingresar solo numeros en el formato de una ip (X.X.X.X).\n";
                    }
                }
            }

            std::cout << "\nFiltro generado: '" << filter_exp << "'" << std::endl;

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
                    outfile << "ID,IP_ID,ENLACE,MAC_SRC,MAC_DST,SRC_IP,DST_IP,TOS,TTL,LEN,PROTOCOLO,PUERTO_ORIGEN, PUERTO_DESTINO,ICMP_TYPE,ICMP_CODE,FLAGS,RAW_DATA\n";
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
            cont_pkt = 0;
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
                std::cout << "2. Seleccionar Paquete\n";
                std::cout << "3. Volver al menu\n";
                std::cout << "Seleccione una opcion: ";
                char option = _getch();

                switch(option) {
                    case '1': std::cout << "\nReanudando captura...\n"; break;
                    case '2': {
                        int id;
                        bool encontrado = false;
                        Packet seleccionado;

                        while (!encontrado) {
                            std::cout << "\nIngrese el ID del paquete a visualizar: ";
                            std::cin >> id;

                            if (std::cin.fail()) {
                                std::cin.clear();
                                std::cin.ignore(10000, '\n');
                                std::cout << "ID invalida\n";
                                continue;
                            }

                            for (Packet& p : packets) {
                                if (p.getId() == id) {
                                    seleccionado = p;
                                    encontrado = true;
                                    break;
                                }
                            }

                            if (!encontrado) {
                                std::cout << "No se encontro un paquete con ese ID.\n";
                            }
                        }

                        seleccionado.mostrarDetalle();
                        seleccionado.mostrarDataRaw();

                        std::cin.ignore(10000, '\n');
                        std::cin.get();
                    }
                    break;
                    case '3': std::cout << "\nRegresando al menu principal...\n";
                        cont_pkt = 0;
                        salir = true; 
                        guardarCaptura();
                    break;
                    default: std::cout << "\nOpcion no valida. Regresando al menu principal...\n";
                        cont_pkt = 0;
                        salir = true; break;
                }

            }
            
        }

        int get_link_hdr_length() const { return link_hdr_length; }

};