#ifndef SNIFFER_H
#define SNIFFER_H

#include <iostream>
#include <vector>
#include <string>
#include <functional>
#include <atomic>
#include <cstring>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>

#include "Packet.h"
#include "HeaderStructures.h"
#include "Elige_Interfaz.h"

// Banderas TCP
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

class Sniffer {
private:
    WSADATA wsa;
    std::string device;
    char error_buffer[PCAP_ERRBUF_SIZE];
    pcap_t* capDev = nullptr;
    int link_hdr_length = 0;
    std::atomic<bool> capturing { false };
    std::atomic<int> contador;

public:
    // Callback que MainWindow conecta para recibir cada paquete capturado
    std::function<void(const Packet&)> onPacketCaptured;

    // Constructor: detecta interfaz automaticamente
    Sniffer() {
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            throw std::runtime_error("Error inicializando WinSock");

        pcap_if_t* alldevs = nullptr;
        if (pcap_findalldevs(&alldevs, error_buffer) == -1 || !alldevs) {
            WSACleanup();
            throw std::runtime_error("No se pudo obtener interfaces de red");
        }

        device = elige_Interfaz(alldevs);

        pcap_freealldevs(alldevs);

        capDev = pcap_open_live(device.c_str(), BUFSIZ, 1, 1000, error_buffer);
        if (!capDev) {
            WSACleanup();
            throw std::runtime_error(error_buffer);
        }
        contador = 1;
    }

    ~Sniffer() {
        if (capDev) pcap_close(capDev);
        WSACleanup();
    }

    // capturar(): llama desde un hilo separado en MainWindow
    //   filterExp: expresion BPF opcional (ej. "tcp", "port 80", "").
    void capturar(const std::string& filterExp = "") {
        // Determinar tamaño del header de enlace (Ethernet = 14 bytes)
        switch (pcap_datalink(capDev)) {
        case DLT_NULL: link_hdr_length = 4;  break;
        case DLT_EN10MB: link_hdr_length = 14; break;
        default: link_hdr_length = 0;  break;
        }

        // Aplicar filtro BPF si se proporciono uno
        if (!filterExp.empty()) {
            bpf_program bpf {};
            if (pcap_compile(capDev, &bpf, filterExp.c_str(), 1, PCAP_NETMASK_UNKNOWN) == 0) {
                pcap_setfilter(capDev, &bpf);
                pcap_freecode(&bpf);
            }
        }

        capturing = true;

        // Loop de captura - procesa hasta 32 paquetes por iteracion
        while (capturing) {
            int res = pcap_dispatch(capDev, 32, call_me, reinterpret_cast<u_char*>(this));
            if (res < 0) break; // error
        }
    }

    void detener() {
        capturing = false;
        if (capDev) pcap_breakloop(capDev);
    }

    // Devuelve el nombre de la interfaz seleccionada
    const std::string& getDevice() const { return device; }

private:
    // Callback estatico de pcap
    static void call_me(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* raw_frame) {
        Sniffer* self = reinterpret_cast<Sniffer*>(args);
        if (!self->capturing) return;

        // Guardar puntero al inicio del frame para rawData
        const u_char* frame_start = raw_frame;
        uint32_t frame_len = pkthdr->caplen;

        // Saltar header de enlace para llegar al header IP
        if (frame_len <= static_cast<uint32_t>(self->link_hdr_length)) return;
        const u_char* ip_start = raw_frame + self->link_hdr_length;

        const iphdr* ip = reinterpret_cast<const iphdr*>(ip_start);

        // Solo IPv4
        if ((ip->ver_ihl >> 4) != 4) return;

        int ip_hlen = (ip->ver_ihl & 0x0F) * 4;
        if (ip_hlen < 20) return;

        // Convertir IPs a texto
        in_addr src_addr, dst_addr;
        src_addr.s_addr = ip->saddr;
        dst_addr.s_addr = ip->daddr;

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &src_addr, src_ip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &dst_addr, dst_ip, INET_ADDRSTRLEN);

        // Rellenar campos IP del paquete
        Packet pkt;
        pkt.setId(self->contador);
        pkt.setSrcIp(src_ip);
        pkt.setDstIp(dst_ip);
        pkt.setTos(ip->tos);
        pkt.setTtl(ip->ttl);
        pkt.setLen(ntohs(ip->tot_len));

        // Puntero al payload del protocolo de transporte
        const u_char* transport = ip_start + ip_hlen;

        switch (ip->protocol) {

        case IPPROTO_TCP: {
            const tcphdr* tcp = reinterpret_cast<const tcphdr*>(transport);
            pkt.setProtocol("TCP");
            pkt.setSrcPort(ntohs(tcp->source));
            pkt.setDstPort(ntohs(tcp->dest));
            pkt.addFlag((tcp->flags & TH_SYN) ? 'S' : '-');
            pkt.addFlag((tcp->flags & TH_ACK) ? 'A' : '-');
            pkt.addFlag((tcp->flags & TH_FIN) ? 'F' : '-');
            pkt.addFlag((tcp->flags & TH_RST) ? 'R' : '-');
            pkt.addFlag((tcp->flags & TH_URG) ? 'U' : '-');
            break;
        }

        case IPPROTO_UDP: {
            const udphdr* udp = reinterpret_cast<const udphdr*>(transport);
            pkt.setProtocol("UDP");
            pkt.setSrcPort(ntohs(udp->source));
            pkt.setDstPort(ntohs(udp->dest));
            break;
        }

        case IPPROTO_ICMP: {
            const icmphdr* icmp = reinterpret_cast<const icmphdr*>(transport);
            pkt.setProtocol("ICMP");
            pkt.setIcmpType(icmp->type);
            pkt.setIcmpCode(icmp->code);
            break;
        }

        default:
            pkt.setProtocol("OTHER");
            break;
        }

        // Guardar el frame completo como raw data
        pkt.setRawData(std::vector<unsigned char>(frame_start, frame_start + frame_len));

        // Enviar paquete a MainWindow via callback
        if (self->onPacketCaptured)
            self->onPacketCaptured(pkt);
        self->contador++;
    }
};

#endif