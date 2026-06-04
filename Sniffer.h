#ifndef SNIFFER_H
#define SNIFFER_H

#include <string>
#include <vector>
#include <functional>
#include <atomic>
#include <stdexcept>
#include <cstring>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <pcap.h>

#include "Packet.h"
#include "HeaderStructures.h"

// TCP Flag masks
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20

class Sniffer {
private:

    // WinSock information
    WSADATA wsa;

    // Selected network interface
    std::string device;

    // Buffer used by pcap to store error messages
    char error_buffer[PCAP_ERRBUF_SIZE];

    // Packet capture device
    pcap_t* capDev = nullptr;

    // Length of the data link header
    int link_hdr_length = 0;

    // Indicates whether packet capture is active
    std::atomic<bool> capturing { false };

public:

    // Callback used to send captured packets to MainWindow
    std::function<void(const Packet&)> onPacketCaptured;

    // Initializes WinSock and automatically selects a network interface
    Sniffer() {

        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
            throw std::runtime_error("Error inicializando WinSock");

        pcap_if_t* alldevs = nullptr;

        if (pcap_findalldevs(&alldevs, error_buffer) == -1 || !alldevs) {
            WSACleanup();
            throw std::runtime_error("No se pudo obtener interfaces de red");
        }

        // Look for a wireless interface first
        for (pcap_if_t* d = alldevs; d; d = d->next) {
            if (d->description &&
                std::string(d->description).find("Wireless") != std::string::npos) {
                device = d->name;
                break;
            }
        }

        if (device.empty())
            device = alldevs->name;

        pcap_freealldevs(alldevs);

        // Open the selected interface for live packet capture
        capDev = pcap_open_live(device.c_str(),
                                BUFSIZ,
                                1,
                                1000,
                                error_buffer);

        if (!capDev) {
            WSACleanup();
            throw std::runtime_error(error_buffer);
        }
    }

    // Releases resources used by WinSock and pcap
    ~Sniffer() {
        if (capDev)
            pcap_close(capDev);

        WSACleanup();
    }

    // Starts packet capture using an optional BPF filter
    void capturar(const std::string& filterExp = "") {

        // Determine the length of the data link header
        switch (pcap_datalink(capDev)) {
        case DLT_NULL:
            link_hdr_length = 4;
            break;

        case DLT_EN10MB:
            link_hdr_length = 14;
            break;

        default:
            link_hdr_length = 0;
            break;
        }

        // Apply BPF filter if provided
        if (!filterExp.empty()) {

            bpf_program bpf {};

            if (pcap_compile(capDev,
                             &bpf,
                             filterExp.c_str(),
                             1,
                             PCAP_NETMASK_UNKNOWN) == 0) {

                pcap_setfilter(capDev, &bpf);
                pcap_freecode(&bpf);
            }
        }

        capturing = true;

        // Capture loop
        while (capturing) {

            int res = pcap_dispatch(
                capDev,
                32,
                call_me,
                reinterpret_cast<u_char*>(this)
            );

            if (res < 0)
                break;
        }
    }

    // Stops packet capture
    void detener() {

        capturing = false;

        if (capDev)
            pcap_breakloop(capDev);
    }

    // Returns the selected network interface
    const std::string& getDevice() const {
        return device;
    }

private:

    // Static callback executed for each captured packet
    static void call_me(
        u_char* args,
        const struct pcap_pkthdr* pkthdr,
        const u_char* raw_frame)
    {
        Sniffer* self = reinterpret_cast<Sniffer*>(args);

        if (!self->capturing)
            return;

        // Save the complete frame for later analysis
        const u_char* frame_start = raw_frame;
        uint32_t frame_len = pkthdr->caplen;

        // Skip the data link header and move to the IP header
        if (frame_len <= static_cast<uint32_t>(self->link_hdr_length))
            return;

        const u_char* ip_start =
            raw_frame + self->link_hdr_length;

        const iphdr* ip =
            reinterpret_cast<const iphdr*>(ip_start);

        // Process only IPv4 packets
        if ((ip->ver_ihl >> 4) != 4)
            return;

        // Get the IP header length
        int ip_hlen = (ip->ver_ihl & 0x0F) * 4;

        if (ip_hlen < 20)
            return;

        // Convert source and destination IP addresses to text
        in_addr src_addr;
        in_addr dst_addr;

        src_addr.s_addr = ip->saddr;
        dst_addr.s_addr = ip->daddr;

        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET,
                  &src_addr,
                  src_ip,
                  INET_ADDRSTRLEN);

        inet_ntop(AF_INET,
                  &dst_addr,
                  dst_ip,
                  INET_ADDRSTRLEN);

        // Fill IP packet information
        Packet pkt;

        pkt.setId(ntohs(ip->id));
        pkt.setSrcIp(src_ip);
        pkt.setDstIp(dst_ip);
        pkt.setTos(ip->tos);
        pkt.setTtl(ip->ttl);
        pkt.setLen(ntohs(ip->tot_len));

        // Pointer to the transport layer header
        const u_char* transport =
            ip_start + ip_hlen;

        // Analyze the transport protocol
        switch (ip->protocol) {

        case IPPROTO_TCP: {

            // Extract TCP information
            const tcphdr* tcp =
                reinterpret_cast<const tcphdr*>(transport);

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

            // Extract UDP information
            const udphdr* udp =
                reinterpret_cast<const udphdr*>(transport);

            pkt.setProtocol("UDP");
            pkt.setSrcPort(ntohs(udp->source));
            pkt.setDstPort(ntohs(udp->dest));

            break;
        }

        case IPPROTO_ICMP: {

            // Extract ICMP information
            const icmphdr* icmp =
                reinterpret_cast<const icmphdr*>(transport);

            pkt.setProtocol("ICMP");
            pkt.setIcmpType(icmp->type);
            pkt.setIcmpCode(icmp->code);

            break;
        }

        default:

            // Unsupported protocol
            pkt.setProtocol("OTHER");
            break;
        }

        // Store the complete frame data
        pkt.setRawData(
            std::vector<unsigned char>(
                frame_start,
                frame_start + frame_len
            )
        );

        // Send the packet to MainWindow
        if (self->onPacketCaptured)
            self->onPacketCaptured(pkt);
    }
};

#endif
