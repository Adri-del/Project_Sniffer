#ifndef PACKET_H
#define PACKET_H

#include <string>
#include <vector>
#include <fstream>
#include <iostream>

class Packet {
private:
    // IP
    int         id      = 0;
    std::string src_ip;
    std::string dst_ip;
    int         tos     = 0;
    int         ttl     = 0;
    int         len     = 0;

    // Protocolo encapsulado
    std::string protocol;

    // Puertos (TCP / UDP)
    int src_port = -1;
    int dst_port = -1;

    // ICMP
    int icmp_type = -1;
    int icmp_code = -1;

    // Flags TCP
    std::string flags;

    // Contenido bruto del paquete
    std::vector<unsigned char> rawData;

public:
    Packet() = default;
    Packet(const Packet&)            = default;
    Packet& operator=(const Packet&) = default;

    // Exportar a CSV
    void guardarPaquete(std::ofstream& outfile) const {
        outfile << id       << ","
                << src_ip   << ","
                << dst_ip   << ","
                << tos      << ","
                << ttl      << ","
                << len      << ","
                << protocol << ","
                << src_port << ","
                << dst_port << ","
                << icmp_type << ","
                << icmp_code << ","
                << flags    << "\n";
    }

    // Debug
    void mostrarPaquete() const {
        std::cout << "ID:" << id
                  << " SRC:" << src_ip
                  << " DST:" << dst_ip
                  << " PROTO:" << protocol
                  << std::endl;
    }

    // Setters
    void setId(int v)                                    { id       = v; }
    void setSrcIp(const std::string& v)                  { src_ip   = v; }
    void setDstIp(const std::string& v)                  { dst_ip   = v; }
    void setTos(int v)                                   { tos      = v; }
    void setTtl(int v)                                   { ttl      = v; }
    void setLen(int v)                                   { len      = v; }
    void setProtocol(const std::string& v)               { protocol = v; }
    void setSrcPort(int v)                               { src_port = v; }
    void setDstPort(int v)                               { dst_port = v; }
    void setIcmpType(int v)                              { icmp_type = v; }
    void setIcmpCode(int v)                              { icmp_code = v; }
    void setFlags(const std::string& v)                  { flags    = v; }
    void addFlag(char f)                                 { flags.push_back(f); }
    void setRawData(const std::vector<unsigned char>& v) { rawData  = v; }

    // Getters
    int                              getId()       const { return id;       }
    const std::string&               getSrcIp()    const { return src_ip;   }
    const std::string&               getDstIp()    const { return dst_ip;   }
    int                              getTos()      const { return tos;      }
    int                              getTtl()      const { return ttl;      }
    int                              getLen()      const { return len;      }
    const std::string&               getProtocol() const { return protocol; }
    int                              getSrcPort()  const { return src_port; }
    int                              getDstPort()  const { return dst_port; }
    int                              getIcmpType() const { return icmp_type;}
    int                              getIcmpCode() const { return icmp_code;}
    const std::string&               getFlags()    const { return flags;    }
    const std::vector<unsigned char>& getRawData() const { return rawData;  }
};

#endif
