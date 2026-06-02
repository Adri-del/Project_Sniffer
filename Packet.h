#include <string>
#include <vector>
#include <fstream>
#include <iostream>
#include <iomanip>

// Clase que representa un paquete de red capturado
// Almacena el encabezado IP
// Almacena informacion especifica de cada protocolo (TCP, UDP o ICMP)
// Almacena el contenidobruto del paquete 
class Packet {
    private:

        int id;
        int ip_id;

        // Informacion de la capa de enlace
        std::string link_type;
        std::string mac_src;
        std::string mac_dst;

        // Informacion de la capa de red (Protocolo IP)
        std::string src_ip;
        std::string dst_ip;

        int tos;
        int ttl;
        int len;

        // Protocolo encapsulado (TCP, UDP, ICMP, etc.)
        std::string protocol;

        // Informacion de transporte (TCP o UDP)
        int src_port = -1;
        int dst_port = -1;

        // Informacion de ICMP
        int icmp_type = -1;
        int icmp_code = -1;

        // Flags TCP (SYN, ACK, URG, etc.)
        std::string flags;

        // Contenido bruto del paquete
        std::vector<unsigned char> rawData;

    public:
        Packet() = default;
        Packet(const Packet& obj) {
            id = obj.id;
            ip_id = obj.ip_id;
            link_type = obj.link_type;
            mac_src = obj.mac_src;
            mac_dst =obj.mac_dst;
            src_ip = obj.src_ip;
            dst_ip = obj.dst_ip;
            tos = obj.tos;
            ttl = obj.ttl;
            len = obj.len;
            protocol = obj.protocol;
            src_port = obj.src_port;
            dst_port = obj.dst_port;
            icmp_type = obj.icmp_type;
            icmp_code = obj.icmp_code;
            flags = obj.flags;
            rawData = obj.rawData;
        }

        Packet& operator=(const Packet& obj) {
            if(this != &obj) {
                id = obj.id; 
                ip_id = obj.ip_id;
                link_type = obj.link_type;
                mac_src = obj.mac_src;
                mac_dst =obj.mac_dst;
                src_ip = obj.src_ip;
                dst_ip = obj.dst_ip;
                tos = obj.tos;
                ttl = obj.ttl;
                len = obj.len;
                protocol = obj.protocol;
                src_port = obj.src_port;
                dst_port = obj.dst_port;
                icmp_type = obj.icmp_type;
                icmp_code = obj.icmp_code;
                flags = obj.flags;
                rawData = obj.rawData;
            }
            return *this;
        }

        // Exporta la informacion del paquete en formato CSV
        void guardarPaquete(std::ofstream& outfile) const {
            std::string raw;
            for(unsigned char byte : rawData) {
                raw += (byte < 16 ? "0" : "") + std::to_string(byte);
            }
            outfile << id << ","
                    << ip_id << ","
                    << link_type << ","
                    << mac_src << ","
                    << mac_dst << ","
                    << src_ip << ","
                    << dst_ip << ","
                    << tos << ","
                    << ttl << ","
                    << len << ","
                    << protocol << ","
                    << src_port << ","
                    << dst_port << ","
                    << icmp_type << ","
                    << icmp_code << ","
                    << flags << ","
                    << raw << "\n";
        }

        // Muestra la informacion del paquete
        void mostrarResumen() {
            // Mostrar informacion IP
            std::cout << "======================================================================\n";
            std::cout << "ID: " << id;
            std::cout << "| SRC: " << src_ip;
            std::cout << "| DST: " << dst_ip;
            std::cout << "| TOS: 0x" << std::hex << tos;
            std::cout << "| TTL: " << std::dec << ttl;
            std::cout << "| LEN: " << len << std::endl;

            std::cout << "PROTO: " << protocol;

            // Mostrar flags TCP
            if(flags != "") {
                std::cout << " | FLAGS: " << flags;
            }

            // Mostrar puertos TCP o UDO
            if(src_port != -1 && dst_port != -1) {
                std::cout << " | SPORT: " << src_port;
                std::cout << " | DPORT: " << dst_port;
            }

            // Mostrar informacion ICMP
            if(icmp_type != -1 && icmp_code != -1) {
                std::cout << " | TYPE: " << icmp_type;
                std::cout << " | CODE: " << icmp_code;
            }

            std::cout << std::endl;
        }

        // Mostrar la informacion detallada del paquete
        void mostrarDetalle() {
            std::cout << "\n================  AREA 2  =======================\n";

            std::cout << "\nID             : " << id << "\n";

            std::cout << "\nCAPA FISICA\n";
            std::cout << "Tamano paquete : " << len << " bytes\n";


            std::cout << "\nCAPA DE ENLACE\n";
            std::cout << "Tipo de enlace : " << link_type << "\n";
            if(link_type == "Ethernet") {
                std::cout << "MAC Fuente     : " << mac_src << "\n";
                std::cout << "MAC Destino    : " << mac_dst << "\n";
            }

            
            std::cout << "\nCAPA DE RED\n";
            std::cout << "Identificador  : " << ip_id << "\n";
            std::cout << "IP Fuente      : " << src_ip << "\n";
            std::cout << "IP Destino     : " << dst_ip << "\n";
            std::cout << "TTL            : " << ttl << "\n";
            std::cout << "TOS            : 0x" << std::hex << tos << std::dec << "\n";

            
            std::cout << "\nCAPA DE TRANSPORTE\n";
            std::cout << "Protocolo      : " << protocol << "\n";
            if (src_port != -1 && dst_port != -1) {
            std::cout << "Puerto Fuente  : " << src_port << "\n";
            std::cout << "Puerto Destino : " << dst_port << "\n";
            } else {
            std::cout << "Puerto Fuente  : N/C\n";
            std::cout << "Puerto Destino : N/C\n";
            }
            if (!flags.empty()) {
                std::cout << "Flags      : " << flags << "\n";
            }
            
            std::cout << "\nCAPA DE APLICACION\n";
            if (icmp_type != -1 && icmp_code != -1) {
                std::cout << "Tipo ICMP  : " << icmp_type << "\n";
                std::cout << "ICMP code  : " << icmp_code << "\n";
            } else {
                std::cout << "Tipo ICMP  : N/C\n";
                std::cout << "ICMP Code  : N/C\n";
            }
        }

        // Mostrar el Data Raw
        void mostrarDataRaw() {
            std::cout << "\n============  AREA 3  ================\n";

            if (rawData.empty()) {
                std::cout << "Error al Capturar el Raw Data.\n";
                return;
            }

            const int bytesLine = 16;

            for (int i = 0; i < rawData.size(); i++) {

                // offset
                if (i % bytesLine == 0) {
                    std::cout << "\n" << std::setw(4) << std::setfill('0') << std::hex << i << "  ";
                }

                std::cout << std::setw(2) << std::setfill('0') << std::hex << (int)rawData[i] << " ";

                if (i % bytesLine == 7) {
                    std::cout << " ";
                }
            }

            std::cout << std::dec;
        }

        // Setters
        void setId(int id) { this->id = id; }
        void setIP_ID(int ip_id) { this->ip_id = ip_id; }
        void setLinkType(const std::string& link_type) { this->link_type = link_type; }
        void setMacSrc(const std::string& mac_src) { this->mac_src = mac_src; }
        void setMacDst(const std::string& mac_dst) { this->mac_dst = mac_dst; }
        void setSrcIp(const std::string& src_ip) { this->src_ip = src_ip; }
        void setDstIp(const std::string& dst_ip) { this->dst_ip = dst_ip; }
        void setTos(int tos) { this->tos = tos; }
        void setTtl(int ttl) { this->ttl = ttl; }
        void setLen(int len) { this->len = len; }
        void setProtocol(const std::string& protocol) { this->protocol = protocol; }
        void setSrcPort(int src_port) { this->src_port = src_port; }
        void setDstPort(int dst_port) { this->dst_port = dst_port; }
        void setIcmpType(int icmp_type) { this->icmp_type = icmp_type; }
        void setIcmpCode(int icmp_code) { this->icmp_code = icmp_code; }
        void setFlags(const std::string& flags) { this->flags = flags; }
        void setRawData(const std::vector<unsigned char>& rawData) { this->rawData = rawData; }
        
        // Getters
        int getId() { return id; }
        int getIP_ID() { return ip_id; }
        std::string getLinkType() { return link_type; }
        std::string getMacSrc() { return mac_src; }
        std::string getMacDst() { return mac_dst; }
        std::string getSrcIp() { return src_ip; }
        std::string getDstIp() { return dst_ip; }
        int getTos() { return tos; }
        int getTtl() { return ttl; }
        int getLen() { return len; }
        std::string getProtocol() { return protocol; }
        int getSrcPort() { return src_port; }
        int getDstPort() { return dst_port; }
        int getIcmpType() { return icmp_type; }
        int getIcmpCode() { return icmp_code; }
        std::string& getFlags() { return flags; }
        std::vector<unsigned char>& getRawData() { return rawData; }
};
