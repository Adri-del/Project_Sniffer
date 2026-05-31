#include <string>
#include <vector>
#include <fstream>
#include <iostream>

// Clase que representa un paquete de red capturado
// Almacena el encabezado IP
// Almacena informacion especifica de cada protocolo (TCP, UDP o ICMP)
// Almacena el contenidobruto del paquete 
class Packet {
    private:
        // Informacion general del paquete IP
        int id;

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
            outfile << id << ","
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
                    << flags << "\n";
        }

        // Muestra la informacion del paquete
        void mostrarPaquete() {
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

        // Setters
        void setId(int id) { this->id = id; }
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
