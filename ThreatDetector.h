#ifndef THREATDETECTOR_H
#define THREATDETECTOR_H

#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include <chrono>
#include <ctime>
#include <functional>

#include "Packet.h"

//  Umbrales
constexpr int    THRESH_PKT_PER_IP  = 10;  // paquetes de la misma IP en la ventana
constexpr int    THRESH_PORT_SCAN   = 3;   // puertos distintos desde una sola IP
constexpr int    THRESH_ICMP        = 5;  // paquetes ICMP totales en la ventana
constexpr int    THRESH_SYN_FLOOD   = 5;   // SYN sin ACK desde una sola IP
constexpr double WINDOW_SECONDS     = 30.0; // duración de la ventana deslizante


//  Estructura de alerta
struct Alert {
    enum class Level { INFO, WARNING, CRITICAL };

    Level       level    = Level::INFO;
    std::string message;
    std::string timestamp = "";

};


//  ThreatDetector
class ThreatDetector {
public:
    std::function<void(const Alert&)> onAlert;   // callback → MainWindow

    // Analiza un paquete y dispara alertas si corresponde
    void analyze(const Packet& pkt) {

        // Rotar ventana si pasaron WINDOW_SECONDS
        auto now = std::chrono::steady_clock::now();
        if (std::chrono::duration<double>(now - windowStart).count() >= WINDOW_SECONDS) {
            resetCounters();
            windowStart = now;
        }

        const std::string& src   = pkt.getSrcIp();
        const std::string& proto = pkt.getProtocol();
        int                port  = pkt.getDstPort();

        // IP genera demasiados paquetes
        if (++ipCount[src] == THRESH_PKT_PER_IP) {
            fire({ Alert::Level::CRITICAL,
                   "IP " + src + " genero " + std::to_string(THRESH_PKT_PER_IP) +
                   " paquetes en " + std::to_string((int)WINDOW_SECONDS) + " segundos" });
        }

        // Escaneo de puertos
        if (port > 0) {
            ipPorts[src].insert(port);
            if ((int)ipPorts[src].size() == THRESH_PORT_SCAN) {
                fire({ Alert::Level::CRITICAL,
                       "Posible escaneo de puertos desde " + src +
                       " (" + std::to_string(ipPorts[src].size()) + " puertos distintos)" });
            }
        }

        // Trafico ICMP elevado
        if (proto == "ICMP" && ++icmpCount == THRESH_ICMP) {
            fire({ Alert::Level::WARNING,
                   "Trafico ICMP elevado: " + std::to_string(THRESH_ICMP) +
                   " paquetes ICMP en " + std::to_string((int)WINDOW_SECONDS) + " segundos" });
        }

        // SYN Flood
        if (proto == "TCP") {
            const std::string& flags = pkt.getFlags();
            // Flags guardados como "SAFRU", posicion 0=SYN, 1=ACK
            bool syn = flags.size() > 0 && flags[0] == 'S';
            bool ack = flags.size() > 1 && flags[1] == 'A';
            if (syn && !ack && ++synCount[src] == THRESH_SYN_FLOOD) {
                fire({ Alert::Level::CRITICAL,
                       "Posible SYN Flood desde " + src +
                       " (" + std::to_string(THRESH_SYN_FLOOD) + " SYN sin ACK)" });
            }
        }
    }

    // Llama esto al iniciar una nueva captura
    void reset() {
        resetCounters();
        windowStart = std::chrono::steady_clock::now();
    }

private:
    // Contadores de la ventana actual
    std::unordered_map<std::string, int>                      ipCount;
    std::unordered_map<std::string, std::unordered_set<int>>  ipPorts;
    std::unordered_map<std::string, int>                      synCount;
    int icmpCount = 0;

    std::chrono::steady_clock::time_point windowStart { std::chrono::steady_clock::now() };

    void resetCounters() {
        ipCount.clear();
        ipPorts.clear();
        synCount.clear();
        icmpCount = 0;
    }

    // Estampa la hora y dispara el callback
    void fire(Alert a) {
        std::time_t t = std::time(nullptr);
        char buf[9];
        std::strftime(buf, sizeof(buf), "%H:%M:%S", std::localtime(&t));
        a.timestamp = buf;
        if (onAlert) onAlert(a);
    }
};

#endif
