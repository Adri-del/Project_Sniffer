
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidget>
#include <QTableWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QStatusBar>

#include "Sniffer.h"
#include "Packet.h"
#include "ThreatDetector.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:
    Sniffer* sniffer = nullptr;
    ThreatDetector detector;
    bool importado = false;

    // Tabla principal
    QTableWidget* table;

    // Paneles inferiores
    QTextEdit* details;   // Analisis por capas OSI
    QTextEdit* raw;       // Visor hexadecimal
    
    QListWidget* alertList;       // list of alerts
    QLabel*      alertBadge;      // red counter in the tab
    QPushButton* btnClearAlerts;  // clear alerts
    int          alertCount = 0;

    // Buttons
    QPushButton* btnStart;
    QPushButton* btnStop;
    QPushButton* btnClearFilters;
    QPushButton* btnExportCSV;
    QPushButton* btnClearCapture;

    // Filtros visuales
    QLineEdit* filterSrcIp;
    QLineEdit* filterDstIp;
    QLineEdit* filterSrcPort;
    QLineEdit* filterDstPort;
    QComboBox* filterProtocol;

    // Filtro BPF
    QLineEdit* filterBPF;

    // Datos
    std::vector<Packet> packetList;    // Todos los paquetes capturados
    std::vector<Packet> displayedList; // Los que pasan el filtro visual

    // Status bar
    QLabel* statusLabel;

    // Metodos auxiliares
    void applyFilters();
    void updateTable();
    void exportToCSV();
    void importFromCSV();
    void updateStatusBar();
    void colorRow(int row, const std::string& protocol);
    void appendRow(const Packet& pkt);
    void addAlert(const Alert& alert);
};

#endif