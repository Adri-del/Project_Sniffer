#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QStatusBar>

#include "Sniffer.h"
#include "Packet.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private:

    Sniffer* sniffer = nullptr;

    // Tabla principal
    QTableWidget* table;

    // Paneles inferiores
    QTextEdit* details;   // Analisis por capas OSI
    QTextEdit* raw;       // Visor hexadecimal

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
    void updateStatusBar();
    void colorRow(int row, const std::string& protocol);
    void appendRow(const Packet& pkt);
};

#endif