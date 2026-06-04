#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QTableWidget>
#include <QTextEdit>
#include <QPushButton>
#include <QLineEdit>
#include <QComboBox>
#include <QLabel>
#include <QListWidget>
#include <vector>

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

    // Packet capture engine
    Sniffer* sniffer = nullptr;

    // Threat detection module
    ThreatDetector detector;

    // Main packet table
    QTableWidget* table;

    // Bottom panels
    QTextEdit* details;   // OSI layer analysis
    QTextEdit* raw;       // Hexadecimal viewer

    // Alert panel
    QListWidget* alertList;      // Alert list
    QLabel*      alertBadge;     // Alert counter badge
    QPushButton* btnClearAlerts; // Clear alerts button
    int          alertCount = 0;

    // Control buttons
    QPushButton* btnStart;
    QPushButton* btnStop;
    QPushButton* btnClearFilters;
    QPushButton* btnExportCSV;
    QPushButton* btnClearCapture;

    // Display filters
    QLineEdit* filterSrcIp;
    QLineEdit* filterDstIp;
    QLineEdit* filterSrcPort;
    QLineEdit* filterDstPort;
    QComboBox* filterProtocol;

    // BPF capture filter
    QLineEdit* filterBPF;

    // Captured packet storage
    std::vector<Packet> packetList;
    std::vector<Packet> displayedList;

    // Status bar label
    QLabel* statusLabel;

    // Helper methods
    void applyFilters();
    void updateTable();
    void exportToCSV();
    void updateStatusBar();
    void colorRow(int row, const std::string& protocol);
    void appendRow(const Packet& pkt);
    void addAlert(const Alert& alert);
};

#endif
