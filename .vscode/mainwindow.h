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
#include <QListWidget>

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

    Sniffer*       sniffer  = nullptr;
    ThreatDetector detector;

    // Main table
    QTableWidget* table;

    // Lower panels
    QTextEdit*   details;   // Analysis by OSI layers
    QTextEdit*   raw;       // Hexadecimal viewer

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

    // Visual filters
    QLineEdit* filterSrcIp;
    QLineEdit* filterDstIp;
    QLineEdit* filterSrcPort;
    QLineEdit* filterDstPort;
    QComboBox* filterProtocol;

    // Filter BPF
    QLineEdit* filterBPF;

    // Data
    std::vector<Packet> packetList;
    std::vector<Packet> displayedList;

    // Status bar
    QLabel* statusLabel;

    // Auxiliary methods
    void applyFilters();
    void updateTable();
    void exportToCSV();
    void updateStatusBar();
    void colorRow(int row, const std::string& protocol);
    void appendRow(const Packet& pkt);
    void addAlert(const Alert& alert);
};

#endif
