
#include "mainwindow.h"

#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QGroupBox>
#include <QHeaderView>
#include <QFileDialog>
#include <QMessageBox>
#include <QApplication>
#include <QScrollBar>
#include <QStyle>
#include <QTimer>
#include <QStandardPaths>
#include <QTabWidget>
#include <QListWidgetItem>

#include <thread>
#include <fstream>

//  Constructor
MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle("Packet Sniffer — Equipo 5");
    resize(1500, 900);

    //Prueba del tamaño de la estructura
    #include <iostream>
    std::cout << "--- PRUEBA DE NETWORKS ---" << std::endl;
    std::cout << "Tamano de iphdr: " << sizeof(iphdr) << " bytes" << std::endl;
    std::cout << "--------------------------" << std::endl;

    setStyleSheet(R"(
        QMainWindow          { background-color: #1e1e1e; color: #ffffff; }
        QLabel               { color: #e0e0e0; }
        QGroupBox {
            font-weight: bold;
            color: #cccccc;
            border: 1px solid #555;
            border-radius: 8px;
            margin-top: 10px;
            padding: 6px;
        }
        QGroupBox::title     { subcontrol-origin: margin; left: 10px; }
        QLineEdit, QComboBox {
            background-color: #2e2e2e;
            color: #eeeeee;
            border: 1px solid #555;
            border-radius: 4px;
            padding: 3px 6px;
        }
        QTableWidget {
            background-color: #2a2a2a;
            alternate-background-color: #252525;
            gridline-color: #444;
            color: #eeeeee;
            font-size: 12px;
        }
        QHeaderView::section {
            background-color: #333;
            color: #ccc;
            border: 1px solid #555;
            padding: 4px;
            font-weight: bold;
        }
        QTableWidget::item:selected { background-color: #3a5a8a; }
        QTextEdit {
            background-color: #1e1e1e;
            color: #d0d0d0;
            font-family: Consolas, 'Courier New', monospace;
            font-size: 12px;
            border: 1px solid #444;
        }
        QScrollBar:vertical   { background: #2a2a2a; width: 10px; }
        QScrollBar::handle:vertical { background: #555; border-radius: 4px; }
        QStatusBar            { background-color: #252525; color: #aaa; }
    )");

    QWidget*     central    = new QWidget;
    QVBoxLayout* mainLayout = new QVBoxLayout(central);
    mainLayout->setSpacing(8);
    mainLayout->setContentsMargins(10, 10, 10, 6);

    // Filtros visuales
    QGroupBox*   fgVisual = new QGroupBox("Filtros de captura");
    QHBoxLayout* flVisual = new QHBoxLayout(fgVisual);

    filterSrcIp   = new QLineEdit; filterSrcIp->setPlaceholderText("IP Origen");
    filterDstIp   = new QLineEdit; filterDstIp->setPlaceholderText("IP Destino");
    filterSrcPort = new QLineEdit; filterSrcPort->setPlaceholderText("Puerto Origen");
    filterDstPort = new QLineEdit; filterDstPort->setPlaceholderText("Puerto Destino");

    filterProtocol = new QComboBox;
    filterProtocol->addItems({"Todos", "TCP", "UDP", "ICMP"});

    btnClearFilters  = new QPushButton("Limpiar filtros");
    btnClearCapture  = new QPushButton("Limpiar captura");

    flVisual->addWidget(new QLabel("Src IP:"));   flVisual->addWidget(filterSrcIp);
    flVisual->addWidget(new QLabel("Dst IP:"));   flVisual->addWidget(filterDstIp);
    flVisual->addWidget(new QLabel("Src Port:")); flVisual->addWidget(filterSrcPort);
    flVisual->addWidget(new QLabel("Dst Port:")); flVisual->addWidget(filterDstPort);
    flVisual->addWidget(new QLabel("Protocolo:")); flVisual->addWidget(filterProtocol);

    flVisual->addSpacing(12);
    flVisual->addWidget(btnClearFilters);
    flVisual->addWidget(btnClearCapture);

    QGroupBox*   fgCapture = new QGroupBox("Captura");
    QHBoxLayout* flCapture = new QHBoxLayout(fgCapture);

    filterBPF = new QLineEdit;
    filterBPF->setPlaceholderText("Filtro BPF opcional  (ej: tcp and port 80");
    filterBPF->setMinimumWidth(350);

    btnStart     = new QPushButton("INICIAR CAPTURA");
    btnStart->setIcon(style()->standardIcon(QStyle::SP_MediaPlay));
    btnStop      = new QPushButton("DETENER CAPTURA");
    btnStop->setIcon(style()->standardIcon(QStyle::SP_MediaStop));
    btnExportCSV = new QPushButton("Exportar CSV");
    btnExportCSV->setIcon(style()->standardIcon(QStyle::SP_DialogSaveButton));

    btnStart->setStyleSheet(
        "background-color:#00933b; color:white; font-size:14px;"
        "font-weight:bold; padding:10px 20px; border-radius:6px;");
    btnStop->setStyleSheet(
        "background-color:#7D6C69; color:white; font-size:14px;"
        "font-weight:bold; padding:10px 20px; border-radius:6px;");
    btnExportCSV->setStyleSheet(
        "background-color:#1d6fa4; color:white; font-size:14px;"
        "font-weight:bold; padding:10px 20px; border-radius:6px;");

    btnStop->setEnabled(false);

    flCapture->addWidget(new QLabel("Filtro BPF:"));

    flCapture->addWidget(filterBPF, 1);
    flCapture->addSpacing(12);
    flCapture->addWidget(btnStart);
    flCapture->addWidget(btnStop);
    flCapture->addWidget(btnExportCSV);

    // Tabla de paquetes
    table = new QTableWidget;
    table->setColumnCount(7);
    table->setHorizontalHeaderLabels(
        {"ID", "SRC IP", "DST IP", "SRC PORT", "DST PORT", "PROTOCOLO", "FLAGS"});

    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setAlternatingRowColors(true);
    table->verticalHeader()->setVisible(false);
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);

    table->setColumnWidth(0, 70);   // ID
    table->setColumnWidth(1, 260);  // SRC IP
    table->setColumnWidth(2, 260);  // DST IP
    table->setColumnWidth(3, 260);   // SRC PORT
    table->setColumnWidth(4, 260);   // DST PORT
    table->setColumnWidth(5, 260);   // PROTOCOLO

    // Panel inferior
    details = new QTextEdit;
    details->setPlaceholderText("Haz clic en un paquete para ver el análisis por capas OSI...");
    details->setReadOnly(true);

    raw = new QTextEdit;
    raw->setPlaceholderText("Visor hexadecimal del frame...");
    raw->setReadOnly(true);
    raw->setFont(QFont("Consolas", 11));

    // Alert Panel
    QWidget*     alertPanel  = new QWidget;
    QVBoxLayout* alertLayout = new QVBoxLayout(alertPanel);
    alertLayout->setContentsMargins(0, 0, 0, 0);
    alertLayout->setSpacing(4);

    // Panel Header
    QHBoxLayout* alertHeader = new QHBoxLayout;

    QLabel* alertTitle = new QLabel("SECURITY ALERTS");
    alertTitle->setStyleSheet("color:#ff6b6b; font-weight:bold; font-size:13px;");

    alertBadge = new QLabel("0");
    alertBadge->setAlignment(Qt::AlignCenter);
    alertBadge->setMinimumSize(26, 26);
    alertBadge->setStyleSheet(
        "background-color:#c42b1c; color:white; font-weight:bold;"
        "border-radius:13px; padding: 0 6px;");

    btnClearAlerts = new QPushButton("Clear alerts");
    btnClearAlerts->setStyleSheet(
        "background-color:#444; color:#ccc; padding:4px 12px;"
        "border-radius:4px; font-size:11px;");

    alertHeader->addWidget(alertTitle);
    alertHeader->addWidget(alertBadge);
    alertHeader->addStretch();
    alertHeader->addWidget(btnClearAlerts);

    alertList = new QListWidget;
    alertList->setWordWrap(true);
    alertList->setSpacing(1);

    alertLayout->addLayout(alertHeader);
    alertLayout->addWidget(alertList);

    QTabWidget* tabs = new QTabWidget;
    tabs->addTab(details,    "Detalles");
    tabs->addTab(raw,        "Datos Brutos (Hex)");
    tabs->addTab(alertPanel, "Alertas");

    // Splitter principal
    QSplitter* mainSplitter = new QSplitter(Qt::Vertical);
    mainSplitter->addWidget(table);
    mainSplitter->addWidget(tabs);
    mainSplitter->setStretchFactor(0, 3);
    mainSplitter->setStretchFactor(1, 2);

    // Ensamblar layout principal
    mainLayout->addWidget(fgVisual);
    mainLayout->addWidget(fgCapture);
    mainLayout->addWidget(mainSplitter, 1);
    setCentralWidget(central);

    // Status bar
    statusLabel = new QLabel("Listo  •  Paquetes: 0 •  Alertas: 0");
    statusBar()->addWidget(statusLabel);

    QMessageBox::StandardButton importar;

    importar = QMessageBox::question(
        nullptr,
        "Importar captura",
        "¿Desea importar un archivo CSV?",
        QMessageBox::Yes | QMessageBox::No
        );

    importado = importar == QMessageBox::Yes;

    //  Inicializar Sniffer
    if(!importado) {
        try {
            sniffer = new Sniffer();
            statusLabel->setText(
                QString("Interfaz: %1  •  Paquetes: 0  •  Alerts: 0")
                    .arg(QString::fromStdString(sniffer->getDevice())));
        } catch (const std::exception& e) {
            QMessageBox::critical(
                this, "Error al inicializar el Sniffer",
                QString("No se pudo abrir la interfaz de red:\n\n%1\n\n"
                        "Verifica que Npcap está instalado o que se haya seleccionado una interfaz válida").arg(e.what()));
            btnStart->setEnabled(false);
            QTimer::singleShot(0, this, &QWidget::close);
        }

        detector.onAlert = [this](const Alert& alert) {
            QMetaObject::invokeMethod(this, [this, alert]() {
                addAlert(alert);
            });
        };

        //  Conexión del callback: Sniffer → MainWindow
        if (sniffer) {
            sniffer->onPacketCaptured = [this](const Packet& pkt) {
                // pcap_dispatch corre en un hilo secundario
                // QMetaObject::invokeMethod garantiza que la UI se actualiza
                // siempre desde el hilo principal de Qt.
                QMetaObject::invokeMethod(this, [this, pkt]() {
                    packetList.push_back(pkt);
                    
                    detector.analyze(pkt);

                    // Filtro visual: si pasa, añadirlo directamente a la tabla
                    std::string fSrcIp   = filterSrcIp->text().toStdString();
                    std::string fDstIp   = filterDstIp->text().toStdString();
                    std::string fSrcPort = filterSrcPort->text().toStdString();
                    std::string fDstPort = filterDstPort->text().toStdString();
                    std::string fProto   = filterProtocol->currentText().toStdString();

                    bool match = true;
                    if (!fSrcIp.empty()   && pkt.getSrcIp().find(fSrcIp) == std::string::npos) match = false;
                    if (!fDstIp.empty()   && pkt.getDstIp().find(fDstIp) == std::string::npos) match = false;
                    if (!fSrcPort.empty() && std::to_string(pkt.getSrcPort()) != fSrcPort)      match = false;
                    if (!fDstPort.empty() && std::to_string(pkt.getDstPort()) != fDstPort)      match = false;
                    if (fProto != "Todos" && pkt.getProtocol() != fProto)                       match = false;

                    if (match) {
                        displayedList.push_back(pkt);
                        appendRow(pkt);
                        table->scrollToBottom();
                    }

                    updateStatusBar();
                });
            };
        }

    } else {
        importFromCSV();
        btnStart->setEnabled(false);
        btnStart->setStyleSheet(
            "background-color:#7D6C69; color:white; font-size:14px;"
            "font-weight:bold; padding:10px 20px; border-radius:6px;");
        btnStop->setEnabled(false);
        btnStop->setStyleSheet(
            "background-color:#7D6C69; color:white; font-size:14px;"
            "font-weight:bold; padding:10px 20px; border-radius:6px;");
        btnClearCapture->setEnabled(false);
        btnExportCSV->setEnabled(false);
        btnExportCSV->setStyleSheet(
            "background-color:#7D6C69; color:white; font-size:14px;"
            "font-weight:bold; padding:10px 20px; border-radius:6px;");
    }

    // Boton INICIAR
    connect(btnStart, &QPushButton::clicked, this, [this]() {
        if (!sniffer) return;
        std::string bpf = filterBPF->text().trimmed().toStdString();
        btnStart->setEnabled(false);
        btnStart->setStyleSheet(
            "background-color:#7D6C69; color:white; font-size:14px;"
            "font-weight:bold; padding:10px 20px; border-radius:6px;");
        btnStop->setEnabled(true);
        btnStop->setStyleSheet( "background-color:#C72B0A; color:white; font-size:14px;"
        "font-weight:bold; padding:10px 20px; border-radius:6px;");
        filterBPF->setEnabled(false);
        statusLabel->setText("Capturando…");
        std::thread([this, bpf]() { sniffer->capturar(bpf); }).detach();
    });

    // Boton DETENER
    connect(btnStop, &QPushButton::clicked, this, [this]() {
        if (!sniffer) return;
        sniffer->detener();
        btnStop->setEnabled(false);
        btnStop->setStyleSheet(
            "background-color:#7D6C69; color:white; font-size:14px;"
            "font-weight:bold; padding:10px 20px; border-radius:6px;");
        btnStart->setEnabled(true);
        btnStart->setStyleSheet("background-color:#00933b; color:white; font-size:14px;"
        "font-weight:bold; padding:10px 20px; border-radius:6px;");
        filterBPF->setEnabled(true);
        updateStatusBar();
    });

    // Boton LIMPIAR CAPTURA
    connect(btnClearCapture, &QPushButton::clicked, this, [this]() {
        packetList.clear();
        displayedList.clear();
        table->setRowCount(0);
        details->clear();
        raw->clear();
        detector.reset();
        updateStatusBar();
    });

    // BUTTON CLEAR FILTERS
    connect(btnClearFilters, &QPushButton::clicked, this, [this]() {
        filterSrcIp->clear();
        filterDstIp->clear();
        filterSrcPort->clear();
        filterDstPort->clear();
        filterProtocol->setCurrentIndex(0);
    });

    // Button EXPORT CSV
    connect(btnExportCSV, &QPushButton::clicked, this, &MainWindow::exportToCSV);

    // Button CLEAR ALERTS
    connect(btnClearAlerts, &QPushButton::clicked, this, [this]() {
        alertList->clear();
        alertCount = 0;
        alertBadge->setText("0");
        updateStatusBar();
    });

    auto applySlot = [this]() { applyFilters(); };
    connect(filterSrcIp,    &QLineEdit::textChanged,          this, applySlot);
    connect(filterDstIp,    &QLineEdit::textChanged,          this, applySlot);
    connect(filterSrcPort,  &QLineEdit::textChanged,          this, applySlot);
    connect(filterDstPort,  &QLineEdit::textChanged,          this, applySlot);
    connect(filterProtocol, &QComboBox::currentTextChanged,   this, applySlot);

    // Click en fila → panel detalles OSI + visor Raw
    connect(table, &QTableWidget::cellClicked, this, [this](int row, int) {
        if (row < 0 || row >= static_cast<int>(displayedList.size())) return;
        const Packet& pkt = displayedList[row];

        // Panel detalles (capas OSI)
        QString info;
        info += "-------- ANALISIS POR CAPAS OSI -----------\n\n";

        info += "---------CAPA 3 — NETWORK (IP) --------------\n";
        info += QString("  ID del Paquete  : %1\n").arg(pkt.getId());
        info += QString("  IP Origen       : %1\n").arg(QString::fromStdString(pkt.getSrcIp()));
        info += QString("  IP Destino      : %1\n").arg(QString::fromStdString(pkt.getDstIp()));
        info += QString("  TTL             : %1\n").arg(pkt.getTtl());
        info += QString("  TOS             : 0x%1\n").arg(pkt.getTos(), 2, 16, QChar('0')).toUpper();
        info += QString("  Longitud Total  : %1 bytes\n\n").arg(pkt.getLen());

        info += "-------- CAPA 4 — TRANSPORT -----------------\n";
        info += QString("  Protocolo       : %1\n").arg(QString::fromStdString(pkt.getProtocol()));

        if (pkt.getSrcPort() != -1) {
            info += QString("  Puerto Origen   : %1\n").arg(pkt.getSrcPort());
            info += QString("  Puerto Destino  : %1\n").arg(pkt.getDstPort());
        }
        if (!pkt.getFlags().empty()) {
            info += QString("  Flags TCP       : %1\n").arg(QString::fromStdString(pkt.getFlags()));
            info += "  (S=SYN A=ACK F=FIN R=RST U=URG  '-'=inactivo)\n";
        }
        if (pkt.getIcmpType() != -1) {
            info += QString("  ICMP Type       : %1\n").arg(pkt.getIcmpType());
            info += QString("  ICMP Code       : %1\n").arg(pkt.getIcmpCode());
        }

        details->setText(info);

        // Visor hexadecimal
        const auto& data = pkt.getRawData();
        if (data.empty()) {
            raw->setPlainText("(no hay datos raw disponibles)");

        // Hexadecimal viewer
        const auto& data = pkt.getRawData();
        if (data.empty()) {
            raw->setPlainText("(no raw data available)");
            return;
        }

        QString hex;
        hex.reserve(static_cast<int>(data.size()) * 4);

        for (size_t i = 0; i < data.size(); i += 16) {
            // Offset
            hex += QString("%1  ").arg(static_cast<uint>(i), 4, 16, QChar('0')).toUpper();

            // Bytes en hex (16 por línea)
            hex += QString("%1  ").arg(static_cast<uint>(i), 4, 16, QChar('0')).toUpper();

            for (size_t j = 0; j < 16; ++j) {
                if (i + j < data.size())
                    hex += QString("%1 ").arg(data[i + j], 2, 16, QChar('0')).toUpper();
                else
                    hex += "   ";
                if (j == 7) hex += " "; // separador central
                if (j == 7) hex += " ";
            }

            hex += "  ";

            // Representación ASCII
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < data.size()) {
                    unsigned char c = data[i + j];
                    hex += (c >= 32 && c <= 126) ? QChar(c) : QChar('.');
                }
            }
            hex += "\n";
        }

        raw->setPlainText(hex);
    });
}

//  Destructor
MainWindow::~MainWindow()
{
    if (sniffer) {
        sniffer->detener();
        delete sniffer;
    }
}

//add an alert to the panel
void MainWindow::addAlert(const Alert& alert)
{
    alertCount++;
    alertBadge->setText(QString::number(alertCount));

    QString text = QString("[%1]  %2  %3")
                       .arg(QString::fromStdString(alert.timestamp))
                       //.arg(QString::fromStdString(alert.icon()))
                       .arg(QString::fromStdString(alert.message));

    QListWidgetItem* item = new QListWidgetItem(text, alertList);
    item->setFont(QFont("Consols", 12));

    switch (alert.level) {
    case Alert::Level::CRITICAL:
        item->setForeground(QColor("#ff6b6b"));
        item->setBackground(QColor("#2a1515"));
        break;
    case Alert::Level::WARNING:
        item->setForeground(QColor("#ffd166"));
        item->setBackground(QColor("#2a2010"));
        break;
    case Alert::Level::INFO:
        item->setForeground(QColor("#6bcfff"));
        item->setBackground(QColor("#102030"));
        break;
    }

    alertList->scrollToBottom();
    updateStatusBar();
}

void MainWindow::applyFilters()
{
    std::string fSrcIp   = filterSrcIp->text().toStdString();
    std::string fDstIp   = filterDstIp->text().toStdString();
    std::string fSrcPort = filterSrcPort->text().toStdString();
    std::string fDstPort = filterDstPort->text().toStdString();
    std::string fProto   = filterProtocol->currentText().toStdString();

    displayedList.clear();
    table->setRowCount(0);

    for (const auto& pkt : packetList) {
        bool match = true;
        if (!fSrcIp.empty()   && pkt.getSrcIp().find(fSrcIp) == std::string::npos) match = false;
        if (!fDstIp.empty()   && pkt.getDstIp().find(fDstIp) == std::string::npos) match = false;
        if (!fSrcPort.empty() && std::to_string(pkt.getSrcPort()) != fSrcPort)      match = false;
        if (!fDstPort.empty() && std::to_string(pkt.getDstPort()) != fDstPort)      match = false;

        if (fProto != "Todos" && pkt.getProtocol() != fProto)                         match = false;

        if (match) {
            displayedList.push_back(pkt);
            appendRow(pkt);
        }
    }
    updateTable();
    updateStatusBar();
}

void MainWindow::appendRow(const Packet& pkt)
{
    int row = table->rowCount();
    table->insertRow(row);

    auto item = [](const QString& text) {
        QTableWidgetItem* it = new QTableWidgetItem(text);
        it->setTextAlignment(Qt::AlignCenter);
        return it;
    };

    table->setItem(row, 0, item(QString::number(pkt.getId())));
    table->setItem(row, 1, item(QString::fromStdString(pkt.getSrcIp())));
    table->setItem(row, 2, item(QString::fromStdString(pkt.getDstIp())));
    table->setItem(row, 3, item(pkt.getSrcPort() != -1 ? QString::number(pkt.getSrcPort()) : "-"));
    table->setItem(row, 4, item(pkt.getDstPort() != -1 ? QString::number(pkt.getDstPort()) : "-"));
    table->setItem(row, 5, item(QString::fromStdString(pkt.getProtocol())));
    table->setItem(row, 6, item(QString::fromStdString(pkt.getFlags())));

    colorRow(row, pkt.getProtocol());
}

void MainWindow::updateTable()
{
    table->setRowCount(0);
    for (const auto& pkt : displayedList)
        appendRow(pkt);
}

//  exportToCSV
void MainWindow::exportToCSV() {
    if (packetList.empty()) {
        QMessageBox::information(this, "Sin datos", "No hay paquetes capturados para exportar.");
        return;
    } 

    QString docs = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);
    QString fileName = QFileDialog::getSaveFileName(this, "Guardar captura", docs + "/captura_paquetes.csv", "CSV (*.csv)");

    if (fileName.isEmpty()) return;

    std::ofstream outfile(fileName.toStdString());
    if (!outfile.is_open()) {
        QMessageBox::warning(this, "Error", "No se pudo crear el archivo.");
        return;
    }

    outfile << "ID,SRC_IP,DST_IP,TOS,TTL,LEN,PROTOCOL,"
               "SRC_PORT,DST_PORT,ICMP_TYPE,ICMP_CODE,FLAGS\n";

    for (const auto& pkt : packetList)
        pkt.guardarPaquete(outfile);

    QMessageBox::information(  this, "Exportación exitosa", QString("Se exportaron %1 paquetes a:\n%2").arg(packetList.size()).arg(fileName));
}

// import CSV
void MainWindow::importFromCSV() {
    QString docs = QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation);

    QString ruta = QFileDialog::getOpenFileName(this, "Importar captura", docs, "CSV (*.csv)");

    if (ruta.isEmpty()){
        QMessageBox::critical(
            this, "Error",
            QString("No se pudo importar la captura.\nVerifique que el archivo tenga la extension correcta."));
        QTimer::singleShot(0, this, &QWidget::close);
        return;
    }

    std::ifstream archivo(ruta.toStdString());

    if (!archivo.is_open()) {
        QMessageBox::critical(
            this,
            "Error",
            "No se pudo abrir el archivo."
            );
        return;
    }

    std::string linea;
    std::getline(archivo, linea);

    packetList.clear();
    while(std::getline(archivo, linea)) {
        Packet pkt(linea);
        packetList.push_back(pkt);
        displayedList.push_back(pkt);
    }
    updateTable();

}

//  updateStatusBar
void MainWindow::updateStatusBar()
{
    statusLabel->setText(QString("Total capturados: %1  •  Mostrando: %2").arg(packetList.size()).arg(displayedList.size()));
}

void MainWindow::colorRow(int row, const std::string& protocol)
{
    QColor color;
    if      (protocol == "TCP")  color = QColor(80,  170, 255);
    else if (protocol == "UDP")  color = QColor(80,  220,  80);
    else if (protocol == "ICMP") color = QColor(255, 170,  50);
    else                         color = QColor(180, 180, 180);

    for (int col = 0; col < table->columnCount(); ++col)
        if (QTableWidgetItem* it = table->item(row, col))
            it->setForeground(color);
}
