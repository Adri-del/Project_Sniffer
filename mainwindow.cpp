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

#include <thread>
#include <fstream>

//  Constructor
MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    setWindowTitle("Packet Sniffer — Redes I");
    resize(1500, 900);

    // Tema oscuro
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

    // Widget central
    QWidget*     central    = new QWidget;
    QVBoxLayout* mainLayout = new QVBoxLayout(central);
    mainLayout->setSpacing(8);
    mainLayout->setContentsMargins(10, 10, 10, 6);

    // Filtros visuales
    QGroupBox*   fgVisual = new QGroupBox("Filtros visuales (en tiempo real)");
    QHBoxLayout* flVisual = new QHBoxLayout(fgVisual);

    filterSrcIp   = new QLineEdit; filterSrcIp->setPlaceholderText("IP Origen");
    filterDstIp   = new QLineEdit; filterDstIp->setPlaceholderText("IP Destino");
    filterSrcPort = new QLineEdit; filterSrcPort->setPlaceholderText("Puerto Origen");
    filterDstPort = new QLineEdit; filterDstPort->setPlaceholderText("Puerto Destino");

    filterProtocol = new QComboBox;
    filterProtocol->addItems({"Todos", "TCP", "UDP", "ICMP", "OTHER"});

    btnClearFilters  = new QPushButton("✖ Limpiar filtros");
    btnClearCapture  = new QPushButton("🗑 Limpiar captura");

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
    filterBPF->setPlaceholderText("Filtro BPF opcional  (ej: tcp, udp, port 80, host 192.168.1.1)");
    filterBPF->setMinimumWidth(350);

    btnStart     = new QPushButton("▶  INICIAR CAPTURA");
    btnStop      = new QPushButton("⏹  DETENER CAPTURA");
    btnExportCSV = new QPushButton("💾  Exportar CSV");

    btnStart->setStyleSheet(
        "background-color:#00933b; color:white; font-size:14px;"
        "font-weight:bold; padding:10px 20px; border-radius:6px;");
    btnStop->setStyleSheet(
        "background-color:#c42b1c; color:white; font-size:14px;"
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
    // Anchos iniciales razonables
    table->setColumnWidth(0, 70);   // ID
    table->setColumnWidth(1, 140);  // SRC IP
    table->setColumnWidth(2, 140);  // DST IP
    table->setColumnWidth(3, 90);   // SRC PORT
    table->setColumnWidth(4, 90);   // DST PORT
    table->setColumnWidth(5, 90);   // PROTOCOLO

    // Panel inferior
    details = new QTextEdit;
    details->setPlaceholderText("Haz clic en un paquete para ver el análisis por capas OSI...");
    details->setReadOnly(true);

    raw = new QTextEdit;
    raw->setPlaceholderText("Visor hexadecimal del frame...");
    raw->setReadOnly(true);
    raw->setFont(QFont("Consolas", 11));

    QSplitter* bottomSplitter = new QSplitter(Qt::Horizontal);
    bottomSplitter->addWidget(details);
    bottomSplitter->addWidget(raw);
    bottomSplitter->setStretchFactor(0, 1);
    bottomSplitter->setStretchFactor(1, 1);

    QSplitter* mainSplitter = new QSplitter(Qt::Vertical);
    mainSplitter->addWidget(table);
    mainSplitter->addWidget(bottomSplitter);
    mainSplitter->setStretchFactor(0, 3);
    mainSplitter->setStretchFactor(1, 2);

    // Ensamblar layout principal
    mainLayout->addWidget(fgVisual);
    mainLayout->addWidget(fgCapture);
    mainLayout->addWidget(mainSplitter, 1);
    setCentralWidget(central);

    // Status bar
    statusLabel = new QLabel("Listo  •  Paquetes: 0");
    statusBar()->addWidget(statusLabel);

    //  Inicializar Sniffer
    try {
        sniffer = new Sniffer();
        statusLabel->setText(
            QString("Interfaz: %1  •  Paquetes: 0")
                .arg(QString::fromStdString(sniffer->getDevice())));
    } catch (const std::exception& e) {
        QMessageBox::critical(
            this, "Error al inicializar el Sniffer",
            QString("No se pudo abrir la interfaz de red:\n\n%1\n\n"
                    "Verifica que Npcap está instalado y ejecuta el programa"
                    " como Administrador.").arg(e.what()));
        btnStart->setEnabled(false);
    }

    //  Conexión del callback: Sniffer → MainWindow
    if (sniffer) {
        sniffer->onPacketCaptured = [this](const Packet& pkt) {
            // pcap_dispatch corre en un hilo secundario
            // QMetaObject::invokeMethod garantiza que la UI se actualiza
            // siempre desde el hilo principal de Qt.
            QMetaObject::invokeMethod(this, [this, pkt]() {
                packetList.push_back(pkt);

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

    //  Señales / Slots

    // Boton INICIAR
    connect(btnStart, &QPushButton::clicked, this, [this]() {
        if (!sniffer) return;
        std::string bpf = filterBPF->text().trimmed().toStdString();
        btnStart->setEnabled(false);
        btnStop->setEnabled(true);
        filterBPF->setEnabled(false);
        statusLabel->setText("Capturando…");
        std::thread([this, bpf]() { sniffer->capturar(bpf); }).detach();
    });

    // Boton DETENER
    connect(btnStop, &QPushButton::clicked, this, [this]() {
        if (!sniffer) return;
        sniffer->detener();
        btnStop->setEnabled(false);
        btnStart->setEnabled(true);
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
        updateStatusBar();
    });

    // Boton LIMPIAR FILTROS
    connect(btnClearFilters, &QPushButton::clicked, this, [this]() {
        filterSrcIp->clear();
        filterDstIp->clear();
        filterSrcPort->clear();
        filterDstPort->clear();
        filterProtocol->setCurrentIndex(0);
        //applyFilters() se dispara automáticamente por textChanged
    });

    // Boton EXPORTAR CSV
    connect(btnExportCSV, &QPushButton::clicked, this, &MainWindow::exportToCSV);

    // Filtros visuales
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
        info += "══════════ ANALISIS POR CAPAS OSI ══════════\n\n";

        info += "╔═ CAPA 3 — NETWORK (IP) ═══════════════════\n";
        info += QString("  ID del Paquete  : %1\n").arg(pkt.getId());
        info += QString("  IP Origen       : %1\n").arg(QString::fromStdString(pkt.getSrcIp()));
        info += QString("  IP Destino      : %1\n").arg(QString::fromStdString(pkt.getDstIp()));
        info += QString("  TTL             : %1\n").arg(pkt.getTtl());
        info += QString("  TOS             : 0x%1\n").arg(pkt.getTos(), 2, 16, QChar('0')).toUpper();
        info += QString("  Longitud Total  : %1 bytes\n\n").arg(pkt.getLen());

        info += "╔═ CAPA 4 — TRANSPORT ══════════════════════\n";
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
            return;
        }

        QString hex;
        hex.reserve(static_cast<int>(data.size()) * 4);

        for (size_t i = 0; i < data.size(); i += 16) {
            // Offset
            hex += QString("%1  ").arg(static_cast<uint>(i), 4, 16, QChar('0')).toUpper();

            // Bytes en hex (16 por línea)
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < data.size())
                    hex += QString("%1 ").arg(data[i + j], 2, 16, QChar('0')).toUpper();
                else
                    hex += "   ";
                if (j == 7) hex += " "; // separador central
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

//  applyFilters — re-construye displayedList y la tabla desde cero
//  Se usa cuando el usuario cambia algun filtro mientras ya hay paquetes
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
        if (fProto != "Todos" && pkt.getProtocol() != fProto)                       match = false;

        if (match) {
            displayedList.push_back(pkt);
            appendRow(pkt);
        }
    }

    updateStatusBar();
}

//  appendRow — inserta una sola fila al final de la tabla
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

//  updateTable — reconstruye la tabla desde displayedList (uso interno)
void MainWindow::updateTable()
{
    table->setRowCount(0);
    for (const auto& pkt : displayedList)
        appendRow(pkt);
}

//  exportToCSV
void MainWindow::exportToCSV()
{
    if (packetList.empty()) {
        QMessageBox::information(this, "Sin datos", "No hay paquetes capturados para exportar.");
        return;
    }

    QString fileName = QFileDialog::getSaveFileName(
        this, "Guardar captura", "captura_paquetes.csv", "CSV (*.csv)");
    if (fileName.isEmpty()) return;

    std::ofstream outfile(fileName.toStdString());
    if (!outfile.is_open()) {
        QMessageBox::warning(this, "Error", "No se pudo crear el archivo.");
        return;
    }

    outfile << "ID,SRC_IP,DST_IP,TOS,TTL,LEN,PROTOCOLO,"
               "PUERTO_ORIGEN,PUERTO_DESTINO,ICMP_TYPE,ICMP_CODE,FLAGS\n";
    for (const auto& pkt : packetList)
        pkt.guardarPaquete(outfile);

    QMessageBox::information(
        this, "Exportación exitosa",
        QString("Se exportaron %1 paquetes a:\n%2")
            .arg(packetList.size()).arg(fileName));
}

//  updateStatusBar
void MainWindow::updateStatusBar()
{
    statusLabel->setText(
        QString("Total capturados: %1  •  Mostrando: %2")
            .arg(packetList.size())
            .arg(displayedList.size()));
}

//  colorRow — color de texto según protocolo
void MainWindow::colorRow(int row, const std::string& protocol)
{
    QColor color;
    if      (protocol == "TCP")  color = QColor(80,  170, 255);  // azul
    else if (protocol == "UDP")  color = QColor(80,  220,  80);  // verde
    else if (protocol == "ICMP") color = QColor(255, 170,  50);  // naranja
    else                         color = QColor(180, 180, 180);  // gris

    for (int col = 0; col < table->columnCount(); ++col)
        if (QTableWidgetItem* it = table->item(row, col))
            it->setForeground(color);
}