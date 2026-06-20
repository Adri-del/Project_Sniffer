QT += widgets

CONFIG += c++17

SOURCES += \
    src\main.cpp \
    src\mainwindow.cpp

HEADERS += \
    src\Elige_Interfaz.h \
    src\HeaderStructures.h \
    src\Packet.h \
    src\Sniffer.h \
    src\ThreatDetector.h \
    src\mainwindow.h

INCLUDEPATH += $$PWD/npcap-sdk/Include
LIBS += -L$$PWD/npcap-sdk/Lib/x64 -lwpcap -lPacket -lws2_32