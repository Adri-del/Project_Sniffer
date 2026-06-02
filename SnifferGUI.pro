QT += widgets

CONFIG += c++17

SOURCES += \
    main.cpp \
    mainwindow.cpp

HEADERS += \
    HeaderStructures.h \
    Packet.h \
    Sniffer.h \
    mainwindow.h

INCLUDEPATH += "C:/npcap-sdk-1.16/Include"
LIBS += -L"C:/npcap-sdk-1.16/Lib/x64" -lwpcap -lPacket -lws2_32