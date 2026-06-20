#ifndef ELIGE_INTERFAZ_H
#define ELIGE_INTERFAZ_H

#include <QInputDialog>
#include <QStringList>
#include <pcap.h>
#include <string>

inline std::string elige_Interfaz(pcap_if_t* alldevs) {
    QStringList interfaces;
    std::vector<std::string> devices;

    // Recorrer interfaces
    for (pcap_if_t* d = alldevs; d; d = d->next) {
        QString descripcion;

        if (d->description)
            descripcion = QString::fromUtf8(d->description);
        else
            descripcion = " - ";

        interfaces << descripcion;
        devices.push_back(d->name);
    }

    // Verificar que existan interfaces
    if (interfaces.isEmpty()) {
        return "";
    }

    QInputDialog dialog;
    dialog.setWindowTitle("Seleccionar interfaz");
    dialog.setLabelText("Interfaz de red:");
    dialog.setComboBoxItems(interfaces);
    dialog.setOption(QInputDialog::UseListViewForComboBoxItems);

    if (dialog.exec() != QDialog::Accepted) {
        return "";
    }

    QString seleccion = dialog.textValue();

    // Obtener índice seleccionado
    int index = interfaces.indexOf(seleccion);

    if (index < 0) {
        return "";
    }

    std::string device = devices[index];

    return device;
}

#endif // ELIGE_INTERFAZ_H
