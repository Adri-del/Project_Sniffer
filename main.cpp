#include <iostream>
#include "Sniffer.h"

int main() {
    char option;
    Sniffer sniffer;
    do{
        std::cout << "\n===MENU PRINCIPAL===\n";
        std::cout << "1.Iniciar captura\n";
        std::cout << "2.Salir\n";
        std::cout << "Seleccione una opcion: ";
        option = _getch();

        switch(option) {
            case '1': sniffer.capturar(); break;
            case '2': std::cout << "\nSaliendo..." << std::endl; break;
            default: std::cout << "\nOpcion no valida. Intente de nuevo." << std::endl; break;
        }
    }while(option != '2');

    return 0;
}
