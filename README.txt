## Descripción del proyecto

Packet-Sniffer es una aplicación desarrollada en C++ que permite la captura, análisis y visualización de tráfico de red en tiempo real. El sistema utiliza la biblioteca Npcap para acceder al tráfico de red a nivel de paquetes y el framework Qt para la construcción de la interfaz gráfica.

La aplicación permite capturar paquetes en vivo, aplicar filtros de visualización, importar y exportar capturas mediante archivos CSV.

---

## Estructura del ZIP
- src/ : Código fuente completo del proyecto.
- Sniffer-Installer/ : Instalador generado con Inno Setup.
- SnifferGUI.pro : Proyecto Qt Creator.

---

- El proyecto fue desarrollado y probado en Windows.
- Npcap es requerido para la captura de paquetes en red.
- El instalador incluye las dependencias necesarias para su ejecución.