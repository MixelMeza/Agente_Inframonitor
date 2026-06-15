#!/bin/bash
# Script de auto-actualización para InfraMonitor Agent (Linux / macOS)

JAR_URL="https://raw.githubusercontent.com/MixelMeza/Agente_Inframonitor/main/releases/inframonitor-agent.jar"
INSTALL_DIR="/opt/inframonitor"
JAR_NAME="inframonitor-agent.jar"

# Determinar directorio de instalación
if [ -f "$INSTALL_DIR/$JAR_NAME" ]; then
    TARGET_PATH="$INSTALL_DIR/$JAR_NAME"
elif [ -f "./$JAR_NAME" ]; then
    TARGET_PATH="./$JAR_NAME"
else
    echo "No se encontró inframonitor-agent.jar en /opt/inframonitor/ o en el directorio actual."
    echo "Se descargará en el directorio actual."
    TARGET_PATH="./$JAR_NAME"
fi

echo "Descargando la última versión del agente desde GitHub..."
curl -L -o "$TARGET_PATH.tmp" "$JAR_URL"

if [ $? -ne 0 ] || [ ! -s "$TARGET_PATH.tmp" ]; then
    echo "Error: Falló la descarga del archivo JAR."
    rm -f "$TARGET_PATH.tmp"
    exit 1
fi

mv "$TARGET_PATH.tmp" "$TARGET_PATH"
chmod +x "$TARGET_PATH"
echo "JAR actualizado con éxito."

# Reiniciar si corre bajo systemd
if systemctl is-active --quiet inframonitor-agent; then
    echo "Reiniciando el servicio systemd (inframonitor-agent)..."
    sudo systemctl restart inframonitor-agent
    echo "Servicio reiniciado."
else
    # Buscar procesos Java activos del agente
    PID=$(pgrep -f "$JAR_NAME")
    if [ ! -z "$PID" ]; then
        echo "Reiniciando proceso del agente (PID: $PID)..."
        kill -9 $PID
        echo "Proceso terminado. Si usas un loop de reinicio automático o systemd, el agente se iniciará solo con la nueva versión."
    else
        echo "No hay procesos activos del agente. Puedes iniciarlo manualmente."
    fi
fi

echo "Actualización completada!"
