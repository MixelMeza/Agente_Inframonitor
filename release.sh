#!/bin/bash
# release.sh - Compila y copia el JAR a la carpeta de releases

echo "[1/2] Compilando agente con Maven..."
./mvnw clean package -DskipTests
if [ $? -ne 0 ]; then
    echo "Error al compilar el proyecto."
    exit 1
fi

echo "[2/2] Copiando JAR a la carpeta de releases..."
mkdir -p releases
cp target/inframonitor-agent.jar releases/inframonitor-agent.jar
if [ $? -ne 0 ]; then
    echo "Error al copiar el archivo."
    exit 1
fi

echo ""
echo "Proceso de compilación y release completado!"
echo "El JAR listo para Git está en: releases/inframonitor-agent.jar"
chmod +x releases/inframonitor-agent.jar
