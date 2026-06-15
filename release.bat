@echo off
:: release.bat - Compila y copia el JAR a la carpeta de releases
echo [1/2] Compilando agente con Maven...
call .\mvnw.cmd clean package -DskipTests
if %ERRORLEVEL% neq 0 (
    echo Error al compilar el proyecto.
    exit /b %ERRORLEVEL%
)

echo [2/2] Copiando JAR a la carpeta de releases...
if not exist releases mkdir releases
copy /Y target\inframonitor-agent.jar releases\inframonitor-agent.jar
if %ERRORLEVEL% neq 0 (
    echo Error al copiar el archivo.
    exit /b %ERRORLEVEL%
)

echo.
echo Proceso de compilacion y release completado!
echo El JAR listo para Git esta en: releases/inframonitor-agent.jar
