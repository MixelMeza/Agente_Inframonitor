# Script de auto-actualización para InfraMonitor Agent (Windows - PowerShell)

$JarUrl = "https://raw.githubusercontent.com/MixelMeza/Agente_Inframonitor/main/releases/inframonitor-agent.jar"
$JarName = "inframonitor-agent.jar"

# Determinar ruta de instalación
if (Test-Path ".\$JarName") {
    $TargetPath = ".\$JarName"
} else {
    $TargetPath = Join-Path $env:ProgramFiles "InfraMonitor\inframonitor-agent.jar"
    if (-not (Test-Path $TargetPath)) {
        Write-Host "No se encontró inframonitor-agent.jar localmente. Se descargará en el directorio actual." -ForegroundColor Yellow
        $TargetPath = ".\$JarName"
    }
}

Write-Host "Descargando la última versión del agente desde GitHub..." -ForegroundColor Cyan
try {
    Invoke-WebRequest -Uri $JarUrl -OutFile "$TargetPath.tmp" -UseBasicParsing
} catch {
    Write-Error "Error al descargar el archivo JAR: $_"
    exit 1
}

if ((Get-Item "$TargetPath.tmp").Length -lt 1000) {
    Write-Error "El archivo descargado es demasiado pequeño o está corrupto."
    Remove-Item "$TargetPath.tmp" -Force
    exit 1
}

# Detener proceso java que ejecuta el agente para liberar el bloqueo del archivo
Write-Host "Buscando procesos activos del agente..." -ForegroundColor Gray
$AgentProcesses = Get-WmiObject Win32_Process -Filter "name='java.exe'" | Where-Object { $_.CommandLine -like "*$JarName*" }

if ($AgentProcesses) {
    Write-Host "Deteniendo procesos activos del agente..." -ForegroundColor Yellow
    foreach ($proc in $AgentProcesses) {
        Stop-Process -Id $proc.ProcessId -Force
    }
}

# Mover el archivo
Move-Item -Path "$TargetPath.tmp" -Destination $TargetPath -Force
Write-Host "JAR actualizado con éxito." -ForegroundColor Green

Write-Host "Actualización completada! Si estabas corriendo el agente en un script de bucle o servicio, se reiniciará automáticamente." -ForegroundColor Green
