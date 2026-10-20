# Lance toute la plateforme : WAF, passerelle, services, détecteur ML, front, observabilité, alertes, et le relais
# d'IP réelle (si EDGE_RELAY=true dans .env).
#   powershell -ExecutionPolicy Bypass -File scripts/start.ps1
# Arrêt : powershell -ExecutionPolicy Bypass -File scripts/stop.ps1   (ou docker compose down ; -v efface la base)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Test-Docker {
    # PowerShell 5.1 : rediriger le stderr d'un exécutable avec « Stop » lève une exception ; on teste le code retour.
    $ErrorActionPreference = "Continue"
    docker info --format "{{.ServerVersion}}" 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}

function Get-EnvValue([string]$text, [string]$name) {
    if ($text -match "(?m)^$name=(.*)$") { return $Matches[1].Trim() }
    return ""
}

# 0. Prérequis : Docker (Desktop) et Python 3.10+ (génération du .env, relais d'IP réelle)
if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    throw "Docker est introuvable : installer Docker Desktop (https://www.docker.com/products/docker-desktop/) puis relancer."
}
$ErrorActionPreference = "Continue"
$pyVersion = python -c "import sys; print('%d.%d' % sys.version_info[:2]); sys.exit(0 if sys.version_info >= (3, 10) else 1)" 2>$null
$pyOk = $LASTEXITCODE -eq 0
$ErrorActionPreference = "Stop"
if (-not $pyOk) {
    throw "Python 3.10 ou plus récent est requis (trouvé : '$pyVersion'). Installer Python depuis https://www.python.org/downloads/ en cochant « Add python.exe to PATH », puis relancer."
}

# 1. Moteur Docker (Docker Desktop est démarré s'il est arrêté)
if (-not (Test-Docker)) {
    $desktop = "C:\Program Files\Docker\Docker\Docker Desktop.exe"
    if (-not (Test-Path $desktop)) { throw "Docker n'est pas démarré et Docker Desktop est introuvable." }
    Write-Host "Démarrage de Docker Desktop..."
    Start-Process $desktop
    $deadline = (Get-Date).AddMinutes(3)
    while (-not (Test-Docker)) {
        if ((Get-Date) -gt $deadline) { throw "Docker ne répond toujours pas après 3 minutes." }
        Start-Sleep -Seconds 3
    }
}

# 2. Configuration
if (-not (Test-Path ".env")) {
    Write-Host "Aucun .env : génération des secrets..."
    python scripts/gen_env.py
    if ($LASTEXITCODE -ne 0) { throw "Échec de scripts/gen_env.py" }
}
$envText = Get-Content ".env" -Raw
if (-not (Get-EnvValue $envText "DISCORD_WEBHOOK_URL")) {
    Write-Warning "DISCORD_WEBHOOK_URL vide dans .env : les alertes resteront visibles dans Grafana, sans message Discord."
}
if (-not (Test-Path "ml/model/model.joblib")) {
    Write-Warning "ml/model/model.joblib absent (normalement fourni par le dépôt : git pull) : le détecteur ML démarre sans modèle et ne bloque rien."
}
$relay = (Get-EnvValue $envText "EDGE_RELAY") -eq "true"

# 3. Construction et démarrage (sans Internet, la construction échoue : on relance avec les images existantes)
$ErrorActionPreference = "Continue"
docker compose up -d --build --remove-orphans
if ($LASTEXITCODE -ne 0) {
    Write-Warning "Construction impossible (accès Internet ?) : démarrage avec les images déjà construites."
    docker compose up -d --remove-orphans
    if ($LASTEXITCODE -ne 0) { throw "docker compose up a échoué." }
}
$ErrorActionPreference = "Stop"

# 4. Relais d'IP réelle (Docker Desktop) : remplace une instance précédente
New-Item -ItemType Directory -Force ".run" | Out-Null
$pidFile = ".run/edge_relay.pid"
if (Test-Path $pidFile) {
    $old = Get-Content $pidFile -ErrorAction SilentlyContinue
    if ($old) { Stop-Process -Id $old -Force -ErrorAction SilentlyContinue }
    Remove-Item $pidFile -Force
}
if ($relay) {
    $proc = Start-Process python -ArgumentList "scripts/edge_relay.py" -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput ".run/edge_relay.log" -RedirectStandardError ".run/edge_relay.err.log"
    $proc.Id | Set-Content $pidFile
    Start-Sleep -Seconds 2
    if ($proc.HasExited) {
        Write-Warning "Le relais d'IP réelle s'est arrêté : voir .run/edge_relay.err.log (port 8080 ou 8443 déjà pris ?)."
    } else {
        Write-Host "Relais d'IP réelle démarré (PID $($proc.Id)) : 8080 et 8443 -> WAF. Autoriser python dans le pare-feu Windows si demandé."
    }
}

# 5. Attente des contrôles de santé
Write-Host "Attente des contrôles de santé..."
$deadline = (Get-Date).AddMinutes(3)
do {
    $rows = docker compose ps --format "{{.Name}}`t{{.Status}}"
    $waiting = @($rows | Where-Object { $_ -match "health: starting|unhealthy|Restarting|Created" })
    if ($waiting.Count -eq 0) { break }
    Start-Sleep -Seconds 3
} while ((Get-Date) -lt $deadline)

docker compose ps --format "table {{.Name}}\t{{.Status}}"
if ($waiting.Count -gt 0) {
    Write-Warning "Pas encore prêts : $($waiting -join ', ')"
}

$lan = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.PrefixOrigin -ne "WellKnown" -and $_.IPAddress -notlike "169.254.*" -and $_.InterfaceAlias -notmatch "vEthernet|WSL|Loopback" } |
    Select-Object -ExpandProperty IPAddress)
Write-Host ""
Write-Host "Application     https://localhost:8443       (certificat autosigné : accepter l'avertissement)"
Write-Host "API             https://localhost:8443/api   (ou http://localhost:8080/api)"
foreach ($ip in $lan) { Write-Host "Depuis le réseau https://${ip}:8443" }
Write-Host "Grafana         http://localhost:3000        (admin / GRAFANA_ADMIN_PASSWORD dans .env)"
Write-Host "WAF et bans     http://localhost:3000/d/ra-waf   ·  Sécurité : https://localhost:8443/admin/security"
Write-Host "Détection ML    http://localhost:3000/d/ra-detection"
Write-Host "Alertes         http://localhost:3000/alerting/list"
if (-not $relay) {
    Write-Host "IP réelle       relais désactivé (EDGE_RELAY) : sous Docker Desktop, tous les clients extérieurs ont la même adresse."
}
