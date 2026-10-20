# Lance toute la plateforme : services, passerelle, détecteur ML, front, observabilité et alertes.
#   powershell -ExecutionPolicy Bypass -File scripts/start.ps1
# Arrêt : docker compose down   (ajouter -v efface aussi la base)
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

function Test-Docker {
    # PowerShell 5.1 : rediriger le stderr d'un exécutable avec « Stop » lève une exception ; on teste le code retour.
    $ErrorActionPreference = "Continue"
    docker info --format "{{.ServerVersion}}" 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
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
if ($envText -notmatch "(?m)^DISCORD_WEBHOOK_URL=\S+") {
    Write-Warning "DISCORD_WEBHOOK_URL vide dans .env : les alertes resteront visibles dans Grafana, sans message Discord."
}
if (-not (Test-Path "ml/model/model.joblib")) {
    Write-Warning "ml/model/model.joblib absent (normalement fourni par le dépôt : git pull) : le détecteur ML démarre sans modèle et ne bloque rien."
}

# 3. Construction et démarrage
docker compose up -d --build --remove-orphans
if ($LASTEXITCODE -ne 0) { throw "docker compose up a échoué." }

# 4. Attente des contrôles de santé
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

Write-Host ""
Write-Host "Front           http://localhost:3001"
Write-Host "API (passerelle) http://localhost:8080"
Write-Host "Grafana         http://localhost:3000   (admin / GRAFANA_ADMIN_PASSWORD dans .env)"
Write-Host "Détection ML    http://localhost:3000/d/ra-detection"
Write-Host "Alertes         http://localhost:3000/alerting/list"
