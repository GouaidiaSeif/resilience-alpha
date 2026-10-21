# Éteint la plateforme et le relais d'IP réelle, SANS supprimer les conteneurs (docker compose stop) : tout est
# conservé, historique Grafana compris. Rallumer : demarrer.cmd (ou docker compose start).
#   powershell -ExecutionPolicy Bypass -File scripts/stop.ps1
# Supprimer les conteneurs (données gardées) : docker compose down ; tout effacer : docker compose down -v
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$pidFile = ".run/edge_relay.pid"
if (Test-Path $pidFile) {
    $old = Get-Content $pidFile -ErrorAction SilentlyContinue
    if ($old) { Stop-Process -Id $old -Force -ErrorAction SilentlyContinue }
    Remove-Item $pidFile -Force
    Write-Host "Relais d'IP réelle arrêté."
}
docker compose stop
