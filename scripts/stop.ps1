# Arrête la plateforme et le relais d'IP réelle. Les données (base, liste des bans) sont conservées.
#   powershell -ExecutionPolicy Bypass -File scripts/stop.ps1
# Remise à zéro complète (efface la base et la liste des bans) : docker compose down -v
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

$pidFile = ".run/edge_relay.pid"
if (Test-Path $pidFile) {
    $old = Get-Content $pidFile -ErrorAction SilentlyContinue
    if ($old) { Stop-Process -Id $old -Force -ErrorAction SilentlyContinue }
    Remove-Item $pidFile -Force
    Write-Host "Relais d'IP réelle arrêté."
}
docker compose down
