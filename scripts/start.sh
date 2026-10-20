#!/usr/bin/env bash
# Lance toute la plateforme : services, passerelle, détecteur ML, front, observabilité et alertes.
#   ./scripts/start.sh            (Linux, macOS, Git Bash ; sous Windows, scripts/start.ps1 démarre aussi Docker Desktop)
# Arrêt : docker compose down   (ajouter -v efface aussi la base)
set -euo pipefail
cd "$(dirname "$0")/.."

if ! docker info >/dev/null 2>&1; then
  echo "Docker n'est pas démarré : lancer Docker (ou Docker Desktop) puis relancer ce script." >&2
  exit 1
fi

if [ ! -f .env ]; then
  echo "Aucun .env : génération des secrets..."
  python3 scripts/gen_env.py 2>/dev/null || python scripts/gen_env.py
fi
grep -Eq '^DISCORD_WEBHOOK_URL=[^[:space:]]+' .env \
  || echo "Attention : DISCORD_WEBHOOK_URL vide dans .env, les alertes resteront visibles dans Grafana, sans message Discord." >&2
[ -f ml/model/model.joblib ] \
  || echo "Attention : ml/model/model.joblib absent, le détecteur ML démarre sans modèle et ne bloque rien (docs/02, section 3.4)." >&2

docker compose up -d --build --remove-orphans

echo "Attente des contrôles de santé..."
waiting=""
for _ in $(seq 60); do
  waiting=$(docker compose ps --format '{{.Name}} {{.Status}}' | grep -E 'health: starting|unhealthy|Restarting|Created' || true)
  [ -z "$waiting" ] && break
  sleep 3
done
docker compose ps --format 'table {{.Name}}\t{{.Status}}'
[ -n "$waiting" ] && echo "Pas encore prêts : $waiting" >&2

cat <<'EOF'

Front            http://localhost:3001
API (passerelle) http://localhost:8080
Grafana          http://localhost:3000   (admin / GRAFANA_ADMIN_PASSWORD dans .env)
Détection ML     http://localhost:3000/d/ra-detection
Alertes          http://localhost:3000/alerting/list
EOF
