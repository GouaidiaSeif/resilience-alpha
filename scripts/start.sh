#!/usr/bin/env bash
# Lance toute la plateforme : WAF, passerelle, services, détecteur ML, front, observabilité, alertes, et le relais
# d'IP réelle (si EDGE_RELAY=true dans .env ; utile sous Docker Desktop, inutile sous Linux).
#   ./scripts/start.sh            (Linux, macOS, Git Bash ; sous Windows, scripts/start.ps1 démarre aussi Docker Desktop)
# Arrêt : ./scripts/stop.sh   (ou docker compose down ; -v efface aussi la base)
set -euo pipefail
cd "$(dirname "$0")/.."
PY=$(command -v python3 || command -v python)

if ! docker info >/dev/null 2>&1; then
  echo "Docker n'est pas démarré : lancer Docker (ou Docker Desktop) puis relancer ce script." >&2
  exit 1
fi

if [ ! -f .env ]; then
  echo "Aucun .env : génération des secrets..."
  "$PY" scripts/gen_env.py
fi
grep -Eq '^DISCORD_WEBHOOK_URL=[^[:space:]]+' .env \
  || echo "Attention : DISCORD_WEBHOOK_URL vide dans .env, les alertes resteront visibles dans Grafana, sans message Discord." >&2
[ -f ml/model/model.joblib ] \
  || echo "Attention : ml/model/model.joblib absent (normalement fourni par le dépôt : git pull), le détecteur ML démarre sans modèle et ne bloque rien." >&2

# Sans Internet, la construction échoue : on relance avec les images déjà construites.
if ! docker compose up -d --build --remove-orphans; then
  echo "Attention : construction impossible (accès Internet ?), démarrage avec les images existantes." >&2
  docker compose up -d --remove-orphans
fi

# Relais d'IP réelle : remplace une instance précédente.
mkdir -p .run
if [ -f .run/edge_relay.pid ]; then
  kill "$(cat .run/edge_relay.pid)" 2>/dev/null || true
  rm -f .run/edge_relay.pid
fi
if grep -Eq '^EDGE_RELAY=true' .env; then
  nohup "$PY" scripts/edge_relay.py > .run/edge_relay.log 2>&1 &
  echo $! > .run/edge_relay.pid
  sleep 2
  if kill -0 "$(cat .run/edge_relay.pid)" 2>/dev/null; then
    echo "Relais d'IP réelle démarré (PID $(cat .run/edge_relay.pid)) : 8080 et 8443 -> WAF."
  else
    echo "Attention : le relais d'IP réelle s'est arrêté, voir .run/edge_relay.log (port 8080 ou 8443 déjà pris ?)." >&2
  fi
fi

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

Application      https://localhost:8443       (certificat autosigné : accepter l'avertissement)
API              https://localhost:8443/api   (ou http://localhost:8080/api)
Grafana          http://localhost:3000        (admin / GRAFANA_ADMIN_PASSWORD dans .env)
WAF et bans      http://localhost:3000/d/ra-waf   ·  Sécurité : https://localhost:8443/admin/security
Détection ML     http://localhost:3000/d/ra-detection
Alertes          http://localhost:3000/alerting/list
EOF
