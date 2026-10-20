#!/usr/bin/env bash
# Arrête la plateforme et le relais d'IP réelle. Les données (base, liste des bans) sont conservées.
#   ./scripts/stop.sh            Remise à zéro complète (efface la base et les bans) : docker compose down -v
cd "$(dirname "$0")/.."
if [ -f .run/edge_relay.pid ]; then
  kill "$(cat .run/edge_relay.pid)" 2>/dev/null && echo "Relais d'IP réelle arrêté."
  rm -f .run/edge_relay.pid
fi
docker compose down
