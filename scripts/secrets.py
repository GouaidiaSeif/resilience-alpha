#!/usr/bin/env python3
"""Secrets de la plateforme, gardés dans Vault : lecture, modification, identifiants PostgreSQL temporaires.

    python scripts/secrets.py show                                   # mots de passe de connexion (front, Grafana)
    python scripts/secrets.py set grafana discord_webhook_url URL    # puis : docker compose restart grafana
    python scripts/secrets.py get auth                               # un chemin secret/resilience/<nom>
    python scripts/secrets.py db-creds                               # utilisateur PostgreSQL temporaire (lecture seule, 1 h)
    python scripts/secrets.py token                                  # jeton pour l'interface http://127.0.0.1:8200

Utilise le jeton racine de .vault/init.json (écrit par vault-keeper) et l'API de Vault publiée en local.
Bibliothèque standard uniquement.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VAULT = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200").rstrip("/")
PATHS = ("shared", "auth", "canary", "grafana", "postgres")


def token() -> str:
    try:
        return json.loads((ROOT / ".vault" / "init.json").read_text(encoding="utf-8"))["root_token"]
    except FileNotFoundError:
        sys.exit("Vault n'est pas encore initialisé (.vault/init.json absent) : lancer la plateforme (demarrer.cmd).")


def api(method: str, path: str, body: dict | None = None) -> dict:
    req = urllib.request.Request(f"{VAULT}/v1/{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", "X-Vault-Token": token()})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        sys.exit(f"Vault a refusé {method} {path} (HTTP {e.code}) : {e.read().decode(errors='replace')[:300]}")
    except urllib.error.URLError:
        sys.exit(f"Vault injoignable sur {VAULT} : la plateforme est-elle lancée ?")


def kv(name: str) -> dict[str, str]:
    return api("GET", f"secret/data/resilience/{name}")["data"]["data"]


def main(argv: list[str]) -> None:
    cmd = argv[0] if argv else "show"
    if cmd == "show":
        print(f"Front (https://localhost:8443)   admin / {kv('auth')['admin_password']}")
        print(f"Grafana (http://localhost:3000)  admin / {kv('grafana')['admin_password']}")
        hook = kv("grafana").get("discord_webhook_url") or ""
        print(f"Webhook Discord                  {'défini (' + hook[:40] + '…)' if hook else 'non défini'}")
    elif cmd == "get" and len(argv) >= 2 and argv[1] in PATHS:
        values = kv(argv[1])
        print(values.get(argv[2], "") if len(argv) > 2 else json.dumps(values, indent=2, ensure_ascii=False))
    elif cmd == "set" and len(argv) == 4 and argv[1] in PATHS:
        values = kv(argv[1])
        values[argv[2]] = argv[3]
        api("POST", f"secret/data/resilience/{argv[1]}", {"data": values})
        print(f"secret/resilience/{argv[1]} : {argv[2]} mis à jour (nouvelle version ; l'ancienne reste consultable).")
        if argv[1] == "grafana":
            print("Grafana relit ses secrets au démarrage : docker compose restart grafana (dans les 30 s).")
        elif argv[1] in ("shared", "auth", "canary"):
            print("Les services lisent leurs secrets au démarrage : redémarrer ceux qui l'utilisent.")
    elif cmd == "db-creds":
        role = argv[1] if len(argv) > 1 else "readonly"
        lease = api("GET", f"database/creds/{role}")
        print(f"Hôte localhost:5432 (docker-compose.dbeaver.yml), base resilience")
        print(f"Utilisateur {lease['data']['username']}")
        print(f"Mot de passe {lease['data']['password']}")
        print(f"Valable {lease['lease_duration'] // 60} min, puis supprimé automatiquement par Vault.")
    elif cmd == "token":
        print(token())
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main(sys.argv[1:])
