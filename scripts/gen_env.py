#!/usr/bin/env python3
"""Crée .env à partir de .env.example (configuration non secrète ; les secrets sont générés et gardés par Vault).

Une ligne « CLE=CHANGE_ME » éventuelle reçoit une valeur aléatoire (modèles personnalisés).
"""

import secrets
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
template, target = ROOT / ".env.example", ROOT / ".env"

if target.exists() and "--force" not in sys.argv:
    sys.exit(".env existe déjà (utiliser --force pour le recréer depuis .env.example).")

lines = []
for line in template.read_text(encoding="utf-8").splitlines():
    if line.endswith("=CHANGE_ME"):
        line = f"{line.split('=', 1)[0]}={secrets.token_hex(16)}"
    lines.append(line)

target.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f".env créé ({target}). Les secrets sont créés par Vault au premier démarrage : python scripts/secrets.py show")
