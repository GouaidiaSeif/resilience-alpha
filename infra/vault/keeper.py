"""Gardien de Vault (service vault-keeper) : initialise, descelle, configure, puis surveille Vault.

Au démarrage de la pile :
  1. initialise Vault s'il est neuf (clé de descellement et jeton racine écrits dans .vault/init.json, sur le PC Hôte,
     jamais dans Git), puis le descelle ;
  2. configure, de façon idempotente : journal d'audit, moteur KV (secrets), AppRole (une identité par service),
     politiques (chaque service ne lit que SES secrets), moteur database (identifiants PostgreSQL temporaires) ;
  3. crée les secrets absents : repris de l'ancien .env (migration) ou générés aléatoirement ;
  4. écrit pour chaque service son identité AppRole (role_id + nouveau secret_id à chaque démarrage) et, pour les
     deux composants qui ne savent pas parler à Vault (PostgreSQL, Grafana), leurs fichiers de secrets ;
  5. surveille Vault toutes les 5 s : s'il redémarre (il revient scellé), le descelle aussitôt.

Bibliothèque standard uniquement. Laboratoire : 1 seule clé de descellement, gardée sur le PC Hôte (en production :
descellement automatique par un KMS/HSM et clés réparties entre plusieurs personnes). Voir docs/03-secrets-vault.md.
"""

from __future__ import annotations

import json
import os
import secrets
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

VAULT = os.environ.get("VAULT_ADDR", "http://vault:8200").rstrip("/")
KEYS = Path(os.environ.get("KEYS_DIR", "/vault-keys"))
PG_HOST = os.environ.get("PG_HOST", "postgres")
PG_DB = os.environ.get("PG_DB", "resilience")
PG_ADMIN = os.environ.get("PG_ADMIN_USER", "pgadmin")
WATCH_SECONDS = 5

# Consommateurs : secrets KV lus (en plus de « shared ») et rôle de base de données (identifiants temporaires).
APPS: dict[str, dict] = {
    "auth": {"kv": ["auth"], "db": "auth"},
    "accounts": {"kv": [], "db": "accounts"},
    "payments": {"kv": [], "db": "payments"},
    "notifications": {"kv": [], "db": "notifications"},
    "audit": {"kv": [], "db": "audit"},
    "remediation": {"kv": [], "db": None},
    "canary": {"kv": ["canary"], "db": None},
    "detector": {"kv": [], "db": None},
}

# Secrets gardés dans Vault (KV v2, chemin secret/resilience/<nom>) : (clé, variable de l'ancien .env, génération).
SECRETS: dict[str, list[tuple[str, str, str]]] = {
    "shared": [("jwt_secret", "JWT_SECRET", "jwt")],
    "auth": [("admin_password", "ADMIN_PASSWORD", "password")],
    "canary": [("canary_password", "CANARY_PASSWORD", "password")],
    "grafana": [("admin_password", "GRAFANA_ADMIN_PASSWORD", "password"), ("discord_webhook_url", "DISCORD_WEBHOOK_URL", "empty")],
    "postgres": [("admin_password", "POSTGRES_ADMIN_PASSWORD", "password")],
}
# Sans webhook Discord, Grafana refuse de démarrer : adresse locale sans destinataire (alertes visibles dans Grafana).
NO_WEBHOOK = "http://127.0.0.1:9/discord-non-configure"
# Propriétaires des fichiers rendus (Linux ; sous Windows les montages ignorent les droits).
UIDS = {"postgres": 70, "grafana": 472, "app": 10001}


def log(event: str, level: str = "INFO", **fields) -> None:
    print(json.dumps({"ts": datetime.now(timezone.utc).isoformat(), "level": level, "service": "vault-keeper",
                      "logger": "vault-keeper", "msg": event, "event": event, **fields}, ensure_ascii=False), flush=True)


class VaultError(RuntimeError):
    def __init__(self, status: int, errors: list[str]) -> None:
        super().__init__(f"HTTP {status} : {'; '.join(errors) or 'sans détail'}")
        self.status = status


def api(method: str, path: str, body: dict | None = None, token: str | None = None) -> dict:
    req = urllib.request.Request(f"{VAULT}/v1/{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"X-Vault-Token": token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        try:
            errors = json.loads(e.read() or b"{}").get("errors", [])
        except ValueError:
            errors = []
        raise VaultError(e.code, errors) from None


def write_file(path: Path, content: str, owner: str = "app") -> None:
    """Écriture atomique, lisible par le seul propriétaire attendu (sous Linux)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(content, encoding="utf-8")
    try:
        os.chown(tmp, UIDS[owner], UIDS[owner])
        os.chmod(tmp, 0o400)
    except (PermissionError, OSError, AttributeError):
        pass
    os.replace(tmp, path)


def wait_vault() -> None:
    for _ in range(120):
        try:
            api("GET", "sys/seal-status")
            return
        except (urllib.error.URLError, OSError, VaultError):
            time.sleep(1)
    raise SystemExit("Vault injoignable après 120 s")


# ───────────────────────────── 1. Initialisation et descellement ─────────────────────────────

def init_or_load() -> dict:
    keys_file = KEYS / "init.json"
    status = api("GET", "sys/init")
    if not status.get("initialized"):
        if keys_file.exists():
            backup = keys_file.with_name(f"init-{int(time.time())}.json.old")
            keys_file.replace(backup)
            log("vault_reinitialized", "WARNING", reason="données Vault absentes (volume recréé)", old_keys=backup.name)
        # Laboratoire : 1 part, seuil 1. Production : 5 parts, seuil 3, réparties entre plusieurs personnes.
        res = api("PUT", "sys/init", {"secret_shares": 1, "secret_threshold": 1})
        KEYS.mkdir(parents=True, exist_ok=True)
        # Réponse brute écrite AVANT toute lecture : une clé de descellement perdue rend Vault inutilisable.
        (KEYS / "init-response.json").write_text(json.dumps(res), encoding="utf-8")
        keys = {"unseal_key": res["keys_base64"][0], "root_token": res["root_token"],
                "created_at": datetime.now(timezone.utc).isoformat()}
        keys_file.write_text(json.dumps(keys, indent=2), encoding="utf-8")
        (KEYS / "init-response.json").unlink()
        try:
            os.chmod(keys_file, 0o600)
        except OSError:
            pass
        log("vault_initialized", keys_file=".vault/init.json")
        return keys
    if not keys_file.exists():
        log("vault_keys_missing", "ERROR", detail="Vault est initialisé mais .vault/init.json est introuvable : sans la "
            "clé de descellement, ses secrets sont perdus. Repartir de zéro : docker compose down -v, puis relancer.")
        raise SystemExit(1)
    return json.loads(keys_file.read_text(encoding="utf-8"))


def unseal(keys: dict) -> bool:
    if api("GET", "sys/seal-status").get("sealed"):
        api("PUT", "sys/unseal", {"key": keys["unseal_key"]})
        wait_active()
        log("vault_unsealed")
        return True
    return False


def wait_active() -> None:
    """Juste après le descellement, le nœud Raft s'élit lui-même : quelques secondes avant d'accepter les écritures."""
    for _ in range(60):
        try:
            if api("GET", "sys/leader").get("is_self"):
                return
        except VaultError:
            pass
        time.sleep(1)


# ───────────────────────────── 2. Configuration ─────────────────────────────

def ensure_mounts(token: str) -> None:
    mounts = api("GET", "sys/mounts", token=token)
    mounts = mounts.get("data", mounts)
    if "secret/" not in mounts:
        api("POST", "sys/mounts/secret", {"type": "kv", "options": {"version": "2"}}, token)
    if "database/" not in mounts:
        api("POST", "sys/mounts/database", {"type": "database"}, token)
    auths = api("GET", "sys/auth", token=token)
    if "approle/" not in auths.get("data", auths):
        api("POST", "sys/auth/approle", {"type": "approle"}, token)
    audits = api("GET", "sys/audit", token=token)
    if "stdout/" not in audits.get("data", audits):
        # Chaque appel à Vault (qui, quoi, quand ; valeurs hachées) part sur la sortie standard : Loki {service="vault"}.
        api("PUT", "sys/audit/stdout", {"type": "file", "options": {"file_path": "stdout"}}, token)


def generate(kind: str) -> str:
    return {"jwt": secrets.token_urlsafe(48), "password": secrets.token_hex(16), "empty": ""}[kind]


def ensure_secrets(token: str) -> dict[str, dict[str, str]]:
    """Crée les secrets absents (repris de l'ancien .env s'il y en a, sinon générés). Ne remplace jamais un existant."""
    values: dict[str, dict[str, str]] = {}
    for name, fields in SECRETS.items():
        try:
            current = api("GET", f"secret/data/resilience/{name}", token=token)["data"]["data"]
        except VaultError as e:
            if e.status != 404:
                raise
            current = {}
        merged, created = dict(current), []
        for key, legacy, kind in fields:
            if key not in merged:
                imported = os.environ.get(f"LEGACY_{legacy}", "")
                merged[key] = imported or generate(kind)
                created.append(f"{key} ({'repris du .env' if imported else 'généré'})")
        if created:
            api("POST", f"secret/data/resilience/{name}", {"data": merged}, token)
            log("vault_secret_created", path=f"secret/resilience/{name}", keys=created)
        values[name] = merged
    return values


def policy(app: str, spec: dict) -> str:
    rules = ['path "secret/data/resilience/shared" { capabilities = ["read"] }']
    rules += [f'path "secret/data/resilience/{kv}" {{ capabilities = ["read"] }}' for kv in spec["kv"]]
    if spec["db"]:
        rules.append(f'path "database/creds/{spec["db"]}" {{ capabilities = ["read"] }}')
        rules.append('path "sys/leases/renew" { capabilities = ["update"] }')
        rules.append('path "sys/leases/revoke" { capabilities = ["update"] }')
    return f"# Généré par infra/vault/keeper.py : le service {app} ne lit que ses propres secrets.\n" + "\n".join(rules) + "\n"


def ensure_approles(token: str) -> None:
    for app, spec in APPS.items():
        api("PUT", f"sys/policies/acl/{app}", {"policy": policy(app, spec)}, token)
        # Jeton périodique : renouvelable sans fin tant que le service tourne (sinon ses baux database expireraient
        # avec lui) ; expire 1 h après l'arrêt du service. secret_id sans expiration : la remédiation redémarre les
        # conteneurs, qui doivent pouvoir se reconnecter ; il est remplacé à chaque démarrage de la pile.
        api("POST", f"auth/approle/role/{app}", {"token_policies": [app], "token_period": "1h",
                                                  "secret_id_ttl": "0", "secret_id_num_uses": 0}, token)
        role_id = api("GET", f"auth/approle/role/{app}/role-id", token=token)["data"]["role_id"]
        try:
            accessors = api("GET", f"auth/approle/role/{app}/secret-id?list=true", token=token)["data"]["keys"]
        except VaultError:
            accessors = []
        secret_id = api("POST", f"auth/approle/role/{app}/secret-id", {}, token)["data"]["secret_id"]
        for acc in accessors:
            api("POST", f"auth/approle/role/{app}/secret-id-accessor/destroy", {"secret_id_accessor": acc}, token)
        write_file(KEYS / "approle" / app / "role_id", role_id)
        write_file(KEYS / "approle" / app / "secret_id", secret_id)
    log("vault_approles_ready", apps=list(APPS), detail="secret_id renouvelés")


def render(values: dict[str, dict[str, str]]) -> None:
    """Fichiers pour les composants qui ne parlent pas à Vault : PostgreSQL (initialisation) et Grafana."""
    write_file(KEYS / "rendered" / "postgres" / "admin_password", values["postgres"]["admin_password"], "postgres")
    write_file(KEYS / "rendered" / "grafana" / "admin_password", values["grafana"]["admin_password"], "grafana")
    write_file(KEYS / "rendered" / "grafana" / "discord_webhook_url",
               values["grafana"]["discord_webhook_url"] or NO_WEBHOOK, "grafana")


def db_role(svc: str) -> dict:
    """Utilisateur PostgreSQL temporaire membre du rôle de groupe svc_<service> (droits du service, rien de plus)."""
    return {
        "db_name": "postgres",
        "creation_statements": [
            f'CREATE ROLE "{{{{name}}}}" WITH LOGIN PASSWORD \'{{{{password}}}}\' VALID UNTIL \'{{{{expiration}}}}\' IN ROLE svc_{svc};',
            # Migration d'une base créée avant Vault : le rôle de groupe perd son mot de passe fixe et sa connexion.
            f"ALTER ROLE svc_{svc} NOLOGIN PASSWORD NULL;",
        ],
        "revocation_statements": [
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}';",
            'DROP ROLE IF EXISTS "{{name}}";',
        ],
        "default_ttl": "1h",
        "max_ttl": "720h",
    }


READONLY_ROLE = {
    "db_name": "postgres",
    "creation_statements": [
        'CREATE ROLE "{{name}}" WITH LOGIN PASSWORD \'{{password}}\' VALID UNTIL \'{{expiration}}\' IN ROLE pg_read_all_data;',
        f'GRANT CONNECT ON DATABASE {PG_DB} TO "{{{{name}}}}";',
    ],
    "revocation_statements": [
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = '{{name}}';",
        f'REVOKE CONNECT ON DATABASE {PG_DB} FROM "{{{{name}}}}";',
        'DROP ROLE IF EXISTS "{{name}}";',
    ],
    "default_ttl": "1h",
    "max_ttl": "8h",
}


def ensure_database(token: str, admin_password: str) -> None:
    """Moteur database : attend PostgreSQL, puis déclare la connexion et un rôle par service (+ lecture seule, DBeaver)."""
    services = [s["db"] for s in APPS.values() if s["db"]]
    for attempt in range(1, 181):
        try:
            with socket.create_connection((PG_HOST, 5432), timeout=2):
                pass
            api("POST", "database/config/postgres", {
                "plugin_name": "postgresql-database-plugin",
                "connection_url": f"postgresql://{{{{username}}}}:{{{{password}}}}@{PG_HOST}:5432/{PG_DB}?sslmode=disable",
                "username": PG_ADMIN, "password": admin_password,
                "allowed_roles": [*services, "readonly"],
            }, token)
            break
        except (OSError, VaultError) as exc:
            if attempt % 10 == 0:
                log("vault_database_waiting", "WARNING", attempt=attempt, error=str(exc)[:200])
            time.sleep(2)
    else:
        log("vault_database_failed", "ERROR", detail="PostgreSQL injoignable ou mot de passe pgadmin refusé")
        return
    for svc in services:
        api("POST", f"database/roles/{svc}", db_role(svc), token)
    api("POST", "database/roles/readonly", READONLY_ROLE, token)
    Path("/tmp/db-ready").write_text("ok")
    log("vault_database_ready", roles=[*services, "readonly"])


# ───────────────────────────── 3. Boucle ─────────────────────────────

def main() -> None:
    wait_vault()
    keys = init_or_load()
    unseal(keys)
    token = keys["root_token"]
    ensure_mounts(token)
    values = ensure_secrets(token)
    render(values)
    ensure_approles(token)
    Path("/tmp/ready").write_text("ok")   # healthcheck : PostgreSQL, Grafana et les services peuvent démarrer
    log("vault_ready", detail="descellé, secrets et identités prêts")
    threading.Thread(target=ensure_database, args=(token, values["postgres"]["admin_password"]), daemon=True).start()

    last_render = time.monotonic()
    while True:
        time.sleep(WATCH_SECONDS)
        try:
            if unseal(keys):
                log("vault_resealed_recovered", "WARNING", detail="Vault avait redémarré scellé : descellé automatiquement")
            if time.monotonic() - last_render > 30:   # un webhook changé dans Vault se propage (puis : restart grafana)
                render({name: api("GET", f"secret/data/resilience/{name}", token=token)["data"]["data"]
                        for name in ("grafana", "postgres")})
                last_render = time.monotonic()
        except (urllib.error.URLError, OSError, VaultError) as exc:
            log("vault_unreachable", "WARNING", error=str(exc)[:200])


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit(0)
