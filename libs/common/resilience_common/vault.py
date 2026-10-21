"""Secrets du service lus dans Vault au démarrage (AppRole), sans changer le reste du code.

Si VAULT_ADDR est défini, load_secrets() :
  1. se connecte avec l'identité AppRole du service (/run/vault/role_id et secret_id, écrits par vault-keeper) ;
  2. lit les secrets KV autorisés par sa politique (secret/resilience/shared et, s'il y a lieu, secret/resilience/<rôle>)
     et les place dans l'environnement : jwt_secret -> JWT_SECRET, admin_password -> ADMIN_PASSWORD, etc. ;
  3. s'il a une base, demande un identifiant PostgreSQL temporaire (database/creds/<rôle>) et compose DATABASE_URL ;
  4. renouvelle jeton et bail en arrière-plan ; revoke() supprime l'identifiant à l'arrêt du service.

Sans VAULT_ADDR (tests, poste de développement), rien ne change : les variables d'environnement sont lues telles quelles.
"""

from __future__ import annotations

import atexit
import json
import logging
import os
import signal
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

from .logs import log_event

log = logging.getLogger("vault")

RENEW_SECONDS = 20 * 60
_state: dict = {"token": None, "lease_id": None, "stop": threading.Event()}


class VaultUnavailable(RuntimeError):
    pass


def _addr() -> str:
    return (os.environ.get("VAULT_ADDR") or "").rstrip("/")


def _call(method: str, path: str, body: dict | None = None, token: str | None = None) -> dict:
    req = urllib.request.Request(f"{_addr()}/v1/{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json", **({"X-Vault-Token": token} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            raw = r.read()
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as e:
        raise VaultUnavailable(f"{method} {path} : HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise VaultUnavailable(f"{method} {path} : {type(e).__name__}") from None


def _login(creds_dir: Path) -> str:
    # Relus à chaque tentative : vault-keeper remplace le secret_id à chaque démarrage de la pile.
    role_id = (creds_dir / "role_id").read_text(encoding="utf-8").strip()
    secret_id = (creds_dir / "secret_id").read_text(encoding="utf-8").strip()
    return _call("POST", "auth/approle/login", {"role_id": role_id, "secret_id": secret_id})["auth"]["client_token"]


def database_url(template: str, username: str, password: str) -> str:
    """postgresql://{username}:{password}@postgres:5432/resilience -> URL complète (caractères spéciaux échappés)."""
    from urllib.parse import quote

    return template.format(username=quote(username, safe=""), password=quote(password, safe=""))


def load_secrets(*, timeout: float = 180.0) -> None:
    if not _addr():
        return
    role = os.environ.get("VAULT_ROLE", "")
    creds_dir = Path(os.environ.get("VAULT_CREDS_DIR", "/run/vault"))
    deadline = time.monotonic() + timeout
    attempt = 0
    while True:
        attempt += 1
        try:
            token = _login(creds_dir)
            secrets: dict[str, str] = {}
            for path in ("shared", role):
                try:
                    secrets.update(_call("GET", f"secret/data/resilience/{path}", token=token)["data"]["data"])
                except VaultUnavailable:
                    if path == "shared":
                        raise   # la politique du service n'autorise pas forcément secret/resilience/<rôle> : facultatif
            db_role = os.environ.get("VAULT_DB_ROLE")
            lease = None
            if db_role:
                lease = _call("GET", f"database/creds/{db_role}", token=token)
                os.environ["DATABASE_URL"] = database_url(
                    os.environ["DATABASE_URL_TEMPLATE"], lease["data"]["username"], lease["data"]["password"])
            break
        except (VaultUnavailable, FileNotFoundError, KeyError) as exc:
            # Vault scellé, en cours de configuration, PostgreSQL pas encore prêt… : on réessaie.
            if time.monotonic() > deadline:
                raise RuntimeError(f"Secrets introuvables dans Vault après {timeout:.0f} s : {exc}") from exc
            if attempt % 5 == 1:
                log_event(log, "vault_waiting", logging.WARNING, attempt=attempt, error=str(exc)[:160])
            time.sleep(2)
    for key, value in secrets.items():
        os.environ[key.upper()] = value
    _state.update(token=token, lease_id=lease["lease_id"] if lease else None)
    # Arrêt pendant le démarrage (avant qu'uvicorn n'installe ses gestionnaires) : en PID 1, SIGTERM serait ignoré,
    # puis le processus tué sans révoquer son identifiant. On sort proprement ; atexit révoque le bail.
    atexit.register(revoke)
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log_event(log, "vault_secrets_loaded", role=role, secrets=sorted(k.upper() for k in secrets),
              db_user=lease["data"]["username"] if lease else None, lease_seconds=lease.get("lease_duration") if lease else None)
    threading.Thread(target=_renew_loop, args=(creds_dir,), daemon=True, name="vault-renew").start()


def _renew_loop(creds_dir: Path) -> None:
    """Jeton périodique et bail database renouvelés toutes les 20 min (expireraient 1 h après la dernière fois)."""
    while not _state["stop"].wait(RENEW_SECONDS):
        try:
            _call("POST", "auth/token/renew-self", {}, _state["token"])
            if _state["lease_id"]:
                _call("PUT", "sys/leases/renew", {"lease_id": _state["lease_id"], "increment": 3600}, _state["token"])
        except VaultUnavailable as exc:
            # Vault indisponible : on retentera ; si le bail finit par expirer, la base refuse la connexion, la sonde
            # le voit et la remédiation redémarre le service, qui obtient de nouveaux identifiants.
            log_event(log, "vault_renew_failed", logging.WARNING, error=str(exc)[:160])


def revoke() -> None:
    """À l'arrêt : l'utilisateur PostgreSQL temporaire est supprimé tout de suite (sinon à l'expiration du bail)."""
    _state["stop"].set()
    lease_id, _state["lease_id"] = _state["lease_id"], None   # idempotent : arrêt normal puis atexit
    if _addr() and _state["token"] and lease_id:
        try:
            _call("PUT", "sys/leases/revoke", {"lease_id": lease_id}, _state["token"])
        except VaultUnavailable:
            pass
