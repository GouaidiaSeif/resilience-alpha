import importlib.util
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from resilience_common import vault

ROOT = Path(__file__).resolve().parents[1]


def _load_keeper():
    spec = importlib.util.spec_from_file_location("keeper", ROOT / "infra" / "vault" / "keeper.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeVault(BaseHTTPRequestHandler):
    """Vault minimal : AppRole, KV (shared seulement pour ce rôle), identifiants database, révocation."""
    calls: list[str] = []

    def _reply(self, status, body=None):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body or {}).encode())

    def _route(self):
        FakeVault.calls.append(f"{self.command} {self.path}")
        if self.path == "/v1/auth/approle/login":
            return self._reply(200, {"auth": {"client_token": "t-1"}})
        if self.headers.get("X-Vault-Token") != "t-1":
            return self._reply(403, {"errors": ["permission denied"]})
        if self.path == "/v1/secret/data/resilience/shared":
            return self._reply(200, {"data": {"data": {"jwt_secret": "s3cr3t"}}})
        if self.path == "/v1/secret/data/resilience/payments":
            return self._reply(403, {"errors": ["permission denied"]})   # pas de secret propre : refus normal
        if self.path == "/v1/database/creds/payments":
            return self._reply(200, {"lease_id": "database/creds/payments/abc", "lease_duration": 3600,
                                     "data": {"username": "v-approle-payments-x", "password": "p@ss/w:rd"}})
        if self.path == "/v1/sys/leases/revoke":
            return self._reply(204)
        return self._reply(404)

    do_GET = do_POST = do_PUT = _route

    def log_message(self, *args):
        pass


@pytest.fixture
def fake_vault(tmp_path, monkeypatch):
    server = HTTPServer(("127.0.0.1", 0), FakeVault)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    creds = tmp_path / "approle"
    creds.mkdir()
    (creds / "role_id").write_text("role")
    (creds / "secret_id").write_text("secret")
    monkeypatch.setenv("VAULT_ADDR", f"http://127.0.0.1:{server.server_port}")
    monkeypatch.setenv("VAULT_ROLE", "payments")
    monkeypatch.setenv("VAULT_DB_ROLE", "payments")
    monkeypatch.setenv("VAULT_CREDS_DIR", str(creds))
    monkeypatch.setenv("DATABASE_URL_TEMPLATE", "postgresql://{username}:{password}@postgres:5432/resilience")
    monkeypatch.delenv("JWT_SECRET", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    FakeVault.calls.clear()
    vault._state["stop"].clear()
    yield
    vault._state["stop"].set()
    server.shutdown()


def test_load_secrets_sets_env_and_dynamic_database_url(fake_vault):
    vault.load_secrets(timeout=5)
    assert os.environ["JWT_SECRET"] == "s3cr3t"
    # Caractères spéciaux du mot de passe échappés dans l'URL.
    assert os.environ["DATABASE_URL"] == "postgresql://v-approle-payments-x:p%40ss%2Fw%3Ard@postgres:5432/resilience"
    vault.revoke()
    assert "PUT /v1/sys/leases/revoke" in FakeVault.calls


def test_without_vault_addr_nothing_changes(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.setenv("JWT_SECRET", "from-env")
    vault.load_secrets(timeout=1)
    assert os.environ["JWT_SECRET"] == "from-env"


def test_policies_grant_each_service_only_its_own_secrets():
    keeper = _load_keeper()
    payments = keeper.policy("payments", keeper.APPS["payments"])
    assert 'path "database/creds/payments"' in payments and "database/creds/auth" not in payments
    assert "secret/data/resilience/auth" not in payments and "secret/data/resilience/postgres" not in payments
    auth = keeper.policy("auth", keeper.APPS["auth"])
    assert 'path "secret/data/resilience/auth"' in auth
    detector = keeper.policy("detector", keeper.APPS["detector"])
    assert "database/" not in detector   # pas de base : ni identifiants ni renouvellement de bail


def test_database_role_is_a_temporary_member_of_the_service_group():
    keeper = _load_keeper()
    role = keeper.db_role("audit")
    create = " ".join(role["creation_statements"])
    assert "VALID UNTIL '{{expiration}}' IN ROLE svc_audit" in create
    assert "ALTER ROLE svc_audit NOLOGIN PASSWORD NULL" in create   # migration des anciens mots de passe fixes
    assert any("pg_terminate_backend" in s for s in role["revocation_statements"])
