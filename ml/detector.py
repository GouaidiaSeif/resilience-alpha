"""Service « detector » : détection d'anomalies en temps réel sur le trafic de la passerelle (Isolation Forest).

Boucle (toutes les EVAL_INTERVAL_SECONDS) :
  1. lit dans Loki les WINDOW_S dernières secondes du journal d'accès de la passerelle ;
  2. calcule les variables par client (features.py) et applique le modèle hybride entraîné (train.py) :
     Isolation Forest + garde-fous de bornes + classifieur supervisé (s'il a été entraîné) ;
  3. un client anormal PERSIST fois de suite est bloqué BLOCK_TTL_SECONDS ; le moteur de remédiation reçoit une
     alerte « anomaly » (escalade humaine, aucun redémarrage si le service est sain) et l'audit trace le blocage.

Liste des bans (bans.py) : IP bannies à la main (API /api/security/bans, page Sécurité du front), après une
rafale de requêtes bloquées par le WAF, ou quand le modèle bloque un client. Persistante (volume detector-data).

La passerelle (gateway/nginx.conf) interroge GET /internal/check avant chaque requête :
403 si l'IP est bannie ou le client bloqué, 204 sinon. Si le détecteur ne répond pas, la passerelle laisse passer (ouverture
par défaut) : une panne du détecteur ne coupe jamais la plateforme.
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import socket
import time
from collections import Counter, defaultdict
from pathlib import Path

import httpx
import numpy as np
from fastapi import APIRouter, Depends, FastAPI, Header, HTTPException, Response
from prometheus_client import Counter as PCounter
from prometheus_client import Gauge, Histogram
from pydantic import BaseModel, Field

import loki
from bans import BanError, BanList
from features import client_key, exceeded, route_of, window_features
from model_io import load_bundle, mismatch_text
from resilience_common.app import create_app
from resilience_common.config import env
from resilience_common.events import audit
from resilience_common.logs import log_event
from resilience_common.security import require_roles, service_token

log = logging.getLogger("detector")

MODEL_PATH = Path(env("MODEL_PATH", "/app/model/model.joblib") or "/app/model/model.joblib")
REMEDIATION_URL = env("REMEDIATION_URL", "http://remediation:8000")
EVAL_INTERVAL = float(env("EVAL_INTERVAL_SECONDS", "5") or 5)
LOKI_DELAY = float(env("LOKI_DELAY_SECONDS", "3") or 3)
PERSIST = int(env("PERSIST", "2") or 2)
BLOCK_TTL = float(env("BLOCK_TTL_SECONDS", "600") or 600)
ALERT_COOLDOWN = float(env("ALERT_COOLDOWN_SECONDS", "600") or 600)
MIN_REQUESTS = int(env("MIN_REQUESTS", "3") or 3)
# Jamais bloqués : la sonde et le conteneur du front (tous les utilisateurs de l'interface partagent son adresse).
# Identifiés par leur adresse (nom ou IP de conteneur), non falsifiable depuis l'extérieur ; l'agent seul ne suffit pas.
ALLOW_UA = re.compile(env("ALLOW_UA_REGEX", r"^$") or "^$")
ALLOW_HOSTS = [h for h in (env("ALLOW_HOSTS", "canary") or "").split(",") if h]
SERVICES = ("auth", "accounts", "payments", "notifications")
# Liste des bans
BANS_PATH = Path(env("BANS_PATH", "/data/bans.json") or "/data/bans.json")
NEVER_BAN = (env("NEVER_BAN", "127.0.0.0/8,::1/128,10.250.0.0/24") or "").split(",")
ML_BAN_IP = (env("ML_BAN_IP", "true") or "true").lower() == "true"          # un blocage ML bannit aussi l'IP
WAF_AUTOBAN = (env("WAF_AUTOBAN", "true") or "true").lower() == "true"
WAF_BAN_THRESHOLD = int(env("WAF_BAN_THRESHOLD", "5") or 5)                  # requêtes bloquées par le WAF…
WAF_BAN_WINDOW = float(env("WAF_BAN_WINDOW_SECONDS", "120") or 120)          # …dans cette fenêtre
WAF_BAN_TTL = float(env("WAF_BAN_TTL_SECONDS", "3600") or 3600)
# Règles comptées comme « attaque » quand le WAF ne bloque pas (mode DetectionOnly) : score d'anomalie dépassé,
# outil de scan reconnu.
WAF_ATTACK_RULES = {"949110", "9000001"}

EVALS = PCounter("detector_evaluations_total", "Fenêtres client notées")
ANOMALIES = PCounter("detector_anomalies_total", "Fenêtres client jugées anormales")
REASONS = PCounter("detector_anomaly_reasons_total", "Fenêtres anormales, par règle déclenchée", ["reason"])
BLOCKS = PCounter("detector_blocks_total", "Clients bloqués, par service visé", ["target_service"])
CHECKS = PCounter("detector_checks_total", "Contrôles avant requête, par décision et par demandeur (waf : toute requête externe ; gateway : requêtes /api)", ["result", "origin"])
BLOCKED = Gauge("detector_blocked_clients", "Clients actuellement bloqués")
MIN_SCORE = Gauge("detector_min_score", "Score le plus bas de la dernière évaluation (plus bas = plus anormal)")
MODEL_LOADED = Gauge("detector_model_loaded", "1 si un modèle est chargé")
THRESHOLD = Gauge("detector_threshold", "Seuil de score de la forêt (sous ce seuil = anormal)")
MAX_PROBA = Gauge("detector_max_attack_probability", "Probabilité d'attaque la plus haute de la dernière évaluation")
SCORED = Gauge("detector_clients_scored", "Clients notés à la dernière évaluation")
LAST_EVAL = Gauge("detector_last_evaluation_timestamp_seconds", "Horodatage de la dernière évaluation")
EVAL_SECONDS = Histogram("detector_evaluation_seconds", "Durée d'une évaluation (lecture Loki + notation)",
                         buckets=(0.05, 0.1, 0.25, 0.5, 1, 2, 5))
# Séries créées à zéro : increase() et les alertes voient le premier blocage, pas seulement le deuxième.
for _svc in SERVICES:
    BLOCKS.labels(_svc)
for _reason in ("forest", "bounds", "supervised"):
    REASONS.labels(_reason)
BANNED = Gauge("detector_banned_ips", "IP actuellement bannies")
BANS = PCounter("detector_bans_total", "IP bannies, par origine", ["source"])
for _result in ("allowed", "blocked", "banned"):
    for _origin in ("waf", "gateway"):
        CHECKS.labels(_result, _origin)
for _source in ("manual", "waf", "ml"):
    BANS.labels(_source)


class State:
    def __init__(self) -> None:
        self.bundle: dict | None = None
        self.blocked: dict[str, dict] = {}  # clé -> {until, score, service, since}
        self.streak: dict[str, int] = defaultdict(int)
        self.last_alert: dict[str, float] = {}
        self.allow_ips: set[str] = set()
        self.bans = BanList(BANS_PATH, NEVER_BAN)
        self.unbanned_at: dict[str, float] = {}  # IP -> heure du dernier déban : les blocages WAF antérieurs ne comptent plus


def load_model(st: State) -> None:
    try:
        st.bundle, mismatch = load_bundle(MODEL_PATH)
    except FileNotFoundError:
        st.bundle = None
        MODEL_LOADED.set(0)
        log_event(log, "detector_model_missing", logging.WARNING, path=str(MODEL_PATH))
        return
    except RuntimeError as exc:
        st.bundle = None
        MODEL_LOADED.set(0)
        log_event(log, "detector_model_incompatible", logging.ERROR, path=str(MODEL_PATH), error=str(exc)[:300])
        return
    MODEL_LOADED.set(1)
    THRESHOLD.set(st.bundle["threshold"])
    log_event(log, "detector_model_loaded", path=str(MODEL_PATH), threshold=st.bundle["threshold"], trained_at=st.bundle["trained_at"],
              versions=st.bundle.get("versions"))
    if mismatch:
        log_event(log, "detector_model_version_mismatch", logging.WARNING, detail=mismatch_text(mismatch))


def refresh_allowlist(st: State) -> None:
    ips = set()
    for host in ALLOW_HOSTS:
        try:
            ips.add(socket.gethostbyname(host))
        except OSError:
            pass
    st.allow_ips = ips


def allowed(st: State, key: str) -> bool:
    ip, _, ua = key.partition("|")
    return ip in st.allow_ips or bool(ALLOW_UA.match(ua))


def target_service(records: list[dict]) -> str:
    """Service le plus visé par le client (pour l'alerte) ; auth par défaut (balayage hors /api)."""
    hits = Counter(r.split("/")[2] for r in (route_of(str(x.get("uri", ""))) for x in records) if r.startswith("/api/") and r.count("/") >= 2)
    for svc, _ in hits.most_common():
        if svc in SERVICES:
            return svc
    return "auth"


async def alert(app: FastAPI, key: str, service: str, score: float, feats: dict) -> None:
    st: State = app.state.det
    if time.monotonic() - st.last_alert.get(service, -ALERT_COOLDOWN) < ALERT_COOLDOWN:
        return  # limite l'usage du disjoncteur de la remédiation (voir docs/02, section 3.6)
    st.last_alert[service] = time.monotonic()
    payload = {
        "source": "detector",
        "service": service,
        "type": "anomaly",
        "severity": "critical" if score < st.bundle["threshold"] - 0.1 else "high",
        "score": round(score, 4),
        "details": {"client": key, "features": {k: round(v, 3) for k, v in feats.items()}},
    }
    try:
        await app.state.http.post(f"{REMEDIATION_URL}/internal/alerts", json=payload,
                                  headers={"Authorization": f"Bearer {service_token('detector')}"}, timeout=3)
    except httpx.HTTPError as exc:
        log_event(log, "detector_alert_failed", logging.WARNING, error=type(exc).__name__)


def ban_ip(st: State, ip: str, source: str, reason: str, ttl: float | None, by: str | None = None, **details) -> dict:
    """Bannit une IP (lève BanError si elle est invalide ou partagée) ; trace dans les journaux et l'audit."""
    if BanList.normalize(ip) in st.allow_ips:
        raise BanError(f"{ip} est une adresse de la pile (sonde ou front) : jamais bannie")
    before = st.bans.get(BanList.normalize(ip))
    ban = st.bans.add(ip, source, reason, ttl, by)
    BANNED.set(len(st.bans.listing()))
    if ban is not before:
        BANS.labels(source).inc()
        log_event(log, "detector_ip_banned", logging.WARNING, ip=ban["ip"], source=source, reason=ban["reason"],
                  ttl=ttl, by=by, **details)
        audit("detector", "ip_banned", actor=by or source, outcome="denied", ip=ban["ip"], source=source,
              reason=ban["reason"], ttl_seconds=ttl, **details)
    return ban


def unban_ip(st: State, ip: str, by: str | None, reason: str) -> bool:
    removed = st.bans.remove(ip)
    st.unbanned_at[BanList.normalize(ip)] = time.time()
    BANNED.set(len(st.bans.listing()))
    if removed:
        log_event(log, "detector_ip_unbanned", ip=BanList.normalize(ip), reason=reason, by=by)
        audit("detector", "ip_unbanned", actor=by or "detector", ip=BanList.normalize(ip), reason=reason)
    return removed


async def waf_autoban(app: FastAPI) -> None:
    """Bannit une IP après WAF_BAN_THRESHOLD requêtes bloquées (ou jugées attaques) par ModSecurity."""
    st: State = app.state.det
    txs = await asyncio.to_thread(loki.waf_transactions, WAF_BAN_WINDOW, LOKI_DELAY, app.state.loki)
    hits: dict[str, list[dict]] = defaultdict(list)
    for tx in txs:
        if tx["_ts"] <= st.unbanned_at.get(tx["client_ip"], 0):
            continue  # déjà jugé : un administrateur a levé le ban après ces requêtes
        if tx["interrupted"] or WAF_ATTACK_RULES.intersection(tx["rules"]):
            hits[tx["client_ip"]].append(tx)
    for ip, found in hits.items():
        if len(found) < WAF_BAN_THRESHOLD or not ip or st.bans.get(ip):
            continue
        rules = sorted({r for tx in found for r in tx["rules"] if r})[:10]
        try:
            ban_ip(st, ip, "waf", f"{len(found)} requêtes bloquées par le WAF en {WAF_BAN_WINDOW:.0f} s",
                   WAF_BAN_TTL, rules=rules, sample_uri=found[-1]["uri"])
        except BanError:
            pass  # adresse partagée (pas de relais d'IP réelle) : visible dans le journal du WAF, pas bannissable


async def evaluate(app: FastAPI) -> None:
    st: State = app.state.det
    now = time.time()
    for key in [k for k, b in st.blocked.items() if b["until"] <= now]:
        st.blocked.pop(key)
        log_event(log, "detector_unblocked", client=key, reason="expired")
    for ip in st.bans.purge(now):
        st.bans.save()
        log_event(log, "detector_ip_unbanned", ip=ip, reason="expired")
    BLOCKED.set(len(st.blocked))
    BANNED.set(len(st.bans.listing()))
    LAST_EVAL.set(now)
    if WAF_AUTOBAN:
        await waf_autoban(app)
    if st.bundle is None:
        return

    window = st.bundle["window_s"]
    records = await asyncio.to_thread(loki.fetch_recent, window, LOKI_DELAY, app.state.loki)
    by_key: dict[str, list[dict]] = defaultdict(list)
    for r in records:
        by_key[client_key(r)].append(r)

    keys, rows, feats_by_key = [], [], {}
    for key, recs in by_key.items():
        if len(recs) < MIN_REQUESTS or allowed(st, key):
            continue
        feats = window_features(recs)
        keys.append(key)
        rows.append([feats[f] for f in st.bundle["features"]])
        feats_by_key[key] = feats
    seen = set(keys)
    for key in list(st.streak):
        if key not in seen:
            st.streak.pop(key)
    SCORED.set(len(rows))
    if not rows:
        # Aucun client noté : pas de valeur (trou dans les courbes) plutôt qu'un 0 qui se lirait comme un score.
        MIN_SCORE.set(float("nan"))
        MAX_PROBA.set(float("nan"))
        return

    X = np.asarray(rows, dtype=float)
    scores = st.bundle["model"].score_samples(X)
    clf = st.bundle.get("classifier")
    probas = clf.predict_proba(X)[:, 1] if clf is not None else np.zeros(len(rows))
    EVALS.inc(len(rows))
    MIN_SCORE.set(float(scores.min()))
    MAX_PROBA.set(float(probas.max()))
    for key, score, proba in zip(keys, scores, probas):
        # Trois règles (modèle hybride) : forêt sous le seuil, variable hors plage normale, classifieur supervisé.
        out = exceeded(feats_by_key[key], st.bundle.get("limits", {}))
        supervised = bool(proba > st.bundle.get("classifier_threshold", 0.5))
        reasons = (["forest"] if score < st.bundle["threshold"] else []) + (["bounds"] if out else []) + (["supervised"] if supervised else [])
        if not reasons:
            st.streak[key] = 0
            continue
        ANOMALIES.inc()
        for reason in reasons:
            REASONS.labels(reason).inc()
        st.streak[key] += 1
        log_event(log, "detector_anomaly", logging.WARNING, client=key, score=round(float(score), 4), streak=st.streak[key],
                  requests=len(by_key[key]), reasons=reasons, exceeded=out, attack_probability=round(float(proba), 3),
                  **{k: round(v, 3) for k, v in feats_by_key[key].items()})
        if st.streak[key] >= PERSIST and key not in st.blocked:
            service = target_service(by_key[key])
            st.blocked[key] = {"until": now + BLOCK_TTL, "score": float(score), "service": service, "since": now}
            BLOCKS.labels(service).inc()
            BLOCKED.set(len(st.blocked))
            log_event(log, "detector_blocked", logging.WARNING, client=key, score=round(float(score), 4), target_service=service,
                      ttl=BLOCK_TTL, reasons=reasons, exceeded=out, attack_probability=round(float(proba), 3))
            audit("detector", "traffic_blocked", actor=key[:64], outcome="denied", score=round(float(score), 4),
                  service=service, ttl_seconds=BLOCK_TTL, requests=len(by_key[key]), reasons=reasons, exceeded=out,
                  attack_probability=round(float(proba), 3))
            await alert(app, key, service, float(score), feats_by_key[key])
            if ML_BAN_IP:
                try:
                    ban_ip(st, key.partition("|")[0], "ml", f"Trafic anormal ({', '.join(reasons)}), service visé {service}",
                           BLOCK_TTL, client=key[:120], attack_probability=round(float(proba), 3))
                except BanError:
                    pass  # adresse partagée : le blocage par client (IP|agent) ci-dessus s'applique seul


async def loop(app: FastAPI) -> None:
    tick = 0
    while True:
        try:
            if tick % 12 == 0:
                refresh_allowlist(app.state.det)
            with EVAL_SECONDS.time():
                await evaluate(app)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # noqa: BLE001 - la boucle ne doit jamais mourir
            log_event(log, "detector_loop_error", logging.ERROR, error=repr(exc)[:200])
        tick += 1
        await asyncio.sleep(EVAL_INTERVAL)


async def startup(app: FastAPI) -> None:
    app.state.det = State()
    load_model(app.state.det)
    refresh_allowlist(app.state.det)
    app.state.http = httpx.AsyncClient()
    app.state.loki = loki._client()
    app.state.task = asyncio.create_task(loop(app))


async def shutdown(app: FastAPI) -> None:
    app.state.task.cancel()
    await app.state.http.aclose()
    app.state.loki.close()


app = create_app("detector", startup=startup, shutdown=shutdown)
router = APIRouter(prefix="/internal", tags=["detector"])


@router.get("/check", status_code=204, include_in_schema=True)
async def check(response: Response, x_client_key: str = Header(default=""), x_check_origin: str = Header(default="gateway")):
    """Appelé par la passerelle (auth_request) avant chaque requête : 403 si l'IP est bannie ou le client bloqué.
    L'en-tête X-Block-Reason (banned | anomaly) permet à la passerelle d'afficher le bon message."""
    st: State = app.state.det
    origin = x_check_origin if x_check_origin in ("waf", "gateway") else "gateway"
    ip = x_client_key.partition("|")[0]
    try:
        banned = st.bans.get(BanList.normalize(ip)) if ip else None
    except BanError:
        banned = None
    if banned:
        CHECKS.labels("banned", origin).inc()
        response.status_code = 403
        response.headers["X-Block-Reason"] = "banned"
        return None
    blocked = st.blocked.get(x_client_key)
    if blocked and blocked["until"] > time.time():
        CHECKS.labels("blocked", origin).inc()
        response.status_code = 403
        response.headers["X-Block-Reason"] = "anomaly"
        return None
    CHECKS.labels("allowed", origin).inc()
    return None


@router.get("/blocked")
async def list_blocked(_: dict = Depends(require_roles("admin", "service"))):
    now = time.time()
    return [{"client": k, "remaining_seconds": round(b["until"] - now), "score": b["score"], "service": b["service"]}
            for k, b in app.state.det.blocked.items()]


class UnblockIn(BaseModel):
    client: str


@router.post("/unblock")
async def unblock(body: UnblockIn, claims: dict = Depends(require_roles("admin", "service"))):
    removed = app.state.det.blocked.pop(body.client, None) is not None
    if removed:
        BLOCKED.set(len(app.state.det.blocked))
        log_event(log, "detector_unblocked", client=body.client, reason="manual", by=claims.get("sub"))
    return {"unblocked": removed}


@router.post("/reload")
async def reload_model(_: dict = Depends(require_roles("admin", "service"))):
    load_model(app.state.det)
    return {"loaded": app.state.det.bundle is not None}


# ───── API d'administration (rôle admin), exposée par la passerelle sous /api/security ─────
security = APIRouter(prefix="/api/security", tags=["security"])


class BanIn(BaseModel):
    ip: str = Field(min_length=2, max_length=45)
    reason: str = Field(min_length=3, max_length=200)
    duration_minutes: int | None = Field(default=None, ge=1, le=525600, description="vide = permanent")


def _who(claims: dict) -> str:
    return str(claims.get("username") or claims.get("sub") or "admin")


@security.get("/bans")
async def get_bans(_: dict = Depends(require_roles("admin", "service"))):
    """IP bannies (manuel, WAF, ML), les plus récentes d'abord."""
    return app.state.det.bans.listing()


@security.post("/bans", status_code=201)
async def post_ban(body: BanIn, claims: dict = Depends(require_roles("admin"))):
    ttl = None if body.duration_minutes is None else body.duration_minutes * 60
    try:
        return ban_ip(app.state.det, body.ip, "manual", body.reason, ttl, by=_who(claims))
    except BanError as exc:
        raise HTTPException(422, str(exc)) from None


@security.delete("/bans/{ip}")
async def delete_ban(ip: str, claims: dict = Depends(require_roles("admin"))):
    try:
        removed = unban_ip(app.state.det, ip, _who(claims), "manual")
    except BanError as exc:
        raise HTTPException(422, str(exc)) from None
    if not removed:
        raise HTTPException(404, "Cette IP n'est pas bannie")
    return {"unbanned": True}


@security.get("/blocks")
async def get_blocks(_: dict = Depends(require_roles("admin", "service"))):
    """Clients (IP et agent) bloqués temporairement par le modèle ML."""
    return await list_blocked(_)


@security.delete("/blocks")
async def delete_block(client: str, claims: dict = Depends(require_roles("admin"))):
    return await unblock(UnblockIn(client=client), claims)


app.include_router(router)
app.include_router(security)
