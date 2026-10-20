"""Liste des IP bannies : appliquée par la passerelle (via le détecteur), persistante, avec expiration.

Trois origines : « manual » (un administrateur), « waf » (rafale de requêtes bloquées par ModSecurity),
« ml » (client bloqué par le modèle). Un ban vise l'IP entière, quel que soit l'agent utilisateur.

Adresses jamais bannies (NEVER_BAN) : celles qui représentent PLUSIEURS clients. Sous Docker Desktop sans relais,
tous les clients extérieurs arrivent avec l'adresse de l'hôte vue par Docker (10.250.0.1) : la bannir couperait
tout le monde. Idem pour le front (10.250.0.10, tous les utilisateurs de l'interface) et le WAF lui-même.
"""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
import time
from pathlib import Path

SOURCES = ("manual", "waf", "ml")


class BanError(ValueError):
    """Ban refusé (adresse invalide ou protégée) : le message s'affiche tel quel à l'administrateur."""


class BanList:
    def __init__(self, path: Path, never_ban: list[str]) -> None:
        self.path = path
        self.never = [ipaddress.ip_network(n, strict=False) for n in never_ban if n.strip()]
        self.bans: dict[str, dict] = {}
        self.load()

    # ── persistance (un fichier JSON sur un volume ; écriture atomique) ──
    def load(self) -> None:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            self.bans = {b["ip"]: b for b in data if isinstance(b, dict) and "ip" in b}
        except FileNotFoundError:
            self.bans = {}
        except (ValueError, OSError):
            self.bans = {}  # fichier illisible : on repart d'une liste vide plutôt que de bloquer le démarrage
        self.purge()

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".bans-")
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(sorted(self.bans.values(), key=lambda b: b["created_at"]), f, ensure_ascii=False, indent=1)
        os.replace(tmp, self.path)

    # ── règles ──
    @staticmethod
    def normalize(ip: str) -> str:
        try:
            addr = ipaddress.ip_address(ip.strip())
        except ValueError:
            raise BanError(f"« {ip} » n'est pas une adresse IP valide") from None
        if addr.version == 6 and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return str(addr)

    def protected(self, ip: str) -> bool:
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self.never)

    def purge(self, now: float | None = None) -> list[str]:
        now = now or time.time()
        expired = [ip for ip, b in self.bans.items() if b.get("until") is not None and b["until"] <= now]
        for ip in expired:
            self.bans.pop(ip)
        return expired

    def get(self, ip: str) -> dict | None:
        b = self.bans.get(ip)
        if b and (b.get("until") is None or b["until"] > time.time()):
            return b
        return None

    def add(self, ip: str, source: str, reason: str, ttl_seconds: float | None, by: str | None = None) -> dict:
        ip = self.normalize(ip)
        if self.protected(ip):
            raise BanError(f"{ip} est une adresse partagée (hôte Docker, front, WAF ou boucle locale) : la bannir "
                           "couperait plusieurs clients. Activer le relais d'IP réelle (EDGE_RELAY) puis bannir l'IP du client.")
        now = time.time()
        current = self.get(ip)
        until = None if ttl_seconds is None else now + ttl_seconds
        if current and (current.get("until") is None or (until is not None and current["until"] >= until)):
            return current  # déjà banni au moins aussi longtemps : on garde le ban existant
        ban = {"ip": ip, "source": source, "reason": reason[:200], "created_at": now, "until": until, "by": by}
        self.bans[ip] = ban
        self.save()
        return ban

    def remove(self, ip: str) -> bool:
        ip = self.normalize(ip)
        removed = self.bans.pop(ip, None) is not None
        if removed:
            self.save()
        return removed

    def listing(self) -> list[dict]:
        now = time.time()
        return [{**b, "remaining_seconds": None if b.get("until") is None else max(0, round(b["until"] - now))}
                for b in sorted(self.bans.values(), key=lambda b: b["created_at"], reverse=True)
                if b.get("until") is None or b["until"] > now]
