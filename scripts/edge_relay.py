#!/usr/bin/env python3
"""Relais TCP sur le PC Hôte : rend au WAF l'IP réelle des clients sous Docker Desktop.

Docker Desktop (Windows/macOS) remplace l'adresse source des connexions vers un port publié : le WAF verrait
tous les clients avec la même adresse (10.250.0.1), et bannir une IP bannirait tout le monde. Ce relais écoute
sur le réseau (8080, 8443), annonce l'adresse du client en tête de connexion (PROXY protocol v1), puis relaie
les octets tels quels vers les ports « relais » du WAF publiés en local (18080, 18443). Le TLS reste terminé
par le WAF : le relais ne voit jamais le contenu chiffré.

    python scripts/edge_relay.py            # lancé par scripts/start.ps1 quand EDGE_RELAY=true dans .env

Prérequis : dans .env, WAF_HTTP_BIND=127.0.0.1:28080 et WAF_HTTPS_BIND=127.0.0.1:28443 (le WAF libère 8080 et
8443 pour le relais). Bibliothèque standard uniquement. Sous Linux (Docker Engine), inutile : l'IP est déjà réelle.
"""

from __future__ import annotations

import argparse
import asyncio
import ipaddress
import logging
import signal

log = logging.getLogger("edge_relay")


def proxy_header(peer: tuple, local: tuple) -> bytes:
    """En-tête PROXY protocol v1 : « PROXY TCP4 <client> <local> <port client> <port local> »."""
    src, dst = ipaddress.ip_address(peer[0]), ipaddress.ip_address(local[0])
    if src.version == 6 and src.ipv4_mapped:
        src = src.ipv4_mapped
    if dst.version == 6 and dst.ipv4_mapped:
        dst = dst.ipv4_mapped
    if src.version != dst.version:  # client IPv4 sur une écoute IPv6 : adresse locale neutre de même famille
        dst = ipaddress.ip_address("0.0.0.0" if src.version == 4 else "::")
    family = "TCP4" if src.version == 4 else "TCP6"
    return f"PROXY {family} {src} {dst} {peer[1]} {local[1]}\r\n".encode()


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass


def handler(upstream_port: int):
    async def handle(client_r: asyncio.StreamReader, client_w: asyncio.StreamWriter) -> None:
        peer, local = client_w.get_extra_info("peername"), client_w.get_extra_info("sockname")
        try:
            up_r, up_w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", upstream_port), timeout=3)
        except (OSError, asyncio.TimeoutError) as exc:
            log.warning("WAF injoignable sur 127.0.0.1:%s (%s) pour %s", upstream_port, type(exc).__name__, peer[0])
            client_w.close()
            return
        up_w.write(proxy_header(peer, local))
        await asyncio.gather(pipe(client_r, up_w), pipe(up_r, client_w))

    return handle


async def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--host", default="0.0.0.0", help="adresse d'écoute (défaut : toutes)")
    p.add_argument("--map", action="append", metavar="ECOUTE:WAF",
                   help="port d'écoute:port relais du WAF (défaut : 8080:18080 et 8443:18443)")
    a = p.parse_args()
    mappings = [tuple(int(x) for x in m.split(":")) for m in (a.map or ["8080:18080", "8443:18443"])]

    servers = []
    for listen, upstream in mappings:
        servers.append(await asyncio.start_server(handler(upstream), a.host, listen))
        log.info("relais %s:%s -> WAF 127.0.0.1:%s (PROXY protocol)", a.host, listen, upstream)

    stop = asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            asyncio.get_running_loop().add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):  # Windows : Ctrl+C lève KeyboardInterrupt
            pass
    try:
        await stop.wait()
    finally:
        for s in servers:
            s.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
