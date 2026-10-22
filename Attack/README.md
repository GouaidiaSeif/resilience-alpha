# Attack/ — scripts d'attaque de la démonstration

Scripts lancés **depuis le PC Attaquant** (second poste ou VM Kali sur le réseau du laboratoire) pour éprouver les
défenses de la plateforme et filmer leur réaction (Grafana, page Sécurité, alertes Discord). **Usage strictement
limité au système fictif du consortium** (réseau `192.168.137.0/24`) : chaque script refuse une cible hors de ce
réseau sans confirmation explicite.

Ils complètent `ml/traffic.py` (générateur de trafic du laboratoire, côté serveur) : ici, le trafic vient d'une
**machine distincte**, avec sa **vraie adresse IP**, comme une attaque réelle (voir `docs/02-reprise-idempotence-ml.md`
§3.1 pour le relais d'IP réelle).

| Script | Attaque | Cible |
|---|---|---|
| `attack_auth.py` | Force brute (`bruteforce`) ou bourrage d'identifiants (`credential-stuffing`) | `POST /api/auth/login` |
| `attack_payments.py` | Déni de service volumétrique **authentifié** (comptes créés par le script, clés d'idempotence uniques pour forcer toute la logique métier) | `POST /api/payments` |

## Prérequis

Sur le PC Attaquant : Python 3.10+ et `aiohttp`.

```bash
pip install aiohttp
```

La **cible est la passerelle en HTTP sur le port 8080** (`http://<IP du PC Hôte>:8080`), pas le port HTTPS 8443 :
les scripts ne gèrent pas le certificat autosigné du WAF. L'IP du PC Hôte est celle affichée par `demarrer.cmd`
(« Depuis le réseau https://192.168.1.49:8443 » → utiliser `http://192.168.1.49:8080`).

> Les scripts refusent une cible hors du réseau `192.168.137.0/24` sans confirmation. Si votre réseau est un autre
> (ex. `192.168.1.x`), ils demandent de taper `oui` pour confirmer que c'est bien votre laboratoire autorisé.

## Utilisation

```bash
# Force brute sur le compte admin (mots de passe variés)
python3 attack_auth.py --target http://192.168.137.1:8080 --mode bruteforce --username admin --duration 30

# Bourrage d'identifiants (couples utilisateur/mot de passe aléatoires)
python3 attack_auth.py --target http://192.168.137.1:8080 --mode credential-stuffing --duration 30

# Déni de service sur les paiements : 5 comptes créés, 150 connexions concurrentes, 45 s
python3 attack_payments.py --target http://192.168.137.1:8080 --users 5 --concurrency 150 --duration 45
```

Chaque script affiche un récapitulatif des codes de réponse reçus (401, 403 WAF, 429 limite de débit, 5xx, latence
moyenne) et rappelle quoi regarder côté défense.

| Option | `attack_auth.py` | `attack_payments.py` |
|---|---|---|
| `--target` | URL de la passerelle, ex. `http://192.168.137.1:8080` (obligatoire) | idem |
| `--mode` | `bruteforce` (défaut) ou `credential-stuffing` | — |
| `--username` | compte ciblé en `bruteforce` (défaut `admin`) | — |
| `--users` | — | nombre d'identités créées (défaut 5) |
| `--concurrency` | connexions concurrentes (défaut 50) | connexions concurrentes (défaut 150) |
| `--duration` | secondes (défaut 30) | secondes (défaut 45) |

## Ce qu'on doit observer côté défense

| Couche | `attack_auth.py` | `attack_payments.py` |
|---|---|---|
| Passerelle / WAF | Limite 10 req/min sur le login → **429** ; au-delà du seuil de requêtes bloquées, **IP bannie** | Limite de débit par IP → **429** |
| auth | 5 échecs/min par IP et par compte → **429** ; temps de réponse constant | — |
| Détecteur ML | Bannit l'IP après ~10 s de trafic anormal | Bannit l'IP (inondation détectée) |
| Sonde / reprise | — | `canary_up` reste vert : les paiements de contrôle passent malgré la charge |
| Où regarder | Grafana « WAF et bans » et « Journaux et sécurité » ; page Sécurité ; alertes Discord | Grafana « Trafic et paiements » (latence p95, 5xx) et « Reprise autonome » (sonde) |

## Après le test

- Les connexions réussies de `attack_auth.py` doivent être **0** (identifiants aléatoires) ; sinon, vérifier qu'il
  ne s'agit pas d'une faille réelle.
- `attack_payments.py` crée des comptes `stress_…` et de nombreux paiements : ils restent dans la base. Remise à
  zéro complète : `docker compose down -v`.
- Lever un bannissement : page **Sécurité** du front (`https://localhost:8443/admin/security`), ou attendre son
  expiration (ML : 10 min ; WAF : 1 h).

> Ces scripts n'ont d'intérêt que contre **votre propre** plateforme de laboratoire. Les employer contre un
> système tiers est illégal.
