# Secrets : HashiCorp Vault

Toutes les valeurs secrètes de la plateforme (clé de signature des jetons, mots de passe, webhook Discord, accès à
la base) sont gardées par **HashiCorp Vault 2.1.2**. Plus aucun secret dans `.env`, dans `docker-compose.yml` ou
dans l'environnement des conteneurs. Ce document explique le fonctionnement, l'usage courant, la résilience et les
limites du montage de laboratoire.

## Sommaire

1. [Avant / après](#1-avant--après)
2. [Architecture](#2-architecture)
3. [Où est chaque secret](#3-où-est-chaque-secret)
4. [Identifiants PostgreSQL temporaires](#4-identifiants-postgresql-temporaires)
5. [Résilience](#5-résilience)
6. [Usage courant](#6-usage-courant)
7. [Migration d'une installation existante](#7-migration-dune-installation-existante)
8. [Limites du laboratoire et cible de production](#8-limites-du-laboratoire-et-cible-de-production)
9. [Dépannage](#9-dépannage)

---

## 1. Avant / après

| Avant | Avec Vault |
|---|---|
| 11 secrets en clair dans `.env` (JWT, mots de passe des 5 rôles de base, admin, sonde, Grafana, webhook) | `.env` ne contient que de la configuration (niveau de log, plafond de paiement, fuseau, WAF) |
| Chaque conteneur reçoit ses secrets par l'environnement (visibles avec `docker inspect`) | Chaque service se connecte à Vault avec **sa propre identité** et ne peut lire **que ses** secrets |
| Un mot de passe PostgreSQL fixe par service, valable indéfiniment | **Identifiants PostgreSQL temporaires** : créés au démarrage du service, valables 1 h, renouvelés, supprimés à son arrêt |
| Aucune trace des lectures de secrets | **Journal d'audit Vault** : chaque accès (qui, quoi, quand ; valeurs hachées) dans Loki `{service="vault"}` |
| Changer un secret = éditer `.env` | `python scripts/secrets.py set …` ou interface web ; chaque modification est une nouvelle version, l'ancienne reste consultable |

## 2. Architecture

```
                       ┌──────────────────────────── Vault (rsl-vault, mode serveur, volume vault-data) ───────────────┐
 vault-keeper ──init, descellement, configuration──► KV « secret/resilience/* »   AppRole   moteur database   audit ──► Loki
 (infra/vault/keeper.py)                              │                            │          │
      │ écrit dans .vault/ (PC Hôte, hors Git)        │ lecture selon la politique │ login    │ CREATE ROLE … VALID UNTIL …
      ├── init.json : clé de descellement, jeton racine                            │          ▼
      ├── approle/<service>/role_id, secret_id ───────► chaque service ────────────┘     PostgreSQL
      └── rendered/postgres, rendered/grafana ────────► PostgreSQL, Grafana (ne savent pas parler à Vault)
```

| Composant | Rôle |
|---|---|
| `vault` | Serveur Vault (stockage Raft persistant, volume `vault-data`), **scellé à chaque démarrage**. Interface web et API d'administration sur `http://127.0.0.1:8200` (PC Hôte uniquement). Configuration : `infra/vault/vault.hcl` |
| `vault-keeper` | Gardien (`infra/vault/keeper.py`, bibliothèque standard Python) : initialise Vault la première fois, le descelle, configure tout de façon idempotente, crée les secrets absents, écrit les identités des services, puis **redescelle Vault s'il redémarre** (contrôle toutes les 5 s) |
| `resilience_common/vault.py` | Côté services : au démarrage, connexion AppRole, lecture des secrets autorisés, identifiant PostgreSQL temporaire ; renouvellement en arrière-plan ; révocation à l'arrêt. Sans `VAULT_ADDR` (tests, développement), lit l'environnement comme avant |

**Séquence de démarrage** (`demarrer.cmd`) : `vault` démarre scellé → `vault-keeper` le descelle et le configure,
puis se déclare prêt → PostgreSQL et Grafana démarrent (leurs fichiers de secrets sont écrits) → chaque service se
connecte à Vault, lit ses secrets, obtient son identifiant de base, puis démarre normalement.

**Une identité et une politique par service** (moindre privilège) : par exemple `payments` ne peut lire que la clé
de signature partagée et ses propres identifiants de base :

```hcl
path "secret/data/resilience/shared" { capabilities = ["read"] }
path "database/creds/payments" { capabilities = ["read"] }
path "sys/leases/renew" { capabilities = ["update"] }
path "sys/leases/revoke" { capabilities = ["update"] }
```

Un service compromis ne peut lire ni le mot de passe admin, ni celui de Grafana, ni les identifiants des autres
services. Les politiques sont générées par `keeper.py` (fonction `policy`) et vérifiées par `tests/test_vault.py`.

## 3. Où est chaque secret

| Chemin Vault (KV v2) | Clés | Lu par |
|---|---|---|
| `secret/resilience/shared` | `jwt_secret` | tous les services, le détecteur (variable `JWT_SECRET`) |
| `secret/resilience/auth` | `admin_password` | auth (création du compte `admin`) |
| `secret/resilience/canary` | `canary_password` | la sonde (compte `canary-bot`) |
| `secret/resilience/grafana` | `admin_password`, `discord_webhook_url` | Grafana, via des fichiers rendus par vault-keeper |
| `secret/resilience/postgres` | `admin_password` | PostgreSQL (initialisation du volume) et le moteur database de Vault |
| `database/creds/<service>` | utilisateur et mot de passe **temporaires** | auth, accounts, payments, notifications, audit |
| `database/creds/readonly` | utilisateur temporaire en lecture seule (1 h) | les humains (DBeaver) |

Au premier démarrage, chaque secret absent est **repris de l'ancien `.env`** s'il y figure (migration), sinon
**généré aléatoirement**. Un secret existant n'est jamais remplacé par vault-keeper.

## 4. Identifiants PostgreSQL temporaires

Les rôles `svc_auth`, `svc_accounts`… sont des **groupes sans connexion ni mot de passe** : ils portent les droits
(`db/init/02-schema.sql`). À son démarrage, un service demande à Vault un identifiant ; Vault crée dans PostgreSQL :

```sql
CREATE ROLE "v-approle-payments-…" WITH LOGIN PASSWORD '…' VALID UNTIL '<+1 h>' IN ROLE svc_payments;
```

- l'utilisateur hérite exactement des droits du service (ni plus, ni moins) ;
- le service renouvelle son bail toutes les 20 min (validité 1 h, 30 jours au plus) ;
- à l'arrêt du service, le bail est révoqué : sessions coupées, utilisateur supprimé **immédiatement** ;
- si le service meurt sans prévenir, l'utilisateur disparaît au plus tard 1 h après.

Mesuré le 2026-10-21 : `rsl-payments` arrêté ⇒ son utilisateur `v-approle-payments-Yz7m…` supprimé dans la
seconde ; la sonde détecte la panne, la remédiation redémarre le service, qui obtient un **nouvel** utilisateur
(`v-approle-payments-m7wI…`), puis la transaction de contrôle réussit (incident résolu en 2 s après la détection).

## 5. Résilience

| Situation | Comportement | Vérifié |
|---|---|---|
| Vault redémarre (il revient **scellé**) | vault-keeper le descelle en moins de 5 s (`vault_resealed_recovered`) | oui, 2026-10-21 |
| Un service redémarre (remédiation) | Il se reconnecte avec son identité AppRole et obtient de nouveaux identifiants | oui, 2026-10-21 |
| Vault indisponible pendant que les services tournent | Rien ne change pour eux (jeton et identifiants valides 1 h) ; le renouvellement réessaie | par construction |
| Vault indisponible quand un service démarre | Le service attend jusqu'à 3 min (`vault_waiting`), puis échoue ; la remédiation le relancera | par construction |
| Démarrage à froid de la pile (services en attente de Vault) | La sonde n'alerte pas tant qu'aucune transaction n'a réussi (2 min au plus) : pas de redémarrage en plein démarrage, donc pas d'identifiant orphelin. Un processus arrêté pendant son démarrage révoque quand même son bail | oui, 2026-10-21 (0 remédiation au démarrage, 1 utilisateur par service) |
| Vault scellé plus de 30 s | Alerte Grafana « Vault scellé ou arrêté » (Discord) ; état dans le tableau « Reprise autonome » | règle provisionnée |

## 6. Usage courant

```bash
python scripts/secrets.py show                       # identifiants de connexion (front, Grafana), état du webhook
python scripts/secrets.py set grafana discord_webhook_url https://discord.com/api/webhooks/...
docker compose restart grafana                       # Grafana relit ses secrets au démarrage (fichier rendu en 30 s)
python scripts/secrets.py get auth                   # contenu d'un chemin secret/resilience/<nom>
python scripts/secrets.py db-creds                   # utilisateur PostgreSQL temporaire en lecture seule (DBeaver)
python scripts/secrets.py token                      # jeton pour l'interface web http://127.0.0.1:8200
```

**Interface web** : `http://127.0.0.1:8200`, méthode « Token », jeton donné par `python scripts/secrets.py token`.
Secrets sous `secret/resilience/`, identités sous « Access > Auth Methods > approle », politiques sous « Policies »,
baux actifs (identifiants de base) sous « Access > Leases ».

**Changer un secret partagé** (ex. la clé JWT) : `secrets.py set shared jwt_secret <nouvelle valeur>`, puis
redémarrer tous les services (`docker compose restart`) : les jetons signés avec l'ancienne clé deviennent invalides.

**Audit** : Grafana > Explore > Loki : `{service="vault"} |= "request"` (chaque appel, avec l'identité appelante ;
les valeurs secrètes sont remplacées par leur empreinte HMAC).

## 7. Migration d'une installation existante

Rien à faire : au premier `demarrer.cmd` après la mise à jour, vault-keeper importe les secrets présents dans `.env`
(mêmes mots de passe, mêmes comptes, base intacte). Ensuite :

- les rôles `svc_*` perdent leur mot de passe fixe et leur droit de connexion (première création d'identifiant
  temporaire) : les anciens mots de passe de `.env` ne servent plus à rien ;
- les lignes secrètes de `.env` peuvent être supprimées : copier `.env.example` vers `.env` en gardant la
  configuration. Elles ne sont plus jamais relues (un secret déjà dans Vault n'est pas réimporté).

Migration réalisée sur le poste de développement le 2026-10-21 : secrets importés, données conservées (comptes,
paiements, piste d'audit intègre), parcours complet de l'interface 35/35, page Sécurité 11/11, `smoke.py` OK.

## 8. Limites du laboratoire et cible de production

| Laboratoire | Production |
|---|---|
| Une seule part de clé de descellement, gardée sur le PC Hôte (`.vault/init.json`) avec le jeton racine | Descellement automatique par KMS/HSM (cloud ou matériel) ; parts réparties entre plusieurs personnes (ex. 3 sur 5) ; jeton racine révoqué après l'installation |
| HTTP entre les conteneurs et Vault (réseau Docker interne) | TLS partout, certificats renouvelés |
| `secret_id` AppRole sans expiration (renouvelé à chaque démarrage de la pile) | `secret_id` à usage unique, livré emballé (« response wrapping ») par l'orchestrateur |
| Vault se connecte à PostgreSQL avec le super-utilisateur `pgadmin` | Rôle dédié `CREATEROLE` et `rotate-root` : son mot de passe n'est connu que de Vault |
| PostgreSQL et Grafana lisent des fichiers rendus par vault-keeper | Vault Agent en conteneur annexe, ou intégrations natives |
| Clé JWT HS256 partagée par tous les services | Moteur `transit` ou clés asymétriques par service : seul auth signe |
| Un seul nœud Vault | Cluster Raft de 3 ou 5 nœuds |

## 9. Dépannage

| Symptôme | Cause et solution |
|---|---|
| `vault_keys_missing` dans les journaux de vault-keeper | Vault est initialisé mais `.vault/init.json` a disparu : sans la clé, ses données sont perdues. Repartir de zéro : `docker compose down -v` puis `demarrer.cmd` (base de données réinitialisée aussi) |
| Un service reste en démarrage avec `vault_waiting` | Vault scellé ou en cours de configuration : `docker compose logs vault-keeper` |
| `python scripts/secrets.py` : « Vault injoignable » | La plateforme n'est pas lancée, ou le port 8200 est pris |
| Grafana n'envoie plus sur Discord après un changement de webhook | `docker compose restart grafana` (il relit le fichier au démarrage) |
| Remise à zéro complète | `docker compose down -v` (base, bans, Vault) puis supprimer le dossier `.vault/` |
