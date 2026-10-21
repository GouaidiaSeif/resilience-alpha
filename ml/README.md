# ml/ — détection d'anomalies (modèle hybride)

Explications complètes, résultats mesurés et limites : **`docs/02-reprise-idempotence-ml.md`, section 3**.

| Fichier | Rôle |
|---|---|
| `features.py` | Variables par client (`IP|agent`) et par fenêtre de 30 s, à partir du journal d'accès de la passerelle |
| `loki.py` | Lecture de ce journal dans Loki (direct depuis un conteneur, ou via le proxy Grafana depuis le PC) |
| `traffic.py` | Générateur de trafic (`BASE_URL`, HTTP ou HTTPS du WAF) : `normal` (base d'apprentissage) et attaques signées (`bruteforce`, `scan`, `enumeration`, `flood`, `payspam`, `stuffing`, option `--slow`) — **laboratoire uniquement** |
| `train.py` | Entraînement du modèle hybride : Isolation Forest + bornes (trafic normal) + classifieur supervisé (attaques étiquetées) → `model/model.joblib` + `model/model.json` |
| `model_io.py` | Chargement du modèle avec contrôle des versions de bibliothèques (détecteur et `evaluate.py`) |
| `bans.py` | Liste des IP bannies (manuel, WAF, ML) : persistance, expiration, adresses partagées protégées (docs/02 §3.14) |
| `compare.py` | Banc d'essai : IF, IF + bornes, ECOD, LOF, One-Class SVM, supervisé, hybrides (docs/02 §3.6) |
| `evaluate.py` | Taux de détection par attaque et taux de faux positifs |
| `detector.py` | Service temps réel : note le trafic toutes les 5 s, bloque et bannit, bannit après une rafale de blocages du WAF, alerte la remédiation, trace dans l'audit ; API `/api/security/*` de la liste des bans |
| `Dockerfile` | Image du détecteur, lancé avec la pile (service `detector` de `docker-compose.yml`) ; la passerelle le consulte avant chaque requête (`auth_request`) |

## Ce qui est publié dans le dépôt

| Fichier | Contenu |
|---|---|
| `model/model.joblib` | **Le modèle entraîné** (forêt, seuil, bornes, classifieur). Chargé tel quel par le détecteur : rien à entraîner pour lancer la pile |
| `model/model.json` | Ses métadonnées lisibles : variables, seuil, bornes, types d'attaque appris, **versions des bibliothèques**, **fichier de données et son empreinte sha256** |
| `data/train.jsonl` | **Les données d'entraînement** : 3 502 lignes du journal d'accès de la passerelle (19 min le 2026-10-19), trafic de laboratoire uniquement (8 utilisateurs simulés, la sonde, 5 attaques étiquetées `rsl-attack-…`), adresses Docker internes, aucun secret |
| `requirements.txt` | Dépendances des scripts sur le PC, **plages larges** (Python 3.10 ou plus récent) |
| `requirements-lock.txt` | **Versions exactes** de l'entraînement du modèle publié ; installées par l'image Docker du détecteur |

Le modèle est un pickle scikit-learn : il ne se recharge de façon fiable qu'avec les versions de son entraînement
(dans `model.json`, clé `versions`). L'image Docker les installe, donc le détecteur fonctionne partout. Sur un PC
avec d'autres versions, `evaluate.py` charge quand même le modèle et l'indique (« Attention, versions
différentes… ») ; pour des résultats identiques, installer `requirements-lock.txt` (Python 3.11+) ou
ré-entraîner localement depuis `data/train.jsonl`.

## Installer

```bash
python -m venv ml/.venv
ml/.venv/Scripts/pip install -r ml/requirements.txt          # Linux/macOS : ml/.venv/bin/pip
# ou, pour les versions exactes du modèle publié (Python 3.11+) :
ml/.venv/Scripts/pip install -r ml/requirements-lock.txt
```

Vérifié sur une installation propre : Python 3.10 (scikit-learn 1.7, numpy 2.2, pandas 2.3), 3.11 (versions
exactes) et 3.14 (scikit-learn 1.9, numpy 2.5, pandas 3.0).

## Utiliser le modèle publié (sans la pile)

```bash
# Ré-entraîner depuis les données publiées : même seuil (-0.6803), mêmes bornes, mêmes scores (random_state fixé)
ml/.venv/Scripts/python ml/train.py --from-file ml/data/train.jsonl
# Évaluer un modèle sur un fichier de journal (ici les données d'entraînement : contrôle de cohérence seulement)
ml/.venv/Scripts/python ml/evaluate.py --from-file ml/data/train.jsonl
```

Pour une vraie mesure, évaluer sur une **autre** période que l'entraînement (docs/02 §3.4, étape 6).

## Entraîner sur sa propre pile

```bash
export LOKI_URL=http://localhost:3000/api/datasources/proxy/uid/loki GRAFANA_USER=admin GRAFANA_PASSWORD=$(python scripts/secrets.py get grafana admin_password)
docker compose stop detector        # pendant la collecte : sinon les attaques simulées sont bloquées (403) et faussent les données
ml/.venv/Scripts/python ml/traffic.py normal --users 8 --duration 900   # 15 min de trafic légitime
for a in scan enumeration flood payspam bruteforce; do ml/.venv/Scripts/python ml/traffic.py $a --duration 45; done
ml/.venv/Scripts/python ml/train.py --since 25m --save-data ml/data/train.jsonl
docker compose start detector       # recharge model/model.joblib au démarrage
```

Pour publier un nouveau modèle : commiter `model/model.joblib`, `model/model.json` et `data/train.jsonl`
ensemble, et reporter dans `requirements-lock.txt` les versions de `model.json` (sinon l'image Docker ne les aura
pas). Les autres fichiers de `model/` et `data/` restent locaux (`ml/.gitignore`).

Suivi : tableau Grafana « Détection ML » (http://localhost:3000/d/ra-detection) et alertes Discord (docs/02 §3.13).
