"""Génère les règles d'alerte Grafana provisionnées de RESILIENCE-ALPHA.

    python infra/grafana/build_alerts.py          # réécrit provisioning/alerting/rules.json
    docker compose restart grafana                # les règles sont lues au démarrage

Livraison : point de contact Discord et politique de routage dans provisioning/alerting/discord.yml.
Les sources sont celles des tableaux : Prometheus (métriques) et Loki (événements JSON des services).

Aucun « $ » dans ce fichier : Grafana interpole les variables d'environnement dans les fichiers provisionnés.
Les modèles d'annotation utilisent donc .Labels et .Value, pas $labels et $value.
"""
import json
import sys
from pathlib import Path

OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(__file__).resolve().parent / "provisioning" / "alerting" / "rules.json"
OUT.parent.mkdir(parents=True, exist_ok=True)

PROM, LOKI = "prometheus", "loki"
FOLDER = "Resilience Alpha"
GRAFANA_URL = "http://localhost:3000"   # = GF_SERVER_ROOT_URL (docker-compose.yml)


def rule(uid, title, ds, expr, op, threshold, summary, description, severity, dashboard, for_="0s", window=300):
    """Règle à une requête : A (requête) -> B (dernière valeur) -> C (seuil). Une série = une alerte."""
    query = {"refId": "A", "expr": expr, "instant": True, "range": False, "intervalMs": 1000, "maxDataPoints": 43200}
    if ds == LOKI:
        query["queryType"] = "instant"
    return {
        "uid": uid,
        "title": title,
        "condition": "C",
        "data": [
            {"refId": "A", "relativeTimeRange": {"from": window, "to": 0}, "datasourceUid": ds, "model": query},
            {"refId": "B", "datasourceUid": "__expr__",
             "model": {"refId": "B", "type": "reduce", "expression": "A", "reducer": "last", "settings": {"mode": "dropNN"}}},
            {"refId": "C", "datasourceUid": "__expr__",
             "model": {"refId": "C", "type": "threshold", "expression": "B",
                       "conditions": [{"evaluator": {"type": op, "params": [threshold]}}]}},
        ],
        # Pas de données = rien d'anormal (aucun événement compté). Erreur de requête : on garde l'état précédent
        # plutôt que d'alerter ; une source réellement arrêtée est couverte par sa propre règle.
        "noDataState": "OK",
        "execErrState": "KeepLast",
        "for": for_,
        # Lien direct vers le tableau (Grafana exige un panneau précis avec __dashboardUid__ : on garde un simple lien).
        "annotations": {"summary": summary, "description": description, "dashboard_url": f"{GRAFANA_URL}/d/{dashboard}"},
        "labels": {"severity": severity},
        "isPaused": False,
    }


security = [
    rule("ra-attack-blocked", "Attaque bloquée par le détecteur ML", LOKI,
         'sum by (client, target_service) (count_over_time({service="detector"} | json | event="detector_blocked" [1m]))', "gt", 0,
         "Client {{ .Labels.client }} bloqué à la passerelle (service visé : {{ .Labels.target_service }}).",
         "Le détecteur ML l'a jugé anormal deux évaluations de suite : toutes ses requêtes reçoivent 403 pendant 10 min. "
         "Détails (motifs, variables hors bornes) : audit « traffic_blocked » et tableau Détection ML.",
         "critical", "ra-detection", window=120),
    rule("ra-bruteforce", "Force brute sur la connexion", LOKI,
         'sum by (client_ip) (count_over_time({service="auth"} | json | event=~"login_failed|login_blocked" [2m]))', "gt", 9,
         "{{ printf `%.0f` .Values.B.Value }} échecs de connexion en 2 min depuis {{ .Labels.client_ip }}.",
         "Le service auth bloque déjà 5 échecs par minute et par IP (429). Vérifier les identifiants visés dans "
         "« Journaux et sécurité » (tableau des échecs par IP et identifiant).",
         "high", "ra-logs", window=180),
    rule("ra-waf-attack", "Attaque bloquée par le WAF", LOKI,
         'sum by (client_ip) (count_over_time({service="waf"} |= `"is_interrupted":true` | json client_ip="transaction.client_ip" [1m]))', "gt", 2,
         "{{ printf `%.0f` .Values.B.Value }} requêtes bloquées par ModSecurity en 1 min depuis {{ .Labels.client_ip }}.",
         "Contenu malveillant (injection SQL, XSS, fichier sensible, outil de scan…). Après 5 blocages en 2 min, l'IP est "
         "bannie 1 h automatiquement. Règles déclenchées : tableau « WAF et bans ».",
         "high", "ra-waf", window=120),
    rule("ra-ip-banned", "Adresse IP bannie", LOKI,
         'sum by (ip, source) (count_over_time({service="detector"} | json | event="detector_ip_banned" | source!="ml" [1m]))', "gt", 0,
         "{{ .Labels.ip }} bannie (origine : {{ .Labels.source }}).",
         "Toutes ses requêtes reçoivent 403, interface comprise. Lever le ban : front, Administration > Sécurité. "
         "(Les bans décidés par le modèle ML sont signalés par « Attaque bloquée par le détecteur ML ».)",
         "critical", "ra-waf", window=120),
    rule("ra-rate-limited", "Limitation de débit déclenchée", LOKI,
         'sum by (client_ip, user_agent) (count_over_time({service="waf"} |= `"source":"waf"` | json | __error__="" | status="429" [1m]))', "gt", 5,
         "{{ printf `%.0f` .Values.B.Value }} requêtes refusées (429) en 1 min pour {{ .Labels.client_ip }} ({{ .Labels.user_agent }}).",
         "Au-delà de 20 requêtes/s par IP (WAF) ou de 10 connexions par minute (passerelle) : déni de service ou force "
         "brute volumétrique probable.",
         "high", "ra-waf", window=120),
    rule("ra-scan", "Balayage (rafale de 404)", LOKI,
         'sum by (client_ip, user_agent) (count_over_time({service="waf"} |= `"source":"waf"` | json | __error__="" | status="404" [1m]))', "gt", 20,
         "{{ printf `%.0f` .Values.B.Value }} réponses 404 en 1 min pour {{ .Labels.client_ip }} ({{ .Labels.user_agent }}).",
         "Recherche de routes cachées. Règle indépendante du ML : elle alerte même si le détecteur est arrêté.",
         "high", "ra-waf", window=120),
    rule("ra-audit-chain", "Piste d'audit altérée", LOKI,
         'sum(count_over_time({service="audit"} | json | event="audit_chain_broken" [5m]))', "gt", 0,
         "La chaîne de hachage de l'audit est rompue : un événement a été modifié ou supprimé.",
         "Ne rien redémarrer, conserver les preuves. Vérifier depuis le front (Audit, « Vérifier la chaîne ») ou /api/audit/verify.",
         "critical", "ra-logs", window=360),
    rule("ra-data-inconsistent", "Soldes incohérents avec le ledger", PROM,
         "min(canary_data_consistent)", "lt", 1,
         "Le solde d'au moins un compte ne correspond plus à la somme de ses écritures.",
         "Corruption ou manipulation des données : restauration à partir des écritures requise (PRA).",
         "critical", "ra-recovery", for_="10s", window=60),
    rule("ra-detector-down", "Détecteur ML arrêté", PROM,
         'max(up{job="detector"}) or vector(0)', "lt", 1,
         "Le détecteur ML ne répond plus : la passerelle laisse passer tout le trafic (ouverture par défaut).",
         "Les règles de 404, 429 et force brute continuent d'alerter. Relancer : docker compose up -d detector.",
         "high", "ra-detection", for_="30s", window=60),
    rule("ra-detector-no-model", "Détecteur ML sans modèle", PROM,
         "max(detector_model_loaded)", "lt", 1,
         "Le détecteur tourne sans modèle (ml/model/model.joblib absent) : il ne bloque rien.",
         "Entraîner le modèle (docs/02, section 3.4) puis POST /internal/reload ou docker compose restart detector.",
         "warning", "ra-detection", for_="1m", window=120),
]

availability = [
    rule("ra-service-down", "Service indisponible", PROM,
         'up{job="services"}', "lt", 1,
         "Le service {{ .Labels.service }} ne répond plus.",
         "La sonde alerte le moteur de remédiation, qui redémarre le conteneur puis prouve la reprise. "
         "Une alerte « résolue » suit en général en moins d'une minute.",
         "high", "ra-recovery", for_="15s", window=60),
    rule("ra-canary-failing", "Paiement de contrôle en échec", PROM,
         "min(canary_up)", "lt", 1,
         "La transaction de contrôle (paiement réel via la passerelle) échoue depuis 20 s.",
         "La plateforme n'est pas utilisable de bout en bout. Voir « Reprise autonome » pour le service en cause.",
         "high", "ra-recovery", for_="20s", window=60),
    rule("ra-remediation-failed", "Remédiation en échec", LOKI,
         'sum by (target_service, state) (count_over_time({service="remediation"} | json | event="remediation_step" | state=~"failed|suppressed" [2m]))', "gt", 0,
         "Remédiation de {{ .Labels.target_service }} : {{ .Labels.state }}. Intervention humaine requise.",
         "failed : service toujours indisponible ou transaction de contrôle en échec après redémarrage. "
         "suppressed : disjoncteur ouvert (trop de redémarrages en 10 min).",
         "critical", "ra-recovery", window=180),
    rule("ra-5xx-rate", "Taux d'erreurs serveur élevé", PROM,
         'sum(rate(http_requests_total{service=~"auth|accounts|payments|notifications|audit", path!~"/ready|/health|/metrics", status=~"5.."}[1m]))'
         ' / sum(rate(http_requests_total{service=~"auth|accounts|payments|notifications|audit", path!~"/ready|/health|/metrics"}[1m]))',
         "gt", 0.05,
         "Plus de 5 % des réponses des services métier sont des erreurs 5xx.",
         "Voir « Trafic et paiements » (5xx par service) : souvent un service appelé est en panne.",
         "warning", "ra-traffic", for_="1m", window=120),
]

doc = {
    "apiVersion": 1,
    "groups": [
        {"orgId": 1, "name": "Sécurité", "folder": FOLDER, "interval": "10s", "rules": security},
        {"orgId": 1, "name": "Disponibilité", "folder": FOLDER, "interval": "10s", "rules": availability},
    ],
}
text = json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
assert "$" not in text, "« $ » serait interpolé par Grafana"
OUT.write_text(text, encoding="utf-8")
print(OUT, len(security) + len(availability), "règles")
