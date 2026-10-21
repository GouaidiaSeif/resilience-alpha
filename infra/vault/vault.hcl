# Serveur Vault de RESILIENCE-ALPHA (mode serveur, pas -dev) : secrets persistants, scellé au démarrage.
# Initialisé, descellé et configuré par infra/vault/keeper.py (service vault-keeper). Voir docs/03-secrets-vault.md.

storage "raft" {
  path    = "/vault/file"
  node_id = "rsl-vault-1"
}

# Réseau interne de la pile ; publié sur 127.0.0.1:8200 uniquement (interface web et API d'administration).
# TLS désactivé : en laboratoire, le trafic ne quitte pas le PC Hôte. En production : certificat et tls_disable = false.
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = true

  telemetry {
    unauthenticated_metrics_access = true   # /v1/sys/metrics lisible par Prometheus (aucun secret n'y figure)
  }
}

api_addr     = "http://vault:8200"
cluster_addr = "http://vault:8201"
ui           = true

# Docker Desktop ne donne pas IPC_LOCK : sans mlock, la mémoire de Vault peut partir en swap (accepté en laboratoire).
disable_mlock = true

telemetry {
  prometheus_retention_time = "60s"
  disable_hostname          = true
}
