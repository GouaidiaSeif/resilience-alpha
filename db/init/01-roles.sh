#!/bin/bash
# Exécuté une seule fois par l'image postgres, à la création du volume.
# Un rôle et un schéma par service : un service compromis ne voit que ses propres données.
#
# Les rôles svc_* sont des GROUPES sans connexion ni mot de passe : ils portent les droits (02-schema.sql). Les
# services se connectent avec des identifiants TEMPORAIRES créés par Vault (moteur database), membres de leur
# groupe, supprimés à l'expiration du bail ou à l'arrêt du service. Aucun mot de passe de service n'existe à l'avance.
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE svc_auth          NOLOGIN;
CREATE ROLE svc_accounts      NOLOGIN;
CREATE ROLE svc_payments      NOLOGIN;
CREATE ROLE svc_notifications NOLOGIN;
CREATE ROLE svc_audit         NOLOGIN;

REVOKE ALL ON DATABASE ${POSTGRES_DB} FROM PUBLIC;
GRANT CONNECT ON DATABASE ${POSTGRES_DB}
  TO svc_auth, svc_accounts, svc_payments, svc_notifications, svc_audit;

CREATE SCHEMA auth;
CREATE SCHEMA accounts;
CREATE SCHEMA payments;
CREATE SCHEMA notifications;
CREATE SCHEMA audit;
SQL
