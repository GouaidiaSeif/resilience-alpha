# Front RESILIENCE-ALPHA (Next.js)

Interface client et de supervision de la plateforme de paiement fictive. Elle consomme uniquement l'API de la
passerelle (`/api/*`) et n'invente aucune fonctionnalité absente du backend.

| Pour qui | Écrans |
|---|---|
| Client | Connexion, inscription, vue d'ensemble, comptes (liste, ouverture, détail), paiements (historique filtrable, nouveau paiement avec vérification, détail), notifications |
| Administrateur | Les mêmes, plus **Supervision** (état des services en direct, incidents de remédiation), **Journal d'audit** (filtres, vérification de la chaîne) et **Sécurité** (liste des bans : bannir, débannir ; clients bloqués par le modèle ML) |

## Démarrage

Le front fait partie de la pile : `scripts/start.ps1` (ou `docker compose up -d --build` à la racine) construit
l'image (`frontend/Dockerfile`, sortie Next.js « standalone ») et lance le conteneur `rsl-frontend`. On y accède
**par le WAF** : https://localhost:8443 (certificat autosigné), ou `https://<IP du PC Hôte>:8443` depuis un autre
poste. Le port 3001 n'est publié qu'en local (http://127.0.0.1:3001, débogage sans WAF). Dans Docker, le front
joint la passerelle par `http://gateway:8080` sur le réseau `web`, avec l'adresse fixe `10.250.0.10` que le
détecteur ML ne bloque jamais.

**Ajouter une page** : le WAF ne transmet au front que ses pages connues. Ajouter la route à la liste de
`waf/includes/waf_routes.conf.template` (sinon elle répond « Page introuvable »), puis `docker compose restart waf`.

Développement (rechargement à chaud), pile démarrée :

```bash
docker compose stop frontend    # libère le port 3001
cd frontend
npm install
cp .env.example .env.local      # GATEWAY_URL=http://localhost:8080 par défaut
npm run dev                     # http://localhost:3001
```

Hors Docker, le front n'a plus l'adresse exemptée : un usage intensif de l'interface peut être noté par le
détecteur ML comme n'importe quel client. Contrôles : `npm run typecheck`, `npm run lint`.

Compte administrateur : `admin` / `ADMIN_PASSWORD` du `.env` racine.

## Architecture

```
Navigateur ──► WAF (:8443) ──► Next.js (:3001) ──► passerelle Nginx (interne) ──► services
               · jeton JWT dans un cookie httpOnly (ra_session), jamais lisible par le JavaScript de la page
               · Server Components pour les lectures, Server Actions pour les écritures
               · /bff/health : vérification des services pour la page Supervision (admin)
```

- Pas de CORS nécessaire : le navigateur ne parle qu'au serveur Next.js.
- `src/proxy.ts` (ex-middleware) redirige vers `/login` quand le jeton est absent ou expiré (15 min, sans
  renouvellement) et renvoie ensuite vers la page demandée.
- Tous les appels passent par `src/lib/api.ts` : délai maximal, résultat typé, 401 → reconnexion, et erreurs
  classées (`unavailable` pour 502/503/504, `unreachable` si la passerelle ne répond pas…).
- Chaque section d'une page charge ses données séparément (Suspense) : un service en panne n'empêche pas
  d'afficher le reste, et l'erreur nomme le service concerné avec la référence `x-request-id`.

### Paiement : idempotence et pannes

La clé `Idempotency-Key` est générée côté serveur pour chaque intention de paiement et affichée à l'étape de
vérification.

| Réponse de la plateforme | Comportement de l'interface |
|---|---|
| 201 `completed` | Détail du paiement, bannière de succès |
| 201 `failed` | Reste sur le formulaire, raison en clair, **nouvelle clé** |
| 503 `pending` (ledger en panne) | Détail du paiement « en cours », actualisé toutes les 5 s jusqu'au règlement par le réconciliateur |
| 502 / 504 / délai dépassé | Bouton « Réessayer » avec **la même clé** : aucun double débit possible |
| 422 | Erreur rattachée au champ (plafond, format, comptes identiques) |

Modifier un champ après un envoi génère une nouvelle clé (nouvelle intention).

### Supervision

- **Services** : toutes les 5 s, le serveur Next.js fait une lecture authentifiée par service via la passerelle
  (`src/app/bff/health/route.ts`). Réponse < 500 = opérationnel ; 502/503/504 ou délai = indisponible.
  L'historique (2 min) n'existe que dans l'onglet ouvert. Bouton pause.
- **Incidents** : reconstitués depuis la piste d'audit du service `remediation` (`incident_opened` →
  `incident_resolved|failed|escalated|suppressed`). Le détail étape par étape reste interne (`/internal/*` non routé).
- Grafana reste le tableau de bord de référence pour les métriques (dashboards provisionnés, voir README racine 10.6).

### Journal d'audit : sonde masquée

La sonde (`canary-bot`) inscrit un paiement de contrôle toutes les 5 s et noierait le journal. Elle est **masquée par
défaut** (filtre « Sonde », `?probe=show` pour l'afficher). L'API d'audit ne sait pas exclure un acteur : le front lit
les 500 derniers événements, retire ceux de la sonde, puis affiche la limite choisie, avec le décompte. La sonde agit
sous deux identités : son nom (connexions) et son UUID (paiements, comptes), retrouvé dans son événement
`user_registered`. En mode affiché, ses lignes portent l'acteur « Sonde ».

## Design system

Voir `design-system/resilience-alpha/` :

- `MASTER.md` : direction visuelle, jetons de couleur (contrastes vérifiés), typographie, espacements,
  composants, accessibilité, anti-patterns, checklist.
- `PRODUCT.md` : correspondance capacités backend → écrans, architecture de l'information, parcours, états à gérer.

Les jetons sont implémentés dans `src/app/globals.css`. La palette Tailwind par défaut est désactivée : seules
les classes sémantiques existent (`bg-surface`, `text-fg-muted`, `bg-primary`, `text-danger`…). Composants
partagés dans `src/components/ui/`, icônes Lucide uniquement.

## Arborescence

```
src/
├── proxy.ts                  # redirections de session
├── actions/                  # Server Actions : auth, comptes, paiements, audit
├── app/
│   ├── (auth)/               # /login, /register
│   ├── (app)/                # pages connectées (layout avec navigation)
│   │   ├── admin/            # supervision, journal d'audit (layout : refus si non admin)
│   │   ├── accounts/  payments/  notifications/
│   │   ├── error.tsx  loading.tsx  not-found.tsx
│   └── bff/health/route.ts   # vérification des services (admin)
├── components/
│   ├── ui/                   # Button, Field, Panel, Table, StatusBadge, Alert, états vide/erreur/permission…
│   ├── shell/                # navigation, thème, horloge de session, bannière hors ligne
│   └── features/             # tableaux de comptes et de paiements
└── lib/                      # api, session, données, formatage, messages (français), types
```

## Limites connues

- **Limitation de débit partagée** : toutes les requêtes arrivent à la passerelle depuis l'IP du serveur Next.js.
  La limite de connexion (10/min par IP côté Nginx, 5 échecs/min côté auth) est donc commune à tous les
  utilisateurs de ce front. Acceptable en laboratoire ; en production, la passerelle devrait faire confiance à
  une IP client transmise par le front uniquement.
- Pas de rafraîchissement de jeton (le backend n'en propose pas) : reconnexion après 15 minutes.
- Pas de nom de compte ni d'annuaire : un compte se désigne par son identifiant (UUID).
- Les paiements reçus d'autres utilisateurs ne sont pas listés (l'API ne liste que les paiements initiés).
- Sur téléphone, les tableaux d'incidents et d'audit défilent horizontalement dans leur cadre.
- Pas de Content-Security-Policy (nécessiterait des nonces pour les scripts Next.js).
