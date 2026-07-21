# Le système de sécurité de la Batcave

Serveur d'authentification centralisé gérant l'accès au « Bat-Ordinateur ». Le projet suit les
cinq protocoles vus en cours, chacun renforçant le précédent : **Basic Auth → sessions → JWT →
Zéro-Confiance + 2FA → OAuth2/OIDC**.

> **Branches** : `main` porte l'état final (JWT + 2FA + OAuth). La branche `TP2` est un instantané
> figé de l'étape 2 (authentification par session `express-session`).

## Stack

- **Node.js + Express 5**
- **jsonwebtoken** — jetons d'accès et de sas signés (HS256)
- **cookie-parser** — lecture des cookies (architecture stateless, plus de store de sessions)
- **bcrypt** — hachage des mots de passe
- **better-sqlite3** — base locale
- **otplib** + **qrcode** — double authentification TOTP et génération du QR code
- **helmet** — en-têtes de sécurité (CSP, HSTS, X-Frame-Options…)
- **express-rate-limit** — anti brute-force sur le login et les codes 2FA
- **dotenv** — secrets externalisés
- Bootstrap 5 + Font Awesome 6 (CDN) pour l'interface

## Installation

```bash
npm install
cp .env.example .env      # puis renseignez au moins JWT_SECRET
npm start
```

Serveur sur **http://localhost:3000** (port configurable via `.env`).
Au premier lancement, un compte **ADMIN** par défaut est créé.

> `better-sqlite3` est un binaire natif : en cas d'erreur `NODE_MODULE_VERSION`, lancez
> `npm rebuild better-sqlite3` avec la bonne version de Node active (voir `.nvmrc`).

### Génération du secret

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Identifiants par défaut

| Rôle  | Identifiant | Mot de passe  |
| :---- | :---------- | :------------ |
| ADMIN | `admin`     | `batcave2026` |

> La double authentification étant obligatoire, le premier login de `admin` déclenche l'enrôlement
> par QR code (voir plus bas).

## Parcours d'authentification

### Connexion classique (mot de passe + 2FA)

1. `POST /auth/login` — vérifie le mot de passe. **Aucun jeton d'accès n'est délivré** : le serveur
   ouvre un « sas » (cookie court `bat_airlock`) et répond selon l'état du compte :
   - 2FA non configurée → `403` + `requiresEnrollment` → l'interface affiche le QR code ;
   - 2FA active → `requires2FA` → l'interface affiche le champ code à 6 chiffres.
2. `POST /auth/verify-2fa` (ou `POST /auth/confirm-2fa` au premier enrôlement) — valide le code TOTP.
   **C'est seulement ici que les cookies de session sont posés.**

### Connexion externe (OAuth2 / OIDC)

Boutons GitHub / Google / Discord, affichés uniquement pour les providers configurés dans `.env`.
Le second facteur est délégué au provider.

### Session stateless

- **accessToken** — JWT de 15 min, cookie `bat_identity` (`{id, username, role, scope}`).
- **refreshToken** — chaîne opaque de 7 jours, cookie `bat_recall`, stockée en base pour permettre
  la **révocation**.
- Renouvellement transparent : un appel `fetch` recevant `401` déclenche `/auth/refresh` puis rejoue
  la requête ; une navigation HTML est renouvelée côté serveur. L'utilisateur ne voit rien.
- **Mémorisation du badge** : la case « se souvenir » décide si `bat_recall` est persistant (7 jours)
  ou meurt à la fermeture du navigateur.

## Routes

### Authentification — `/auth`

| Méthode | Route | Description |
| :-- | :-- | :-- |
| GET  | `/auth/login` | Formulaire de connexion |
| POST | `/auth/login` | Facteur 1 (mot de passe) → sas |
| POST | `/auth/setup-2fa` | Enrôlement A : génère la clé TOTP + le QR code |
| POST | `/auth/confirm-2fa` | Enrôlement B : active la 2FA sur un premier code valide |
| POST | `/auth/verify-2fa` | Facteur 2 (code TOTP) → pose les cookies |
| POST | `/auth/refresh` | Renouvelle l'accessToken depuis le refreshToken |
| POST | `/auth/logout` | Révoque le refreshToken en base + efface les cookies |
| POST | `/auth/register` | Crée un compte `USER` |
| GET  | `/auth/providers` | Liste des providers OAuth configurés |
| GET  | `/auth/:provider` | Démarre le flux OAuth (redirige vers le provider) |
| GET  | `/auth/:provider/callback` | Retour du provider : vérifie, échange, connecte |

### Application (jeton requis — middleware `checkJWT`)

| Méthode | Route | Description |
| :-- | :-- | :-- |
| GET  | `/bat-computer` | Tableau de bord |
| GET  | `/api/me` | Identité de l'utilisateur connecté |
| GET  | `/api/secrets` | Liste des gadgets |
| POST | `/api/reports` | Enregistre un rapport de mission |
| GET  | `/api/logs` | Journal des connexions — **ADMIN uniquement** (`checkRole`) |

## Sécurité en place

| Menace | Parade |
| :-- | :-- |
| Vol de jeton par XSS | cookies `httpOnly` + CSP stricte, scripts/styles hors HTML |
| CSRF | `sameSite: 'strict'` sur les cookies de jetons |
| Falsification de jeton | signature JWT vérifiée (`USER → ADMIN` casse le sceau) |
| Rejeu | accessToken à vie courte (15 min) |
| Brute-force mot de passe / code | `express-rate-limit` |
| Mot de passe volé | 2FA TOTP obligatoire (facteur de possession) |
| Élévation de privilège | `checkRole` sur le rôle du payload signé |
| MITM | `secure: true` en production (HTTPS) + HSTS |
| Interception du code OAuth | PKCE (S256) |
| CSRF sur le retour OAuth | paramètre `state` vérifié |

## Configuration OAuth (optionnelle)

Chaque provider s'active si ses deux clés sont dans `.env`. Callbacks à déclarer chez le provider
(remplacez le port si vous changez `PORT`) :

| Provider | Console | Callback |
| :-- | :-- | :-- |
| GitHub  | github.com/settings/developers | `http://localhost:3000/auth/github/callback` |
| Google  | console.cloud.google.com → Identifiants | `http://localhost:3000/auth/google/callback` |
| Discord | discord.com/developers/applications | `http://localhost:3000/auth/discord/callback` |

## Schéma de la base

- `users (id, username UNIQUE, password, role, two_factor_secret, two_factor_enabled)`
- `reports (id, user_id →users, content, created_at)`
- `logs (id, username, timestamp)` — une ligne par connexion réussie
- `refresh_tokens (id, token UNIQUE, user_id →users, expires_at)` — permet la révocation
- `oauth_accounts (id, provider, provider_user_id, user_id →users, email)` — liaison OAuth

## Structure

```
batcave-security/
├── server.js                 # point d'entrée : helmet, cookies, montage des routeurs
├── .env / .env.example       # secrets (PORT, JWT_SECRET, clés OAuth)
├── config/
│   ├── db.js                 # init SQLite + migrations + requêtes préparées
│   ├── tokens.js             # cycle de vie des jetons (émission, refresh, révocation)
│   ├── oauthProviders.js     # registre OAuth piloté par le .env
│   └── escape.js             # échappement HTML côté serveur
├── middlewares/
│   ├── authCheck.js          # checkJWT, checkRole, checkPending (sas 2FA)
│   └── rateLimit.js          # limiteurs login / 2FA
├── routes/
│   ├── auth.js               # login, refresh, logout, register, 2FA
│   ├── oauth.js              # flux OAuth2/OIDC manuel
│   └── batcomputer.js        # /bat-computer + /api/*
├── views/                    # HTML protégés (login.html, bat-computer.html)
└── public/                   # CSS + JS client (aucun secret)
```

## Étapes du syllabus

| # | Étape | Où |
| :-- | :-- | :-- |
| 1 | Basic Auth + Bcrypt + SQLite | historique git (branche `TP2`) |
| 2 | Sessions + mémorisation du badge | branche `TP2` ; remember-me repris sur le refreshToken |
| 3 | JWT accessToken / refreshToken | `main` |
| 4 | Zéro-Confiance (headers, cycle de vie) + 2FA | `main` |
| 5 | OAuth2 / OpenID Connect — 3 providers | `main` |
