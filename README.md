# TP2 — Système de badges de la Batcave

Authentification par **session** (cookie signé `bat_identity`), mots de passe hachés avec **bcrypt**, stockage **SQLite**. Évolution du TP1 (Basic Auth) vers un badge éphémère côté serveur.

## Stack

- Node.js + Express
- express-session — sessions côté serveur
- connect-sqlite3 — store de sessions persistant (survit au redémarrage)
- dotenv — secrets externalisés (`.env`)
- bcrypt — hachage de mot de passe
- better-sqlite3 — base de données locale
- Bootstrap 5 + Font Awesome 6 — UI

## Installation et lancement

```bash
npm install
cp .env.example .env   # puis renseignez SESSION_SECRET
npm start
```

Le serveur démarre sur **http://localhost:3000** (port configurable via `.env`).

> Au premier lancement, un compte ADMIN par défaut est créé automatiquement.

### Prérequis Node

Le binaire natif `better-sqlite3` doit correspondre à votre version de Node. Avec **Node 22** (version par défaut du projet), `npm install` télécharge le binaire pré-compilé. En cas d'erreur `NODE_MODULE_VERSION`, lancez `npm rebuild better-sqlite3` avec la bonne version de Node active.

## Identifiants par défaut

| Rôle  | Identifiant | Mot de passe   |
| :---- | :---------- | :------------- |
| ADMIN | `admin`     | `batcave2026`  |

## Routes

### Publiques

| Méthode | Route             | Description                                  |
| :------ | :---------------- | :------------------------------------------- |
| GET     | `/`               | Redirige vers `/auth/login`                  |
| GET     | `/auth/login`     | Formulaire de connexion (HTML)               |
| POST    | `/auth/login`     | Vérifie les identifiants, ouvre une session  |
| GET     | `/auth/logout`    | Détruit la session, efface le cookie, redirige |
| GET     | `/register.html`  | Formulaire d'inscription                     |
| POST    | `/auth/register`  | Crée un compte (`USER` par défaut)           |

### Protégées (session requise — middleware `isAuthenticated`)

| Méthode | Route           | Description                              |
| :------ | :-------------- | :--------------------------------------- |
| GET     | `/bat-computer` | Tableau de bord (nom de l'agent injecté) |
| GET     | `/api/secrets`  | Liste des gadgets (JSON)                 |
| GET     | `/api/me`       | Informations de l'utilisateur connecté   |
| POST    | `/api/reports`  | Enregistre un rapport de mission         |

### Configuration du cookie de session

| Option           | Valeur        | Rôle                                            |
| :--------------- | :------------ | :---------------------------------------------- |
| `name`           | `bat_identity`| Masque la techno (défaut `connect.sid`)         |
| `httpOnly`       | `true`        | Inaccessible au JS client → anti-vol XSS        |
| `sameSite`       | `strict`      | Non envoyé en cross-site → anti-CSRF            |
| `maxAge`         | `1800000`     | Déconnexion automatique après 30 min            |
| `secure`         | prod only     | HTTPS uniquement en production                  |

## Schéma de la base

- `users (id PK, username UNIQUE, password, role)` — rôles : `USER` ou `ADMIN`
- `reports (id PK, user_id FK→users.id, content, created_at)`
- `logs (id PK, username, timestamp)` — une ligne par connexion réussie
- `sessions` — table gérée par `connect-sqlite3` dans `sessions.db`

## Structure

```
batcave-security/
├── server.js              # point d'entrée léger (imports + middlewares + listen)
├── .env / .env.example    # secrets (PORT, SESSION_SECRET)
├── config/db.js           # init SQLite + schéma + requêtes préparées
├── middlewares/authCheck.js  # isAuthenticated, checkRole
├── routes/
│   ├── auth.js            # login / logout / register
│   └── batcomputer.js     # /bat-computer + /api/*
├── views/                 # HTML protégés (hors public)
│   ├── login.html
│   └── bat-computer.html
└── public/                # CSS + JS client uniquement
    ├── register.html / register.js
    ├── batcave.css
    └── batcave-client.js
```
