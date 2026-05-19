# TP1 — Système de sécurité de la Batcave

Système d'authentification HTTP **Basic Auth** sécurisé par **bcrypt** et stocké en **SQLite**.

## Stack

- Node.js + Express
- bcrypt — hachage de mot de passe
- better-sqlite3 — base de données locale
- Bootstrap 5 + Font Awesome 6 — UI

## Installation et lancement

```bash
npm install
npm start
```

Le serveur démarre sur **http://localhost:3000**.

> Au premier lancement, un compte ADMIN par défaut est créé automatiquement.

## Identifiants par défaut

| Rôle  | Identifiant | Mot de passe   |
| :---- | :---------- | :------------- |
| ADMIN | `admin`     | `batcave2026`  |

## Routes

### Publiques

| Méthode | Route             | Description                                          |
| :------ | :---------------- | :--------------------------------------------------- |
| GET     | `/register.html`  | Formulaire d'inscription                             |
| POST    | `/register`       | Crée un compte (`USER` par défaut)                   |
| GET     | `/logout`         | Réponse JSON ; le client doit effacer ses credentials |

### Protégées (Basic Auth, rôle `ADMIN` requis)

| Méthode | Route           | Description                              |
| :------ | :-------------- | :--------------------------------------- |
| GET     | `/bat-computer` | Page HTML du Bat-Ordinateur              |
| GET     | `/api/secrets`  | Liste des gadgets (JSON)                 |
| GET     | `/api/me`       | Informations de l'utilisateur connecté    |
| POST    | `/api/reports`  | Enregistre un rapport de mission         |

### Codes de retour

- `201` création réussie
- `400` validation (mot de passe trop court, nom invalide, rapport vide)
- `401` authentification requise (envoie `WWW-Authenticate: Basic realm="Batcave"`)
- `403` rôle insuffisant (`Acces refuse`)
- `409` nom d'utilisateur déjà utilisé

## Tester en 3 méthodes

### 1. Via le navigateur

Ouvrir http://localhost:3000/bat-computer → saisir `admin` / `batcave2026` dans la boîte de dialogue native.

### 2. Via Postman

Onglet **Auth** → **Basic Auth** → identifiants `admin` / `batcave2026` → requête `GET http://localhost:3000/api/secrets`.

### 3. Via cURL

```bash
curl -u "admin:batcave2026" http://localhost:3000/api/secrets
```

## Schéma de la base

- `users (id PK, username UNIQUE, password, role)` — rôles : `USER` ou `ADMIN`
- `reports (id PK, user_id FK→users.id, content, created_at)`
- `logs (id PK, username, timestamp)` — une ligne par accès réussi à une route protégée

## Structure

```
batcave-security/
├── server.js
├── database.db            (créée au premier lancement)
├── public/
│   ├── register.html
│   ├── register.js
│   ├── batcave.css        (styles partagés)
│   └── batcave-client.js  (helpers JS partagés)
└── private/
    └── bat-computer.html  (hors du dossier public)
```
