# Batcave — Guide d'évaluation

> Guide pour lancer le projet et retrouver, dans une seule application, le travail des **cinq TP**
> du cours (du Basic Auth jusqu'à OAuth2). Écrit pour être suivi pas à pas, sans connaissance
> préalable du code.

Le projet est un **serveur d'authentification** qui protège l'accès à un tableau de bord (le
« Bat-Ordinateur »). Chaque TP a ajouté une couche de sécurité par-dessus la précédente. La version
finale (branche `main`) contient tout : mot de passe chiffré, double authentification, jetons JWT,
en-têtes de sécurité et connexion via GitHub / Google / Discord.

---

## 1. Les cinq TP en un coup d'œil

| TP | Sujet | Ce qui a été mis en place | Où le voir |
| :-- | :-- | :-- | :-- |
| **TP1** | Le système de sécurité de la Batcave | Connexion par identifiant + mot de passe, mots de passe **chiffrés** (jamais en clair), base de données SQLite | dans tout le projet |
| **TP2** | Cookies & Sessions | Connexion qui **reste en mémoire** grâce à un cookie de session + option « se souvenir de moi » | branche `TP2` (instantané figé) et repris sur `main` |
| **TP3** | JSON Web Token (JWT) | Le serveur ne garde plus les sessions en mémoire : il délivre des **jetons signés** qui se renouvellent tout seuls | branche `main` |
| **TP4** | Failles de sécurité & 2FA | **Double authentification** (code à 6 chiffres), en-têtes de sécurité, protection contre le vol de jeton et la force brute | branche `main` |
| **TP5** | OAuth2 / OpenID Connect | Connexion avec un compte **GitHub, Google ou Discord** (optionnel) | branche `main` |

> **Résumé** : la branche `main` est la version complète à évaluer. La branche `TP2` est une photo
> figée de l'étape « sessions » si vous voulez voir cet état précis.

---

## 2. Ce qu'il faut avoir sur la machine

- **Node.js version 22** (le fichier `.nvmrc` l'indique ; si vous avez `nvm`, tapez `nvm use`).
- Rien d'autre. La base de données est un simple fichier créé automatiquement au premier lancement.

---

## 3. Lancer le projet (5 étapes)

Dans un terminal, à la racine du dossier `batcave-security` :

```bash
# 1. Installer les dépendances
npm install

# 2. Créer le fichier de configuration à partir de l'exemple
cp .env.example .env

# 3. Générer une clé secrète et la coller dans .env (ligne JWT_SECRET)
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"

# 4. Ouvrez .env, remplacez la valeur de JWT_SECRET par la clé générée à l'étape 3

# 5. Démarrer le serveur
npm start
```

Le serveur affiche alors :

```
Default ADMIN created: admin / batcave2026
Batcave security online: http://localhost:3000
```

Ouvrez **http://localhost:3000** dans votre navigateur. 🦇

> **Important** : sans `JWT_SECRET` dans le `.env`, le serveur refuse de démarrer (c'est voulu :
> aucune signature de jeton n'est possible sans clé). Les étapes 2 à 4 sont donc obligatoires.

---

## 4. Se connecter — le compte administrateur

| Rôle | Identifiant | Mot de passe |
| :-- | :-- | :-- |
| **ADMIN** | `admin` | `batcave2026` |

Comme la **double authentification est obligatoire**, la première connexion de `admin` se déroule
en deux temps :

1. Saisissez `admin` / `batcave2026` → le mot de passe seul **n'ouvre aucune session**.
2. Le site affiche un **QR code**. Scannez-le avec une application d'authentification
   (**Google Authenticator**, **Authy**, **Microsoft Authenticator** ou **1Password**).
3. L'application affiche un **code à 6 chiffres** qui change toutes les 30 secondes. Saisissez-le
   pour armer la double authentification → vous entrez dans le Bat-Ordinateur.

Aux connexions suivantes, `admin` n'aura plus le QR code : le site demandera directement le
**code à 6 chiffres** de l'application.

> **Pas d'application d'authentification sous la main ?** Vous pouvez tout de même voir l'écran
> d'enrôlement et le QR code. Pour valider un code sans téléphone, ouvrez un second terminal et
> lancez la commande donnée en fin de guide (section Dépannage).

### Créer un compte simple (rôle USER)

Depuis la page de connexion, lien **« Nouvel opérateur — s'enregistrer »**. Un compte USER passe
lui aussi par l'enrôlement 2FA à sa première connexion. Un USER **n'a pas accès** au journal réservé
aux administrateurs (voir plus bas).

---

## 5. Que regarder pour chaque TP

Une fois connecté en tant qu'`admin`, vous êtes sur le **Bat-Ordinateur** :

- **TP1 — mot de passe chiffré** : les mots de passe sont hachés avec bcrypt ; même en ouvrant la
  base de données, on ne voit jamais le mot de passe en clair.
- **TP2 — session mémorisée** : la case « Mémoriser ce badge » sur l'écran de connexion garde la
  connexion active même après fermeture du navigateur.
- **TP3 — JWT** : votre connexion reste valide et se renouvelle toute seule, sans que le serveur
  garde une liste de sessions en mémoire. Le bouton « Fermer la session » révoque le jeton.
- **TP4 — 2FA & sécurité** : le code à 6 chiffres demandé à la connexion. En bas de page, la
  section **« Journal d'accès »** liste les connexions — elle n'apparaît **que** pour un ADMIN.
- **TP5 — OAuth** : les boutons **GitHub / Google / Discord** sur la page de connexion (visibles
  seulement si les clés sont configurées, voir section 7).

---

## 6. Le détail de chaque TP, en clair

### TP1 — Identifiant, mot de passe, base de données
On authentifie un utilisateur avec un identifiant et un mot de passe. Les mots de passe ne sont
**jamais stockés en clair** : ils sont transformés par bcrypt en une empreinte impossible à
inverser. Les comptes sont rangés dans une base SQLite (un simple fichier).

### TP2 — Cookies et sessions
Pour éviter de retaper le mot de passe à chaque page, le serveur pose un **cookie**. L'option
« se souvenir de moi » décide si ce badge disparaît à la fermeture du navigateur ou s'il reste
valable plusieurs jours.

### TP3 — Les jetons JWT (connexion « stateless »)
Au lieu de garder la liste des connexions en mémoire, le serveur délivre deux **jetons signés** :
- un **jeton d'accès** de courte durée (15 minutes) ;
- un **jeton de rafraîchissement** de longue durée (7 jours), stocké en base pour pouvoir être
  **révoqué** (déconnexion).

Le jeton d'accès se renouvelle automatiquement en arrière-plan : l'utilisateur ne voit rien.
Comme le jeton est signé, un utilisateur ne peut pas trafiquer son contenu (ex. se donner le rôle
ADMIN) : la signature ne correspondrait plus.

### TP4 — Failles de sécurité et double authentification
Deux volets :
- **Double authentification (2FA)** : en plus du mot de passe (« ce que je sais »), il faut un code
  à 6 chiffres généré par une application sur le téléphone (« ce que je possède »). Norme TOTP,
  compatible Google Authenticator. Le mot de passe seul ne suffit donc plus, même s'il est volé.
- **Durcissement** : en-têtes de sécurité (helmet), politique stricte qui empêche l'exécution de
  scripts injectés (protection anti-XSS), cookies inaccessibles au JavaScript, et un **limiteur**
  qui bloque les tentatives répétées de mot de passe ou de code (anti force brute).

### TP5 — OAuth2 / OpenID Connect
On peut se connecter avec un compte **GitHub, Google ou Discord** sans créer de mot de passe sur le
site. Le site ne voit jamais votre mot de passe du fournisseur ; il reçoit seulement une preuve
d'identité. Sécurisé par les mécanismes standards `state` (anti-CSRF) et `PKCE`.

---

## 7. Connexion GitHub / Google / Discord (optionnelle)

Cette partie **n'est pas nécessaire** pour évaluer le reste : sans clés, les boutons sont simplement
masqués et tout le reste fonctionne. Pour l'activer, il faut créer une application chez chaque
fournisseur et coller les clés dans `.env` :

| Fournisseur | Où créer l'application | URL de retour à déclarer |
| :-- | :-- | :-- |
| GitHub | github.com/settings/developers | `http://localhost:3000/auth/github/callback` |
| Google | console.cloud.google.com → Identifiants | `http://localhost:3000/auth/google/callback` |
| Discord | discord.com/developers/applications | `http://localhost:3000/auth/discord/callback` |

Un fournisseur ne s'active que si **ses deux clés** (`CLIENT_ID` et `CLIENT_SECRET`) sont remplies
dans `.env`.

---

## 8. Récapitulatif des accès

| Élément | Valeur |
| :-- | :-- |
| Adresse | http://localhost:3000 |
| Compte administrateur | `admin` / `batcave2026` |
| Créer un compte utilisateur | page de connexion → « Nouvel opérateur — s'enregistrer » |
| Route réservée aux ADMIN | `GET /api/logs` (le « Journal d'accès » du tableau de bord) |
| Base de données | fichier `database.db`, créé au premier lancement |

> La protection ADMIN est **côté serveur** : un simple utilisateur qui appellerait directement
> `GET /api/logs` reçoit une erreur `403`. Masquer la section dans la page n'est pas la sécurité,
> le contrôle du rôle dans le jeton l'est.

---

## 9. Dépannage

- **« JWT_SECRET manquant »** au démarrage → vous avez sauté les étapes 2 à 4 : créez `.env` et
  renseignez `JWT_SECRET`.
- **Erreur `NODE_MODULE_VERSION` / `better-sqlite3`** → mauvaise version de Node. Activez Node 22
  (`nvm use`) puis lancez `npm rebuild better-sqlite3`.
- **Le port 3000 est déjà pris** → changez `PORT` dans `.env` (pensez à adapter les URL de retour
  OAuth si vous utilisez cette partie).
- **Repartir d'une base vierge** → arrêtez le serveur, supprimez le fichier `database.db`, relancez
  `npm start` : le compte `admin` est recréé sans 2FA.
- **Valider un code 2FA sans téléphone** → une fois le QR code affiché à l'écran (la clé est alors
  enregistrée en base), générez le code à 6 chiffres depuis un second terminal, qui lit la clé dans
  la base et calcule le code du moment :
  ```bash
  node -e "const d=require('better-sqlite3')('./database.db');const s=d.prepare('SELECT two_factor_secret FROM users WHERE username=?').get('admin').two_factor_secret;console.log(require('otplib').authenticator.generate(s))"
  ```
  Saisissez le code obtenu sur la page. (Remplacez `admin` par un autre identifiant au besoin.)

---

*Version finale sur la branche `main`. Instantané de l'étape sessions sur la branche `TP2`.*
