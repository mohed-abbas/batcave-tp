// Point d'entrée léger : config, middlewares globaux, montage des routeurs, listen.
require('dotenv').config(); // doit être appelé AVANT toute lecture de process.env

const express = require('express');
const path = require('path');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);

require('./config/db'); // initialise la base (schéma + admin par défaut)
const authRouter = require('./routes/auth');
const batcomputerRouter = require('./routes/batcomputer');

const app = express();
const PORT = process.env.PORT || 3000;

// Parsers de corps de requête
app.use(express.json());                          // pour les API JSON (register, reports)
app.use(express.urlencoded({ extended: true }));  // pour le formulaire de login (POST classique)

// Sessions : le serveur émet un badge éphémère (cookie bat_identity).
app.use(session({
  name: 'bat_identity',                 // masque la techno (défaut: connect.sid)
  secret: process.env.SESSION_SECRET,   // signe le cookie => détecte toute altération
  resave: false,                        // ne réécrit pas la session si rien n'a changé
  saveUninitialized: false,             // pas de session pour un visiteur anonyme
  store: new SQLiteStore({ db: 'sessions.db', dir: __dirname }), // persistance disque (Bonus 1)
  cookie: {
    httpOnly: true,                     // inaccessible au JS du client => anti-vol XSS
    sameSite: 'strict',                 // jamais envoyé en cross-site => anti-CSRF
    maxAge: 1800000,                    // 30 min puis déconnexion automatique
    secure: process.env.NODE_ENV === 'production' // HTTPS only en prod (false sur localhost http)
  }
}));

// Fichiers publics : uniquement CSS + JS client
app.use(express.static(path.join(__dirname, 'public')));

// Montage des routeurs
app.use('/auth', authRouter);   // /auth/login, /auth/logout, /auth/register
app.use('/', batcomputerRouter); // /bat-computer, /api/*

app.get('/', (req, res) => res.redirect('/auth/login'));

app.listen(PORT, () => {
  console.log(`Batcave security online: http://localhost:${PORT}`);
});
