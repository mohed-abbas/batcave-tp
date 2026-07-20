// Point d'entrée léger : config, middlewares globaux, montage des routeurs, listen.
require('dotenv').config(); // doit être appelé AVANT toute lecture de process.env

const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');

const { stmts } = require('./config/db'); // initialise la base (schéma + admin par défaut)
const authRouter = require('./routes/auth');
const batcomputerRouter = require('./routes/batcomputer');

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET manquant : sans secret, aucune signature de jeton n\'est possible.');
}

// Purge des refreshTokens périmés au démarrage (la table ne grossit pas indéfiniment).
stmts.deleteExpiredRefreshTokens.run();

// Parsers de corps de requête
app.use(express.json());                          // API JSON (login, register, reports)
app.use(express.urlencoded({ extended: true }));

// Architecture stateless : plus de store de sessions, seulement la lecture des cookies
// qui transportent le jeton d'accès et le jeton de rafraîchissement.
app.use(cookieParser());

// Fichiers publics : uniquement CSS + JS client
app.use(express.static(path.join(__dirname, 'public')));

// Montage des routeurs
app.use('/auth', authRouter);    // /auth/login, /auth/refresh, /auth/logout, /auth/register
app.use('/', batcomputerRouter); // /bat-computer, /api/*

app.get('/', (req, res) => res.redirect('/auth/login'));

app.listen(PORT, () => {
  console.log(`Batcave security online: http://localhost:${PORT}`);
});
