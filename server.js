// Point d'entrée léger : config, middlewares globaux, montage des routeurs, listen.
require('dotenv').config(); // doit être appelé AVANT toute lecture de process.env

const express = require('express');
const path = require('path');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');

const { stmts } = require('./config/db'); // initialise la base (schéma + admin par défaut)
const authRouter = require('./routes/auth');
const oauthRouter = require('./routes/oauth');
const batcomputerRouter = require('./routes/batcomputer');

const app = express();
const PORT = process.env.PORT || 3000;

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET manquant : sans secret, aucune signature de jeton n\'est possible.');
}

// Purge des refreshTokens périmés au démarrage (la table ne grossit pas indéfiniment).
stmts.deleteExpiredRefreshTokens.run();

// Zéro-Confiance : on dicte au navigateur ce qu'il a le droit de faire.
// Helmet pose nosniff, X-Frame-Options (anti-clickjacking), HSTS, et supprime
// l'en-tête X-Powered-By qui annonçait « Express » à un attaquant.
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // Liste blanche des CDN réellement utilisés. Un script injecté depuis un
      // domaine pirate est bloqué par le navigateur avant même de s'exécuter.
      scriptSrc: ["'self'", 'https://cdn.jsdelivr.net'],
      styleSrc: [
        "'self'",
        'https://cdn.jsdelivr.net',
        'https://cdnjs.cloudflare.com',
        'https://fonts.googleapis.com'
      ],
      fontSrc: ["'self'", 'https://cdnjs.cloudflare.com', 'https://fonts.gstatic.com'],
      // data: est nécessaire au QR code de la 2FA, généré en base64 par le serveur.
      imgSrc: ["'self'", 'data:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"]
    }
  }
}));

// Parsers de corps de requête
app.use(express.json());                          // API JSON (login, register, reports)
app.use(express.urlencoded({ extended: true }));

// Architecture stateless : plus de store de sessions, seulement la lecture des cookies
// qui transportent le jeton d'accès et le jeton de rafraîchissement.
app.use(cookieParser());

// Fichiers publics : uniquement CSS + JS client
app.use(express.static(path.join(__dirname, 'public')));

// Montage des routeurs. authRouter d'abord : ses routes nommées (login, refresh,
// logout, register, *-2fa) ont priorité sur le /:provider générique d'oauthRouter.
app.use('/auth', authRouter);    // /auth/login, /auth/refresh, /auth/logout, /auth/register
app.use('/auth', oauthRouter);   // /auth/providers, /auth/:provider, /auth/:provider/callback
app.use('/', batcomputerRouter); // /bat-computer, /api/*

app.get('/', (req, res) => res.redirect('/auth/login'));

app.listen(PORT, () => {
  console.log(`Batcave security online: http://localhost:${PORT}`);
});
