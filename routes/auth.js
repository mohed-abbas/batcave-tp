const express = require('express');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const { stmts, SALT_ROUNDS } = require('../config/db');
const { REFRESH_COOKIE, issueSession, renewAccess, revokeSession } = require('../config/tokens');

const router = express.Router();

const LOGIN_VIEW = path.join(__dirname, '..', 'views', 'login.html');
const asString = (v) => (v ?? '').toString();

// 1) Formulaire de connexion
router.get('/login', (req, res) => {
  res.send(fs.readFileSync(LOGIN_VIEW, 'utf-8'));
});

// 2) Traitement de la connexion : émet le couple accessToken / refreshToken.
router.post('/login', async (req, res) => {
  const username = asString(req.body.username).trim();
  const password = asString(req.body.password);
  const remember = Boolean(req.body.remember);

  try {
    const user = stmts.selectUserByUsername.get(username);
    // Toujours comparer (même si user absent) => temps constant, anti-énumération.
    const passwordOk = user ? await bcrypt.compare(password, user.password) : false;
    if (!user || !passwordOk) {
      return res.status(401).json({ error: 'Identifiants invalides.' });
    }

    issueSession(res, user, remember);
    stmts.insertLog.run(user.username);
    return res.json({ success: true });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// 3) Renouvellement : le serveur reste amnésique, il ne fait confiance qu'à la base.
router.post('/refresh', (req, res) => {
  const user = renewAccess(res, req.cookies?.[REFRESH_COOKIE]);
  if (!user) return res.status(401).json({ error: 'Session expirée, reconnectez-vous.' });
  return res.json({ success: true });
});

// 4) Déconnexion : la ligne en base disparaît => un refreshToken volé devient inutile.
router.post('/logout', (req, res) => {
  revokeSession(res, req.cookies?.[REFRESH_COOKIE]);
  res.json({ success: true });
});

// Navigation directe (lien du dashboard) : même révocation, puis retour au login.
router.get('/logout', (req, res) => {
  revokeSession(res, req.cookies?.[REFRESH_COOKIE]);
  res.redirect('/auth/login');
});

// Inscription (logique TP1 inchangée).
router.post('/register', async (req, res) => {
  const username = asString(req.body.username).trim();
  const password = asString(req.body.password);

  if (!username || /\s/.test(username)) {
    return res.status(400).json({ error: "Le nom d'utilisateur ne doit pas contenir d'espaces." });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit faire au moins 8 caracteres.' });
  }

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const info = stmts.insertUser.run(username, hash);
    return res.status(201).json({ id: info.lastInsertRowid, username });
  } catch (err) {
    if (err && err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: "Nom d'utilisateur deja utilise." });
    }
    console.error(err);
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
});

module.exports = router;
