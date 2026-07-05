const express = require('express');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const { stmts, SALT_ROUNDS } = require('../config/db');

const router = express.Router();

const LOGIN_VIEW = path.join(__dirname, '..', 'views', 'login.html');
const asString = (v) => (v ?? '').toString();

// Rend login.html en injectant un éventuel message d'erreur dans {{error}}.
function renderLogin(error = '') {
  const html = error
    ? `<div class="alert alert-danger mt-3 py-2 small mb-0">${error}</div>`
    : '';
  return fs.readFileSync(LOGIN_VIEW, 'utf-8').replaceAll('{{error}}', html);
}

// 1) Formulaire de connexion
router.get('/login', (req, res) => {
  res.send(renderLogin());
});

// 2) Traitement de la connexion
router.post('/login', async (req, res, next) => {
  const username = asString(req.body.username).trim();
  const password = asString(req.body.password);

  const user = stmts.selectUserByUsername.get(username);
  // Toujours comparer (même si user absent) => temps constant, anti-énumération.
  const passwordOk = user ? await bcrypt.compare(password, user.password) : false;
  if (!user || !passwordOk) {
    return res.status(401).send(renderLogin('Identifiants invalides.'));
  }

  // Anti-fixation de session : on jette l'ancien ID avant d'authentifier.
  req.session.regenerate((err) => {
    if (err) return next(err);
    req.session.user = { id: user.id, username: user.username, role: user.role };
    stmts.insertLog.run(user.username);
    // save() explicite : on attend l'écriture du store avant de rediriger.
    req.session.save(() => res.redirect('/bat-computer'));
  });
});

// 4) Déconnexion propre : détruit la session + efface le cookie + redirige.
router.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('bat_identity');
    res.redirect('/auth/login');
  });
});

// Inscription (logique TP1 inchangée, simplement relocalisée ici).
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
