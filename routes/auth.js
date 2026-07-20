const express = require('express');
const bcrypt = require('bcrypt');
const fs = require('fs');
const path = require('path');
const { authenticator } = require('otplib');
const qrcode = require('qrcode');
const { stmts, SALT_ROUNDS } = require('../config/db');
const {
  REFRESH_COOKIE,
  issueSession,
  issuePendingToken,
  renewAccess,
  revokeSession
} = require('../config/tokens');
const { checkPending } = require('../middlewares/authCheck');
const { loginLimiter, otpLimiter } = require('../middlewares/rateLimit');

const router = express.Router();

const APP_NAME = 'Batcave';

// Tolérance réseau : on accepte aussi la tranche de 30 s précédente et la suivante
// (C-1 et C+1). Sans cela, une horloge de téléphone légèrement décalée ou un code
// saisi à cheval sur deux tranches serait rejeté à tort.
authenticator.options = { window: 1 };

const LOGIN_VIEW = path.join(__dirname, '..', 'views', 'login.html');
const asString = (v) => (v ?? '').toString();

// 1) Formulaire de connexion
router.get('/login', (req, res) => {
  res.send(fs.readFileSync(LOGIN_VIEW, 'utf-8'));
});

// 2) Premier verrou : le mot de passe. Il n'ouvre plus rien à lui seul.
router.post('/login', loginLimiter, async (req, res) => {
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

    // Mot de passe correct : on entre dans le sas, aucun jeton d'accès n'est délivré.
    issuePendingToken(res, user);

    // 403 et non 401 : les identifiants sont bons, c'est le niveau de sécurité du
    // compte qui est insuffisant. L'utilisateur doit enrôler son second facteur.
    if (!user.two_factor_enabled || !user.two_factor_secret) {
      return res.status(403).json({
        requiresEnrollment: true,
        error: 'Double authentification obligatoire : enrôlez votre appareil.'
      });
    }

    return res.json({
      requires2FA: true,
      remember,
      message: 'Étape 1 validée. Saisissez votre code à 6 chiffres.'
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
});

// 2.a) Enrôlement, étape A : génère la clé TOTP et le QR code.
// Accessible depuis le sas uniquement (mot de passe déjà prouvé).
router.post('/setup-2fa', checkPending, async (req, res) => {
  const user = req.pendingUser;

  // Un compte déjà protégé ne peut pas régénérer sa clé depuis le sas : il faudrait
  // sinon seulement le mot de passe pour réinitialiser le second facteur.
  if (user.two_factor_enabled) {
    return res.status(409).json({ error: 'La double authentification est déjà active.' });
  }

  const secret = authenticator.generateSecret();
  // URI normalisée que toutes les applications d'authentification savent lire.
  const otpauth = authenticator.keyuri(user.username, APP_NAME, secret);

  // enabled reste à 0 : tant que la synchronisation n'est pas prouvée, on ne
  // verrouille pas le compte.
  stmts.setTwoFactorSecret.run(secret, user.id);

  const qrCode = await qrcode.toDataURL(otpauth);
  return res.json({ qrCode, secret });
});

// 2.b) Enrôlement, étape B : le premier code prouve que téléphone et serveur sont
// synchronisés. C'est seulement là que la 2FA est verrouillée.
router.post('/confirm-2fa', checkPending, otpLimiter, (req, res) => {
  const user = req.pendingUser;
  const code = asString(req.body.code).trim();

  if (!user.two_factor_secret) {
    return res.status(400).json({ error: 'Aucun enrôlement en cours.' });
  }
  if (!authenticator.check(code, user.two_factor_secret)) {
    return res.status(401).json({ error: 'Code incorrect. Activation avortée.' });
  }

  stmts.enableTwoFactor.run(user.id);
  issueSession(res, user, false);
  stmts.insertLog.run(user.username);
  return res.json({ success: true, message: 'Double authentification activée.' });
});

// 2.c) Second verrou : le code TOTP. Les cookies ne sont posés qu'ici.
router.post('/verify-2fa', checkPending, otpLimiter, (req, res) => {
  const user = req.pendingUser;
  const code = asString(req.body.code).trim();
  const remember = Boolean(req.body.remember);

  if (!user.two_factor_enabled || !user.two_factor_secret) {
    return res.status(403).json({ error: 'Double authentification non configurée.' });
  }

  // check() rejoue l'algorithme TOTP : clé secrète + tranche de 30 s en cours.
  if (!authenticator.check(code, user.two_factor_secret)) {
    return res.status(401).json({ error: 'Code 2FA invalide ou expiré.' });
  }

  issueSession(res, user, remember);
  stmts.insertLog.run(user.username);
  return res.json({ success: true });
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

  // Liste blanche plutôt que liste noire : on n'accepte que ce qui est prévu.
  // L'échappement à l'affichage reste la vraie parade XSS, ceci est une seconde barrière.
  if (!/^[A-Za-z0-9_-]{3,30}$/.test(username)) {
    return res.status(400).json({
      error: "Le nom d'utilisateur doit faire 3 à 30 caractères (lettres, chiffres, - et _)."
    });
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
