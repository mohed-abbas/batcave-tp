// Cycle de vie des jetons : émission, renouvellement, révocation.
// Centralisé ici pour que le login classique, la 2FA (TP4) et OAuth (TP5) délivrent
// exactement les mêmes cookies.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { stmts } = require('./db');

const ACCESS_TTL_MS = 15 * 60 * 1000;            // 15 min : fenêtre d'exploitation courte si vol
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;  // 7 jours
const PENDING_TTL_MS = 5 * 60 * 1000;            // 5 min pour saisir un code à 6 chiffres

// Noms neutres : ils ne trahissent ni la techno ni le rôle du jeton.
const ACCESS_COOKIE = 'bat_identity';
const REFRESH_COOKIE = 'bat_recall';
const PENDING_COOKIE = 'bat_airlock'; // sas : mot de passe validé, second facteur en attente

// httpOnly => invisible du JS client (anti-XSS) ; sameSite strict => jamais envoyé
// en cross-site (anti-CSRF) ; secure => HTTPS only en production (anti-MITM).
const BASE_COOKIE = {
  httpOnly: true,
  sameSite: 'strict',
  secure: process.env.NODE_ENV === 'production'
};

// Le payload est lisible par n'importe qui (Base64Url) : aucune donnée sensible ici.
// Le claim `scope` empêche qu'un jeton de sas serve de jeton d'accès.
function signAccessToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role, scope: 'access' },
    process.env.JWT_SECRET,
    { expiresIn: ACCESS_TTL_MS / 1000 }
  );
}

function setAccessCookie(res, user) {
  res.cookie(ACCESS_COOKIE, signAccessToken(user), { ...BASE_COOKIE, maxAge: ACCESS_TTL_MS });
}

// Chaîne opaque, pas un JWT : elle ne transporte aucune donnée, sa seule valeur est
// d'exister en base. La supprimer suffit donc à révoquer la connexion.
function issueRefreshToken(res, userId, remember) {
  const token = crypto.randomBytes(40).toString('hex');
  const expiresAt = new Date(Date.now() + REFRESH_TTL_MS).toISOString();
  stmts.insertRefreshToken.run(token, userId, expiresAt);

  // Mémorisation du badge : sans maxAge, le cookie meurt à la fermeture du navigateur.
  res.cookie(REFRESH_COOKIE, token, {
    ...BASE_COOKIE,
    ...(remember && { maxAge: REFRESH_TTL_MS })
  });
  return token;
}

// Sas d'attente : le mot de passe est validé, mais rien n'est encore accordé.
// Ce jeton prouve seulement « le facteur 1 est passé pour cet utilisateur ».
// Sans lui, /verify-2fa accepterait un simple nom d'utilisateur et le mot de passe
// deviendrait contournable.
function issuePendingToken(res, user) {
  const token = jwt.sign(
    { id: user.id, scope: '2fa' },
    process.env.JWT_SECRET,
    { expiresIn: PENDING_TTL_MS / 1000 }
  );
  res.cookie(PENDING_COOKIE, token, { ...BASE_COOKIE, maxAge: PENDING_TTL_MS });
}

function readPendingToken(req) {
  const token = req.cookies?.[PENDING_COOKIE];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    return payload.scope === '2fa' ? payload : null;
  } catch {
    return null;
  }
}

function issueSession(res, user, remember) {
  res.clearCookie(PENDING_COOKIE); // le sas est franchi, il n'a plus lieu d'être
  setAccessCookie(res, user);
  issueRefreshToken(res, user.id, remember);
}

// Valide un refreshToken et, s'il tient, réémet un jeton d'accès.
// Retourne l'utilisateur, ou null si le jeton est absent, révoqué ou périmé.
function renewAccess(res, refreshToken) {
  if (!refreshToken) return null;

  const stored = stmts.selectRefreshToken.get(refreshToken);
  // Deux barrières : présence en base (donc non révoqué) et fraîcheur.
  if (!stored || new Date() > new Date(stored.expires_at)) return null;

  // On relit l'utilisateur : un rôle modifié entre-temps est pris en compte ici.
  const user = stmts.selectUserById.get(stored.user_id);
  if (!user) return null;

  setAccessCookie(res, user);
  return user;
}

function revokeSession(res, refreshToken) {
  if (refreshToken) stmts.deleteRefreshToken.run(refreshToken);
  res.clearCookie(ACCESS_COOKIE);
  res.clearCookie(REFRESH_COOKIE);
  res.clearCookie(PENDING_COOKIE);
}

module.exports = {
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  PENDING_COOKIE,
  ACCESS_TTL_MS,
  REFRESH_TTL_MS,
  setAccessCookie,
  issueSession,
  issuePendingToken,
  readPendingToken,
  renewAccess,
  revokeSession
};
