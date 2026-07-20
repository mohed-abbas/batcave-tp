// Cycle de vie des jetons : émission, renouvellement, révocation.
// Centralisé ici pour que le login classique, la 2FA (TP4) et OAuth (TP5) délivrent
// exactement les mêmes cookies.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const { stmts } = require('./db');

const ACCESS_TTL_MS = 15 * 60 * 1000;            // 15 min : fenêtre d'exploitation courte si vol
const REFRESH_TTL_MS = 7 * 24 * 60 * 60 * 1000;  // 7 jours

// Noms neutres : ils ne trahissent ni la techno ni le rôle du jeton.
const ACCESS_COOKIE = 'bat_identity';
const REFRESH_COOKIE = 'bat_recall';

// httpOnly => invisible du JS client (anti-XSS) ; sameSite strict => jamais envoyé
// en cross-site (anti-CSRF) ; secure => HTTPS only en production (anti-MITM).
const BASE_COOKIE = {
  httpOnly: true,
  sameSite: 'strict',
  secure: process.env.NODE_ENV === 'production'
};

// Le payload est lisible par n'importe qui (Base64Url) : aucune donnée sensible ici.
function signAccessToken(user) {
  return jwt.sign(
    { id: user.id, username: user.username, role: user.role },
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

function issueSession(res, user, remember) {
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
}

module.exports = {
  ACCESS_COOKIE,
  REFRESH_COOKIE,
  ACCESS_TTL_MS,
  REFRESH_TTL_MS,
  setAccessCookie,
  issueSession,
  renewAccess,
  revokeSession
};
