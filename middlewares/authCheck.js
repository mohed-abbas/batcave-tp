// Vigiles de sécurité : ils valident le jeton d'accès, plus aucune session en RAM.
const jwt = require('jsonwebtoken');
const { ACCESS_COOKIE, REFRESH_COOKIE, renewAccess, readPendingToken } = require('../config/tokens');
const { stmts } = require('../config/db');

const isNavigation = (req) => req.get('sec-fetch-mode') === 'navigate';

// jwt.verify() décode ET vérifie la signature : un payload modifié (USER -> ADMIN)
// casse le sceau mathématique et lève une erreur.
function readAccessToken(req) {
  const token = req.cookies?.[ACCESS_COOKIE];
  if (!token) return null;
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    // Un jeton de sas (scope 2fa) ne doit jamais ouvrir une route protégée.
    return payload.scope === 'access' ? payload : null;
  } catch {
    return null;
  }
}

function checkJWT(req, res, next) {
  const payload = readAccessToken(req);
  if (payload) {
    req.user = payload;
    return next();
  }

  // Chargement d'une page : pas de JS pour rattraper le 401, on renouvelle ici même.
  // Sans cela, un badge mémorisé renverrait quand même l'utilisateur au login dès
  // que le jeton d'accès a expiré.
  if (isNavigation(req)) {
    const user = renewAccess(res, req.cookies?.[REFRESH_COOKIE]);
    if (user) {
      req.user = { id: user.id, username: user.username, role: user.role };
      return next();
    }
    return res.redirect('/auth/login');
  }

  // Appel fetch : on renvoie le 401 que le client intercepte pour appeler /refresh
  // puis rejouer sa requête.
  return res.status(401).json({ error: 'Accès refusé. Jeton absent, invalide ou expiré.' });
}

// Restreint l'accès à un rôle donné (ex: ADMIN). À utiliser APRÈS checkJWT.
function checkRole(role) {
  return (req, res, next) => {
    if (req.user && req.user.role === role) return next();
    res.status(403).json({ error: 'Accès refusé.' });
  };
}

// Garde des routes d'enrôlement et de vérification 2FA : l'utilisateur a prouvé le
// facteur 1 (mot de passe) mais n'a encore aucun droit sur l'application.
function checkPending(req, res, next) {
  const payload = readPendingToken(req);
  if (!payload) {
    return res.status(401).json({ error: 'Sas expiré. Reprenez la connexion.' });
  }

  const user = stmts.selectUserById.get(payload.id);
  if (!user) return res.status(401).json({ error: 'Sas expiré. Reprenez la connexion.' });

  req.pendingUser = user;
  return next();
}

module.exports = { checkJWT, checkRole, checkPending };
