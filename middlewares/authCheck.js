// Vigiles de sécurité : ils valident le jeton d'accès, plus aucune session en RAM.
const jwt = require('jsonwebtoken');
const { ACCESS_COOKIE, REFRESH_COOKIE, renewAccess } = require('../config/tokens');

const isNavigation = (req) => req.get('sec-fetch-mode') === 'navigate';

// jwt.verify() décode ET vérifie la signature : un payload modifié (USER -> ADMIN)
// casse le sceau mathématique et lève une erreur.
function readAccessToken(req) {
  const token = req.cookies?.[ACCESS_COOKIE];
  if (!token) return null;
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
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

module.exports = { checkJWT, checkRole };
