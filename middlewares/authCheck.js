// Vigiles de sécurité : protègent les routes selon l'état de la session.

// Laisse passer si une session utilisateur existe, sinon 401 + redirection login.
function isAuthenticated(req, res, next) {
  if (req.session && req.session.user) return next();
  res.status(401).redirect('/auth/login');
}

// Restreint l'accès à un rôle donné (ex: ADMIN). À utiliser APRÈS isAuthenticated.
function checkRole(role) {
  return (req, res, next) => {
    if (req.session.user && req.session.user.role === role) return next();
    res.status(403).send('Accès refusé.');
  };
}

module.exports = { isAuthenticated, checkRole };
