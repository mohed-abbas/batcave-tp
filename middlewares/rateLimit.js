// Limiteurs de débit : une signature valide ne protège pas du bruteforce.
// Sans eux, un code TOTP à 6 chiffres (1 000 000 de combinaisons) tomberait
// mécaniquement en essayant assez vite.
const rateLimit = require('express-rate-limit');

const common = {
  standardHeaders: true, // en-têtes RateLimit-* standard
  legacyHeaders: false,  // pas de X-RateLimit-* obsolètes
  message: { error: 'Trop de tentatives. Réessayez dans quelques minutes.' }
};

const loginLimiter = rateLimit({
  ...common,
  windowMs: 15 * 60 * 1000,
  limit: 10, // 10 essais de mot de passe par IP et par quart d'heure
  skipSuccessfulRequests: true
});

// Plus strict : la fenêtre de validité d'un code n'est que de 30 secondes.
const otpLimiter = rateLimit({
  ...common,
  windowMs: 5 * 60 * 1000,
  limit: 5,
  skipSuccessfulRequests: true
});

module.exports = { loginLimiter, otpLimiter };
