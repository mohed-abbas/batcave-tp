// Connexion externe OAuth2 / OpenID Connect, écrite à la main.
// Flux : /auth/:provider redirige vers le fournisseur, /auth/:provider/callback
// vérifie la réponse, échange le code, lit le profil, puis pose les cookies JWT.
const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { stmts, SALT_ROUNDS } = require('../config/db');
const { providers, exchangeCode, publicList } = require('../config/oauthProviders');
const { issueSession } = require('../config/tokens');

const router = express.Router();

const FLOW_COOKIE = 'bat_oauth';   // porte state + vérifieur PKCE, le temps de l'aller-retour
const FLOW_TTL_MS = 10 * 60 * 1000;

const base64url = (buf) => buf.toString('base64url');

// PKCE : le vérifieur est un secret aléatoire ; seul son empreinte SHA-256 (le
// challenge) part chez le provider. Un code intercepté est donc inutilisable sans le
// vérifieur, qui n'a jamais quitté le serveur.
function makePkce() {
  const verifier = base64url(crypto.randomBytes(32));
  const challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
  return { verifier, challenge };
}

// Liste des providers configurés, pour l'affichage des boutons.
router.get('/providers', (req, res) => {
  res.json(publicList());
});

// 1) Départ : on fabrique state + PKCE, on les scelle dans un cookie signé, puis on
// redirige vers la page de consentement du provider.
router.get('/:provider', (req, res, next) => {
  const provider = providers[req.params.provider];
  if (!provider) return next(); // laisse Express répondre 404 si le provider est inconnu

  const state = base64url(crypto.randomBytes(16)); // anti-CSRF sur le retour
  const { verifier, challenge } = makePkce();

  // Le flux est signé et à durée de vie courte. sameSite 'lax' et non 'strict' :
  // le retour du provider est une navigation top-level cross-site ; en 'strict' le
  // cookie ne serait pas renvoyé et le state ne pourrait pas être vérifié.
  const flow = jwt.sign(
    { provider: provider.name, state, verifier },
    process.env.JWT_SECRET,
    { expiresIn: FLOW_TTL_MS / 1000 }
  );
  res.cookie(FLOW_COOKIE, flow, {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: FLOW_TTL_MS
  });

  const params = new URLSearchParams({
    client_id: provider.clientId,
    redirect_uri: provider.callbackUrl,
    response_type: 'code',
    scope: provider.scope,
    state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...(provider.extraAuthParams || {})
  });
  res.redirect(`${provider.authorizeUrl}?${params}`);
});

// Dérive un nom d'utilisateur libre à partir du profil externe.
function uniqueUsername(base, providerName) {
  const clean = (base || providerName).replace(/[^A-Za-z0-9_-]/g, '').slice(0, 24) || providerName;
  let candidate = clean.length >= 3 ? clean : `${clean}-${providerName}`;
  let n = 0;
  while (stmts.selectUserByUsername.get(candidate)) {
    n += 1;
    candidate = `${clean}-${providerName}${n > 1 ? n : ''}`.slice(0, 30);
  }
  return candidate;
}

// Retrouve le compte lié, ou en crée un nouveau. Pas de fusion automatique par e-mail :
// laisser un compte Google dont l'e-mail coïncide avec un compte local prendre la main
// dessus serait une prise de contrôle. La liaison ne se fait donc que volontairement,
// depuis une session déjà authentifiée (paramètre link).
function resolveUser(provider, profile, linkUserId) {
  const existing = stmts.selectOAuthAccount.get(provider.name, profile.providerUserId);
  if (existing) return stmts.selectUserById.get(existing.user_id);

  if (linkUserId) {
    // L'utilisateur est déjà connecté et rattache ce provider à son compte.
    stmts.insertOAuthAccount.run(provider.name, profile.providerUserId, linkUserId, profile.email);
    return stmts.selectUserById.get(linkUserId);
  }

  // Première connexion via ce provider : on crée un compte Batcave dédié.
  // Mot de passe aléatoire et inutilisable : ce compte se connecte par le provider,
  // jamais par mot de passe (la colonne est NOT NULL, on la remplit d'un secret perdu).
  const username = uniqueUsername(profile.username, provider.name);
  const unusable = bcrypt.hashSync(crypto.randomBytes(32).toString('hex'), SALT_ROUNDS);
  const info = stmts.insertOAuthUser.run(username, unusable);
  stmts.insertOAuthAccount.run(provider.name, profile.providerUserId, info.lastInsertRowid, profile.email);
  return stmts.selectUserById.get(info.lastInsertRowid);
}

// 2) Retour : on valide, on échange, on identifie, on ouvre la session.
router.get('/:provider/callback', async (req, res, next) => {
  const provider = providers[req.params.provider];
  if (!provider) return next();

  const failure = (msg) => {
    res.clearCookie(FLOW_COOKIE);
    return res.redirect(`/auth/login?error=${encodeURIComponent(msg)}`);
  };

  // Le provider signale lui-même un refus de consentement.
  if (req.query.error) return failure('Connexion externe refusée.');

  const flowCookie = req.cookies?.[FLOW_COOKIE];
  if (!flowCookie) return failure('Flux expiré, réessayez.');

  let flow;
  try {
    flow = jwt.verify(flowCookie, process.env.JWT_SECRET);
  } catch {
    return failure('Flux invalide, réessayez.');
  }

  // Vérification du state : il doit correspondre à celui posé au départ, et concerner
  // le bon provider. C'est la parade CSRF du retour OAuth.
  if (flow.provider !== provider.name || flow.state !== req.query.state) {
    return failure('Validation de sécurité échouée.');
  }
  if (!req.query.code) return failure('Code d\'autorisation manquant.');

  try {
    const accessToken = await exchangeCode(provider, req.query.code, flow.verifier);
    const profile = await provider.fetchProfile(accessToken);
    if (!profile.providerUserId) return failure('Profil externe illisible.');

    // Si une session valide existe déjà, on RATTACHE le provider au compte courant.
    const linkUserId = readCurrentUserId(req);
    const user = resolveUser(provider, profile, linkUserId);

    res.clearCookie(FLOW_COOKIE);
    issueSession(res, user, true); // connexion via provider : badge mémorisé
    stmts.insertLog.run(user.username);
    // Relais same-site : voir GET /auth/complete. Une redirection directe vers
    // /bat-computer perdrait les cookies sameSite 'strict' (chaîne cross-site).
    return res.redirect('/auth/complete');
  } catch (err) {
    console.error(err);
    return failure('Échec de la connexion externe.');
  }
});

// Lecture best-effort de l'utilisateur courant (pour la liaison de compte).
function readCurrentUserId(req) {
  const token = req.cookies?.bat_identity;
  if (!token) return null;
  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);
    return payload.scope === 'access' ? payload.id : null;
  } catch {
    return null;
  }
}

module.exports = router;
