// Registre des fournisseurs OAuth2 / OpenID Connect.
// Chaque provider est activé uniquement si son couple client id / secret est présent
// dans le .env : le projet démarre donc même sans aucune clé configurée, et seuls les
// boutons des providers réellement paramétrés apparaissent à l'écran.

const BASE_URL = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;

const callbackUrl = (provider) => `${BASE_URL}/auth/${provider}/callback`;

// GET JSON authentifié par le jeton d'accès du provider.
async function getJSON(url, accessToken, extraHeaders = {}) {
  const res = await fetch(url, {
    headers: {
      Authorization: `Bearer ${accessToken}`,
      Accept: 'application/json',
      'User-Agent': 'Batcave-Security', // exigé par l'API GitHub
      ...extraHeaders
    }
  });
  if (!res.ok) throw new Error(`Profil ${url} -> ${res.status}`);
  return res.json();
}

const definitions = {
  github: {
    label: 'GitHub',
    icon: 'fa-github',
    color: '#24292f',
    authorizeUrl: 'https://github.com/login/oauth/authorize',
    tokenUrl: 'https://github.com/login/oauth/access_token',
    scope: 'read:user user:email',
    async fetchProfile(accessToken) {
      const user = await getJSON('https://api.github.com/user', accessToken);
      let email = user.email;
      // L'e-mail GitHub peut être privé : on le récupère alors via l'endpoint dédié.
      if (!email) {
        const emails = await getJSON('https://api.github.com/user/emails', accessToken);
        const primary = emails.find((e) => e.primary && e.verified) || emails.find((e) => e.verified);
        email = primary?.email || null;
      }
      return { providerUserId: String(user.id), username: user.login, email };
    }
  },

  google: {
    label: 'Google',
    icon: 'fa-google',
    color: '#4285f4',
    authorizeUrl: 'https://accounts.google.com/o/oauth2/v2/auth',
    tokenUrl: 'https://oauth2.googleapis.com/token',
    scope: 'openid email profile',
    // access_type/prompt propres à Google, ajoutés à l'URL d'autorisation.
    extraAuthParams: { access_type: 'online', prompt: 'select_account' },
    async fetchProfile(accessToken) {
      // Endpoint OIDC standard userinfo (le jeton donne accès aux claims du profil).
      const info = await getJSON('https://openidconnect.googleapis.com/v1/userinfo', accessToken);
      return {
        providerUserId: info.sub,
        username: (info.email || info.name || 'google').split('@')[0],
        email: info.email || null
      };
    }
  },

  discord: {
    label: 'Discord',
    icon: 'fa-discord',
    color: '#5865f2',
    authorizeUrl: 'https://discord.com/api/oauth2/authorize',
    tokenUrl: 'https://discord.com/api/oauth2/token',
    scope: 'identify email',
    async fetchProfile(accessToken) {
      const user = await getJSON('https://discord.com/api/users/@me', accessToken);
      return { providerUserId: user.id, username: user.username, email: user.email || null };
    }
  }
};

// N'expose que les providers dont les identifiants sont configurés.
const providers = {};
for (const [name, def] of Object.entries(definitions)) {
  const clientId = process.env[`${name.toUpperCase()}_CLIENT_ID`];
  const clientSecret = process.env[`${name.toUpperCase()}_CLIENT_SECRET`];
  if (clientId && clientSecret) {
    providers[name] = { name, clientId, clientSecret, callbackUrl: callbackUrl(name), ...def };
  }
}

// Échange le code d'autorisation contre un jeton d'accès (avec le vérifieur PKCE).
async function exchangeCode(provider, code, codeVerifier) {
  const body = new URLSearchParams({
    grant_type: 'authorization_code',
    code,
    redirect_uri: provider.callbackUrl,
    client_id: provider.clientId,
    client_secret: provider.clientSecret,
    code_verifier: codeVerifier
  });

  const res = await fetch(provider.tokenUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' },
    body
  });
  if (!res.ok) throw new Error(`Échange de code ${provider.name} -> ${res.status}`);

  const data = await res.json();
  if (!data.access_token) throw new Error(`Pas de jeton d'accès renvoyé par ${provider.name}`);
  return data.access_token;
}

// Liste destinée à l'affichage des boutons (jamais le secret côté client).
function publicList() {
  return Object.values(providers).map(({ name, label, icon, color }) => ({ name, label, icon, color }));
}

module.exports = { providers, exchangeCode, publicList, BASE_URL };
