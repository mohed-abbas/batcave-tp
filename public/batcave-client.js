(function () {
  // Les jetons voyagent dans des cookies httpOnly : le navigateur les joint tout seul,
  // et ce script est incapable de les lire (c'est précisément la parade anti-XSS).

  function escapeHTML(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Affiche un message sans jamais interpréter son contenu comme du HTML.
  function showError(container, message, type = 'danger') {
    const alert = document.createElement('div');
    alert.className = `alert alert-${type} py-2 small mb-0`;
    alert.textContent = message;
    container.replaceChildren(alert);
  }

  async function postJSON(url, body) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  }

  // Rejeu transparent : un 401 signifie « jeton d'accès périmé ». On tente un
  // renouvellement puis on rejoue la requête initiale. L'utilisateur ne voit rien.
  let refreshing = null;

  async function fetchWithRetry(url, options = {}) {
    let response = await fetch(url, options);
    if (response.status !== 401) return response;

    // Plusieurs requêtes peuvent échouer en même temps : on ne veut qu'un seul /refresh.
    refreshing = refreshing || fetch('/auth/refresh', { method: 'POST' })
      .finally(() => { refreshing = null; });
    const refreshed = await refreshing;

    if (!refreshed.ok) {
      // refreshToken expiré ou révoqué : la partie est finie, retour au login.
      window.location.href = '/auth/login';
      return response;
    }

    return fetch(url, options);
  }

  window.Batcave = { escapeHTML, showError, postJSON, fetchWithRetry };
})();
