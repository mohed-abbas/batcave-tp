(function () {
  // Auth désormais portée par le cookie de session (envoyé automatiquement).
  // Plus de sessionStorage ni d'en-tête Authorization à gérer côté client.

  function escapeHTML(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  async function postJSON(url, body) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  }

  window.Batcave = { escapeHTML, postJSON };
})();
