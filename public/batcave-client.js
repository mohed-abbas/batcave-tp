(function () {
  const CREDS_KEY = 'batcave_creds';

  const creds = {
    get: () => sessionStorage.getItem(CREDS_KEY),
    set: (value) => sessionStorage.setItem(CREDS_KEY, value),
    clear: () => sessionStorage.removeItem(CREDS_KEY)
  };

  function authHeaders(extra = {}) {
    const c = creds.get();
    return c ? { Authorization: 'Basic ' + c, ...extra } : extra;
  }

  function escapeHTML(value) {
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  async function postJSON(url, body, extraHeaders = {}) {
    return fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...extraHeaders },
      body: JSON.stringify(body)
    });
  }

  window.Batcave = { creds, authHeaders, escapeHTML, postJSON };
})();
