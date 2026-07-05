const { escapeHTML, postJSON } = window.Batcave;

const STATUS_TO_ALERT = { 201: 'success', 400: 'danger', 409: 'warning' };

const form = document.getElementById('registerForm');
const feedback = document.getElementById('feedback');

function showMessage(type, html) {
  feedback.innerHTML = `<div class="alert alert-${type} mb-0">${html}</div>`;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  feedback.innerHTML = '';

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  try {
    const res = await postJSON('/auth/register', { username, password });
    const data = await res.json().catch(() => ({}));
    const type = STATUS_TO_ALERT[res.status] || 'danger';

    if (res.status === 201) {
      showMessage(type,
        `Bienvenue, Justicier <strong>${escapeHTML(data.username)}</strong> ! <br/>` +
        `Vous pouvez maintenant vous <a href="/auth/login" class="alert-link">connecter</a>.`);
      form.reset();
    } else {
      showMessage(type, escapeHTML(data.error || 'Erreur inconnue.'));
    }
  } catch {
    showMessage('danger', 'Impossible de joindre le serveur.');
  }
});
