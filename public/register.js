const { postJSON, showError } = window.Batcave;

const form = document.getElementById('registerForm');
const feedback = document.getElementById('feedback');

// Construit le message de succès par le DOM : le pseudo saisi reste du texte,
// même s'il contient des balises.
function showWelcome(username) {
  const alert = document.createElement('div');
  alert.className = 'alert alert-success mb-0';

  const name = document.createElement('strong');
  name.textContent = username;

  const link = document.createElement('a');
  link.href = '/auth/login';
  link.className = 'alert-link';
  link.textContent = 'connecter';

  alert.append('Bienvenue, Justicier ', name, ' ! Vous pouvez maintenant vous ', link, '.');
  feedback.replaceChildren(alert);
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  feedback.replaceChildren();

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  try {
    const res = await postJSON('/auth/register', { username, password });
    const data = await res.json().catch(() => ({}));

    if (res.status === 201) {
      showWelcome(data.username);
      form.reset();
      return;
    }
    showError(feedback, data.error || 'Erreur inconnue.', res.status === 409 ? 'warning' : 'danger');
  } catch {
    showError(feedback, 'Impossible de joindre le serveur.');
  }
});
