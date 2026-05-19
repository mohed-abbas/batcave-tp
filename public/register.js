const form = document.getElementById('registerForm');
const feedback = document.getElementById('feedback');

function showMessage(type, msg) {
  feedback.innerHTML = `<div class="alert alert-${type} mb-0">${msg}</div>`;
}

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  feedback.innerHTML = '';

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  try {
    const res = await fetch('/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    });

    const data = await res.json().catch(() => ({}));

    if (res.status === 201) {
      showMessage('success', `Bienvenue, Justicier <strong>${data.username}</strong> ! <br/>Vous pouvez maintenant vous connecter au <a href="/bat-computer" class="alert-link">Bat-Ordinateur</a>.`);
      form.reset();
    } else if (res.status === 409) {
      showMessage('warning', data.error || "Nom d'utilisateur déjà utilisé.");
    } else if (res.status === 400) {
      showMessage('danger', data.error || 'Données invalides.');
    } else {
      showMessage('danger', data.error || 'Erreur inconnue.');
    }
  } catch (err) {
    showMessage('danger', 'Impossible de joindre le serveur.');
  }
});
