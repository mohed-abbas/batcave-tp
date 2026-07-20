// Script externe : la CSP interdit les scripts inline.
// fetchWithRetry absorbe l'expiration du jeton d'accès sans que l'utilisateur le voie.
const { postJSON, fetchWithRetry } = window.Batcave;

// Construction par le DOM plutôt que par innerHTML : le texte reste du texte,
// il n'est jamais réinterprété comme du HTML (parade XSS).
function gadgetCard(gadget) {
  const col = document.createElement('div');
  col.className = 'col-12 col-sm-6 col-lg-4';

  const card = document.createElement('div');
  card.className = 'card gadget-card p-4 text-center';

  const icon = document.createElement('i');
  icon.className = `fa-solid gadget-icon mb-3 ${gadget.icon}`;

  const title = document.createElement('h5');
  title.className = 'card-title';
  title.textContent = gadget.name;

  const desc = document.createElement('p');
  desc.className = 'card-text text-muted';
  desc.textContent = gadget.desc;

  card.append(icon, title, desc);
  col.append(card);
  return col;
}

async function loadArsenal() {
  const arsenal = document.getElementById('arsenal');
  const res = await fetchWithRetry('/api/secrets');
  if (!res.ok) {
    arsenal.textContent = "Accès refusé à l'arsenal.";
    return;
  }
  const gadgets = await res.json();
  arsenal.replaceChildren(...gadgets.map(gadgetCard));
}

// Le journal n'est demandé que si le rôle le permet ; en cas de 403 la zone reste
// masquée. La vraie barrière reste checkRole('ADMIN') côté serveur.
async function loadAdminZone() {
  const me = await fetchWithRetry('/api/me');
  if (!me.ok) return;
  const { role } = await me.json();
  if (role !== 'ADMIN') return;

  const res = await fetchWithRetry('/api/logs');
  if (!res.ok) return;

  const logs = await res.json();
  const list = document.getElementById('logList');
  list.replaceChildren(...logs.map((entry) => {
    const item = document.createElement('li');
    item.className = 'list-group-item bg-transparent text-light d-flex justify-content-between';

    const who = document.createElement('span');
    who.textContent = entry.username;

    const when = document.createElement('span');
    when.className = 'text-muted small';
    when.textContent = entry.timestamp;

    item.append(who, when);
    return item;
  }));
  document.getElementById('adminZone').classList.remove('d-none');
}

document.getElementById('reportForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const content = document.getElementById('reportContent').value.trim();
  const feedback = document.getElementById('reportFeedback');

  if (!content) {
    feedback.className = 'ms-3 text-warning';
    feedback.textContent = 'Rapport vide.';
    return;
  }

  const res = await fetchWithRetry('/api/reports', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ content })
  });

  if (res.ok) {
    feedback.className = 'ms-3 text-success';
    feedback.textContent = 'Rapport enregistré.';
    document.getElementById('reportContent').value = '';
  } else {
    feedback.className = 'ms-3 text-danger';
    feedback.textContent = "Échec de l'enregistrement.";
  }
});

// Déconnexion en POST : le serveur supprime le refreshToken en base (révocation
// réelle) puis efface les cookies.
document.getElementById('logoutBtn').addEventListener('click', async () => {
  await postJSON('/auth/logout', {});
  window.location.href = '/auth/login';
});

loadArsenal();
loadAdminZone();
