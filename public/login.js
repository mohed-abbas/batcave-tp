// Script externe et non inline : la CSP interdit l'exécution de scripts inline,
// c'est justement ce qui neutralise une injection XSS dans la page.
const { postJSON, showError } = window.Batcave;

const feedback = document.getElementById('feedback');
const loginZone = document.getElementById('loginZone');
const otpZone = document.getElementById('otpZone');
const enrollZone = document.getElementById('enrollZone');
const qrImage = document.getElementById('qrImage');

// Mémorisé côté client uniquement pour être renvoyé après le second facteur :
// le serveur ne décide de la durée du cookie qu'à l'émission finale des jetons.
let remember = false;

function show(zone) {
  for (const z of [loginZone, otpZone, enrollZone]) {
    z.classList.toggle('d-none', z !== zone);
  }
}

// Étape 1 : mot de passe.
document.getElementById('loginForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  remember = document.getElementById('remember').checked;

  const res = await postJSON('/auth/login', {
    username: document.getElementById('username').value,
    password: document.getElementById('password').value,
    remember
  });
  const data = await res.json().catch(() => ({}));

  if (data.requires2FA) {
    show(otpZone);
    document.getElementById('otpCode').focus();
    return;
  }

  // 403 : le mot de passe est bon mais le compte n'a pas encore de second facteur.
  if (data.requiresEnrollment) {
    const setup = await postJSON('/auth/setup-2fa', {});
    const setupData = await setup.json().catch(() => ({}));
    if (!setup.ok) {
      showError(feedback, setupData.error || "Échec de l'enrôlement.");
      return;
    }
    qrImage.src = setupData.qrCode;
    show(enrollZone);
    document.getElementById('enrollCode').focus();
    return;
  }

  showError(feedback, data.error || 'Erreur inconnue.');
});

// Étape 2 : code TOTP. C'est la réponse du serveur qui pose les cookies.
document.getElementById('otpForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const res = await postJSON('/auth/verify-2fa', {
    code: document.getElementById('otpCode').value,
    remember
  });

  if (res.ok) {
    window.location.href = '/bat-computer';
    return;
  }
  const data = await res.json().catch(() => ({}));
  showError(document.getElementById('otpFeedback'), data.error || 'Code refusé.');
});

// Enrôlement : le premier code prouve que le téléphone est synchronisé.
document.getElementById('enrollForm').addEventListener('submit', async (event) => {
  event.preventDefault();
  const res = await postJSON('/auth/confirm-2fa', {
    code: document.getElementById('enrollCode').value
  });

  if (res.ok) {
    window.location.href = '/bat-computer';
    return;
  }
  const data = await res.json().catch(() => ({}));
  showError(document.getElementById('enrollFeedback'), data.error || 'Code refusé.');
});
