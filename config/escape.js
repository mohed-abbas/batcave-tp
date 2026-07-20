// Échappement HTML côté serveur : toute donnée venant d'un utilisateur passe par ici
// avant d'être injectée dans un gabarit. Neutralise les caractères qui permettraient
// de refermer une balise et d'ouvrir un <script>.
const ENTITIES = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, (char) => ENTITIES[char]);
}

module.exports = { escapeHTML };
