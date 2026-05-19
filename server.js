const express = require('express');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;

const db = new Database(path.join(__dirname, 'database.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'USER'
  );

  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    content TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
  );

  CREATE TABLE IF NOT EXISTS logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
  );
`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

const GADGETS = [
  { name: 'Batarang', desc: 'Arme de jet', icon: 'fa-shuriken' },
  { name: 'Grappin', desc: 'Deplacement vertical', icon: 'fa-anchor' },
  { name: 'Bat-Signal', desc: "Communication d'urgence", icon: 'fa-bullhorn' },
  { name: 'Smoke Pellets', desc: 'Esquive tactique', icon: 'fa-cloud' },
  { name: 'Cles Batmobile', desc: 'Vehicule blinde', icon: 'fa-car' },
  { name: 'Gel Explosif', desc: 'Demolition controlee', icon: 'fa-bomb' }
];

app.post('/register', async (req, res) => {
  const rawUsername = (req.body.username ?? '').toString();
  const password = (req.body.password ?? '').toString();
  const username = rawUsername.trim();

  if (!username || /\s/.test(username)) {
    return res.status(400).json({ error: "Le nom d'utilisateur ne doit pas contenir d'espaces." });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit faire au moins 8 caracteres.' });
  }

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const stmt = db.prepare('INSERT INTO users (username, password) VALUES (?, ?)');
    const info = stmt.run(username, hash);
    return res.status(201).json({ id: info.lastInsertRowid, username });
  } catch (err) {
    if (err && err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: "Nom d'utilisateur deja utilise." });
    }
    console.error(err);
    return res.status(500).json({ error: 'Erreur serveur.' });
  }
});

async function basicAuth(req, res, next) {
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Basic ')) {
    res.set('WWW-Authenticate', 'Basic realm="Batcave"');
    return res.status(401).json({ error: 'Authentification requise.' });
  }

  let decoded;
  try {
    decoded = Buffer.from(header.slice(6), 'base64').toString('utf-8');
  } catch {
    res.set('WWW-Authenticate', 'Basic realm="Batcave"');
    return res.status(401).json({ error: 'En-tete invalide.' });
  }

  const sep = decoded.indexOf(':');
  if (sep < 0) {
    res.set('WWW-Authenticate', 'Basic realm="Batcave"');
    return res.status(401).json({ error: 'En-tete invalide.' });
  }
  const username = decoded.slice(0, sep);
  const password = decoded.slice(sep + 1);

  const user = db.prepare('SELECT id, username, password, role FROM users WHERE username = ?').get(username);
  if (!user) {
    res.set('WWW-Authenticate', 'Basic realm="Batcave"');
    return res.status(401).json({ error: 'Identifiants invalides.' });
  }

  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    res.set('WWW-Authenticate', 'Basic realm="Batcave"');
    return res.status(401).json({ error: 'Identifiants invalides.' });
  }

  if (user.role !== 'ADMIN') {
    return res.status(403).json({ error: 'Acces refuse' });
  }

  req.user = { id: user.id, username: user.username, role: user.role };
  db.prepare('INSERT INTO logs (username) VALUES (?)').run(user.username);
  next();
}

app.get('/bat-computer', basicAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'private', 'bat-computer.html'));
});

app.get('/api/secrets', basicAuth, (req, res) => {
  res.json(GADGETS);
});

app.get('/api/me', basicAuth, (req, res) => {
  res.json({ id: req.user.id, username: req.user.username });
});

app.post('/api/reports', basicAuth, (req, res) => {
  const content = (req.body.content ?? '').toString().trim();
  if (!content) {
    return res.status(400).json({ error: 'Le rapport ne peut etre vide.' });
  }
  const info = db
    .prepare('INSERT INTO reports (user_id, content) VALUES (?, ?)')
    .run(req.user.id, content);
  return res.status(201).json({ id: info.lastInsertRowid, user_id: req.user.id, content });
});

app.get('/logout', (req, res) => {
  res.status(200).json({ message: 'Deconnexion effectuee. Credentials a effacer cote client.' });
});

app.get('/', (req, res) => res.redirect('/register.html'));

app.listen(PORT, () => {
  console.log(`Batcave security online: http://localhost:${PORT}`);
});
