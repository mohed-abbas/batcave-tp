const express = require('express');
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const SALT_ROUNDS = 10;
const ROLES = Object.freeze({ ADMIN: 'ADMIN', USER: 'USER' });

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

const stmts = {
  insertUser: db.prepare('INSERT INTO users (username, password) VALUES (?, ?)'),
  insertAdmin: db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'ADMIN')"),
  selectUserByUsername: db.prepare('SELECT id, username, password, role FROM users WHERE username = ?'),
  countUsers: db.prepare('SELECT COUNT(*) AS c FROM users'),
  insertReport: db.prepare('INSERT INTO reports (user_id, content) VALUES (?, ?)'),
  insertLog: db.prepare('INSERT INTO logs (username) VALUES (?)')
};

const DEFAULT_ADMIN = { username: 'admin', password: 'batcave2026' };
if (stmts.countUsers.get().c === 0) {
  const hash = bcrypt.hashSync(DEFAULT_ADMIN.password, SALT_ROUNDS);
  stmts.insertAdmin.run(DEFAULT_ADMIN.username, hash);
  console.log(`Default ADMIN created: ${DEFAULT_ADMIN.username} / ${DEFAULT_ADMIN.password}`);
}

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

const asString = (v) => (v ?? '').toString();

function unauthorized(res, error) {
  res.set('WWW-Authenticate', 'Basic realm="Batcave"');
  return res.status(401).json({ error });
}

app.post('/register', async (req, res) => {
  const username = asString(req.body.username).trim();
  const password = asString(req.body.password);

  if (!username || /\s/.test(username)) {
    return res.status(400).json({ error: "Le nom d'utilisateur ne doit pas contenir d'espaces." });
  }
  if (password.length < 8) {
    return res.status(400).json({ error: 'Le mot de passe doit faire au moins 8 caracteres.' });
  }

  try {
    const hash = await bcrypt.hash(password, SALT_ROUNDS);
    const info = stmts.insertUser.run(username, hash);
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
    return unauthorized(res, 'Authentification requise.');
  }

  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf-8');
  const sep = decoded.indexOf(':');
  if (sep < 0) {
    return unauthorized(res, 'En-tete invalide.');
  }
  const username = decoded.slice(0, sep);
  const password = decoded.slice(sep + 1);

  const user = stmts.selectUserByUsername.get(username);
  // Always run bcrypt.compare to keep timing roughly constant and avoid user enumeration.
  const passwordOk = user ? await bcrypt.compare(password, user.password) : false;
  if (!user || !passwordOk) {
    return unauthorized(res, 'Identifiants invalides.');
  }

  if (user.role !== ROLES.ADMIN) {
    return res.status(403).json({ error: 'Acces refuse' });
  }

  req.user = { id: user.id, username: user.username, role: user.role };
  stmts.insertLog.run(user.username);
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
  const content = asString(req.body.content).trim();
  if (!content) {
    return res.status(400).json({ error: 'Le rapport ne peut etre vide.' });
  }
  const info = stmts.insertReport.run(req.user.id, content);
  return res.status(201).json({ id: info.lastInsertRowid, user_id: req.user.id, content });
});

app.get('/logout', (req, res) => {
  res.status(200).json({ message: 'Deconnexion effectuee. Credentials a effacer cote client.' });
});

app.get('/', (req, res) => res.redirect('/register.html'));

app.listen(PORT, () => {
  console.log(`Batcave security online: http://localhost:${PORT}`);
});
