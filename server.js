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
    password TEXT NOT NULL
  );
`);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));

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

app.get('/', (req, res) => res.redirect('/register.html'));

app.listen(PORT, () => {
  console.log(`Batcave security online: http://localhost:${PORT}`);
});
