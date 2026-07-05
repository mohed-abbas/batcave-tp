// Initialisation unique de la base SQLite + schéma + requêtes préparées.
// Tout module qui fait `require('./config/db')` partage la MÊME connexion.
const bcrypt = require('bcrypt');
const Database = require('better-sqlite3');
const path = require('path');

const SALT_ROUNDS = 10;
const ROLES = Object.freeze({ ADMIN: 'ADMIN', USER: 'USER' });

const db = new Database(path.join(__dirname, '..', 'database.db'));
db.pragma('journal_mode = WAL');   // écritures concurrentes plus sûres
db.pragma('foreign_keys = ON');    // contraintes de clés étrangères appliquées

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

// Requêtes préparées : compilées une fois, paramétrées (?) => anti-injection SQL.
const stmts = {
  insertUser: db.prepare('INSERT INTO users (username, password) VALUES (?, ?)'),
  insertAdmin: db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'ADMIN')"),
  selectUserByUsername: db.prepare('SELECT id, username, password, role FROM users WHERE username = ?'),
  countUsers: db.prepare('SELECT COUNT(*) AS c FROM users'),
  insertReport: db.prepare('INSERT INTO reports (user_id, content) VALUES (?, ?)'),
  insertLog: db.prepare('INSERT INTO logs (username) VALUES (?)')
};

// Bootstrap : crée l'ADMIN par défaut au tout premier démarrage (base vide).
const DEFAULT_ADMIN = { username: 'admin', password: 'batcave2026' };
if (stmts.countUsers.get().c === 0) {
  const hash = bcrypt.hashSync(DEFAULT_ADMIN.password, SALT_ROUNDS);
  stmts.insertAdmin.run(DEFAULT_ADMIN.username, hash);
  console.log(`Default ADMIN created: ${DEFAULT_ADMIN.username} / ${DEFAULT_ADMIN.password}`);
}

module.exports = { db, stmts, SALT_ROUNDS, ROLES };
