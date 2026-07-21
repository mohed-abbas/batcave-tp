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

  -- Seul état conservé côté serveur : il rend la révocation possible (un JWT, lui,
  -- reste valide jusqu'à sa date d'expiration quoi qu'on fasse).
  CREATE TABLE IF NOT EXISTS refresh_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT UNIQUE NOT NULL,
    user_id INTEGER NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  -- Rattachement d'une identité externe (OAuth2/OIDC) à un compte Batcave.
  -- La contrainte d'unicité (provider, provider_user_id) empêche qu'un même compte
  -- Google/GitHub/Discord soit lié à deux comptes locaux.
  CREATE TABLE IF NOT EXISTS oauth_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    provider TEXT NOT NULL,
    provider_user_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    email TEXT,
    linked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE (provider, provider_user_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );
`);

// Migration : les comptes créés avant le TP4 n'ont pas les colonnes 2FA.
// two_factor_secret est la clé TOTP (K) ; two_factor_enabled ne passe à 1 qu'une fois
// la synchronisation prouvée par un premier code valide.
const userColumns = db.prepare('PRAGMA table_info(users)').all().map((c) => c.name);
if (!userColumns.includes('two_factor_secret')) {
  db.exec('ALTER TABLE users ADD COLUMN two_factor_secret TEXT');
}
if (!userColumns.includes('two_factor_enabled')) {
  db.exec('ALTER TABLE users ADD COLUMN two_factor_enabled INTEGER NOT NULL DEFAULT 0');
}

// Requêtes préparées : compilées une fois, paramétrées (?) => anti-injection SQL.
const stmts = {
  insertUser: db.prepare('INSERT INTO users (username, password) VALUES (?, ?)'),
  insertAdmin: db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'ADMIN')"),
  selectUserByUsername: db.prepare(
    'SELECT id, username, password, role, two_factor_secret, two_factor_enabled FROM users WHERE username = ?'
  ),
  countUsers: db.prepare('SELECT COUNT(*) AS c FROM users'),
  selectUserById: db.prepare(
    'SELECT id, username, role, two_factor_secret, two_factor_enabled FROM users WHERE id = ?'
  ),
  setTwoFactorSecret: db.prepare('UPDATE users SET two_factor_secret = ?, two_factor_enabled = 0 WHERE id = ?'),
  enableTwoFactor: db.prepare('UPDATE users SET two_factor_enabled = 1 WHERE id = ?'),
  selectLogs: db.prepare('SELECT username, timestamp FROM logs ORDER BY id DESC LIMIT 50'),
  insertOAuthUser: db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, 'USER')"),
  selectOAuthAccount: db.prepare(
    'SELECT user_id FROM oauth_accounts WHERE provider = ? AND provider_user_id = ?'
  ),
  insertOAuthAccount: db.prepare(
    'INSERT INTO oauth_accounts (provider, provider_user_id, user_id, email) VALUES (?, ?, ?, ?)'
  ),
  selectOAuthAccountsByUser: db.prepare(
    'SELECT provider, email, linked_at FROM oauth_accounts WHERE user_id = ? ORDER BY linked_at'
  ),
  insertReport: db.prepare('INSERT INTO reports (user_id, content) VALUES (?, ?)'),
  insertLog: db.prepare('INSERT INTO logs (username) VALUES (?)'),
  insertRefreshToken: db.prepare('INSERT INTO refresh_tokens (token, user_id, expires_at) VALUES (?, ?, ?)'),
  selectRefreshToken: db.prepare('SELECT token, user_id, expires_at FROM refresh_tokens WHERE token = ?'),
  deleteRefreshToken: db.prepare('DELETE FROM refresh_tokens WHERE token = ?'),
  deleteExpiredRefreshTokens: db.prepare("DELETE FROM refresh_tokens WHERE expires_at < datetime('now')")
};

// Bootstrap : crée l'ADMIN par défaut au tout premier démarrage (base vide).
const DEFAULT_ADMIN = { username: 'admin', password: 'batcave2026' };
if (stmts.countUsers.get().c === 0) {
  const hash = bcrypt.hashSync(DEFAULT_ADMIN.password, SALT_ROUNDS);
  stmts.insertAdmin.run(DEFAULT_ADMIN.username, hash);
  console.log(`Default ADMIN created: ${DEFAULT_ADMIN.username} / ${DEFAULT_ADMIN.password}`);
}

module.exports = { db, stmts, SALT_ROUNDS, ROLES };
