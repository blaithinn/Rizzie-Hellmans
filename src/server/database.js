const Database = require('better-sqlite3');
const db = new Database('users.db');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    public_key TEXT
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    enc TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    tx_hash TEXT,
    sent_at TEXT NOT NULL
  )
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS message_shares (
    message_id INTEGER NOT NULL,
    shared_with_user_id INTEGER NOT NULL,
    PRIMARY KEY (message_id, shared_with_user_id),
    FOREIGN KEY (message_id) REFERENCES messages(id),
    FOREIGN KEY (shared_with_user_id) REFERENCES users(id)
  )
`);

module.exports = db;
