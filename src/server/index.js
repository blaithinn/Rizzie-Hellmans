const express = require('express');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('./database');

const app = express();
app.use(express.json());

const JWT_SECRET = 'change-this-to-a-random-string-later';

// Standard base64 (RFC 4648) — matches sodium_base64_VARIANT_ORIGINAL used by CryptoUtils
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(401).json({ error: 'Missing or invalid authorization header' });

  const token = authHeader.slice(7);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Register
app.post('/auth/register', async (req, res) => {
  const { username, password, publicKey } = req.body;  
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });
    if (publicKey && (typeof publicKey !== 'string' || !BASE64_RE.test(publicKey) || publicKey.length % 4 !== 0))
    return res.status(400).json({ error: 'publicKey must be a valid base64 string' });
  try {
    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,   // 64MB
      timeCost: 3,
      parallelism: 4
    });
    db.prepare('INSERT INTO users (username, password_hash, public_key) VALUES (?, ?, ?)').run(username, hash, publicKey || null);
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(409).json({ error: 'Username already taken' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const match = await argon2.verify(user.password_hash, password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// PUT /users/pubkey — publish or update the authenticated user's X25519 public key
app.put('/users/pubkey', authenticate, (req, res) => {
  const { publicKey } = req.body;
  if (!publicKey || typeof publicKey !== 'string')
    return res.status(400).json({ error: 'publicKey is required' });
  if (!BASE64_RE.test(publicKey) || publicKey.length % 4 !== 0)
    return res.status(400).json({ error: 'publicKey must be a valid base64 string' });

  db.prepare('UPDATE users SET public_key = ? WHERE id = ?').run(publicKey, req.user.id);
  res.json({ message: 'Public key updated' });
});

// GET /users/:id/pubkey — fetch a user's X25519 public key by user ID
app.get('/users/:id/pubkey', authenticate, (req, res) => {
  const user = db.prepare('SELECT public_key FROM users WHERE id = ?').get(req.params.id);
  if (!user) return res.status(404).json({ error: 'User not found' });
  if (!user.public_key) return res.status(404).json({ error: 'User has not published a public key' });
  res.json({ publicKey: user.public_key });
});

app.listen(80, () => {
  console.log('Server running on port 80');
});
