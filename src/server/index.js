const path = require('path');
const express = require('express');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('./database');
const { writeHashToChain } = require('./blockchain');
const {
  validateRegister,
  validateLogin,
  validateSendMessage,
  validateUpdatePublicKey
} = require('./middleware/validation');

const app = express();

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  next();
});

app.use(express.json());
app.use(express.static(path.join(__dirname, '../../public')));

app.get('/verify', (req, res) => {
  res.sendFile(path.join(__dirname, '../../public/verify.html'));
});

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
app.post('/auth/register', validateRegister, async (req, res) => {
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
app.post('/auth/login', validateLogin, async (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) return res.status(401).json({ error: 'Invalid credentials' });

  const match = await argon2.verify(user.password_hash, password);
  if (!match) return res.status(401).json({ error: 'Invalid credentials' });

  const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
  res.json({ token });
});

// PUT /users/pubkey — publish or update the authenticated user's X25519 public key
app.put('/users/pubkey', authenticate, validateUpdatePublicKey, (req, res) => {
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

// POST /messages — send an encrypted message to another user
app.post('/messages', authenticate, validateSendMessage, async (req, res) => {
  const { to, enc, ciphertext } = req.body;

  if (to == null || !enc || !ciphertext)
    return res.status(400).json({ error: 'to, enc, and ciphertext are required' });

  const recipientId = parseInt(to, 10);
  if (isNaN(recipientId) || recipientId <= 0)
    return res.status(400).json({ error: 'to must be a valid user ID' });

  if (typeof enc !== 'string' || !BASE64_RE.test(enc) || enc.length % 4 !== 0)
    return res.status(400).json({ error: 'enc must be a valid base64 string' });

  if (typeof ciphertext !== 'string' || !BASE64_RE.test(ciphertext) || ciphertext.length % 4 !== 0)
    return res.status(400).json({ error: 'ciphertext must be a valid base64 string' });

  const recipient = db.prepare('SELECT id FROM users WHERE id = ?').get(recipientId);
  if (!recipient)
    return res.status(404).json({ error: 'Recipient not found' });

  const txHash = await writeHashToChain(enc, ciphertext);

  const sentAt = new Date().toISOString();
  const result = db.prepare(
    'INSERT INTO messages (sender_id, recipient_id, enc, ciphertext, tx_hash, sent_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(req.user.id, recipientId, enc, ciphertext, txHash, sentAt);

  res.status(201).json({ messageId: result.lastInsertRowid, txHash });
});

// GET /messages — retrieve all inbox and sent messages for the authenticated user
app.get('/messages', authenticate, (req, res) => {
  const rows = db.prepare(
    'SELECT * FROM messages WHERE sender_id = ? OR recipient_id = ?'
  ).all(req.user.id, req.user.id);

  res.json(rows.map(m => ({
    messageId: m.id,
    from: m.sender_id,
    to: m.recipient_id,
    enc: m.enc,
    ciphertext: m.ciphertext,
    txHash: m.tx_hash,
    sentAt: m.sent_at
  })));
});

app.listen(80, () => {
  console.log('Server running on port 80');
});
