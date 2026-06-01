const path = require('path');
const express = require('express');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('./database');
const { writeHashToChain } = require('./blockchain');
const {
  validateRegister,
  validateLogin,
  validateChangePassword,
  validateSendMessage,
  validateUpdatePublicKey,
  validateForwardMessage
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

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET environment variable is not set');
  process.exit(1);
}

// Standard base64 (RFC 4648) — matches sodium_base64_VARIANT_ORIGINAL used by CryptoUtils
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

const authenticate = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(401).json({ error: 'Missing or invalid authorization header' });

  const token = authHeader.slice(7);
  try {
    req.user = jwt.verify(token, JWT_SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  const user = db.prepare('SELECT token_version FROM users WHERE id = ?').get(req.user.id);
  if (!user || user.token_version !== req.user.tokenVersion)
    return res.status(401).json({ error: 'Session expired, please log in again' });

  next();
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

  const token = jwt.sign({ id: user.id, username: user.username, tokenVersion: user.token_version }, JWT_SECRET, { expiresIn: '24h' });
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

// GET /messages/:id/download — download a message the authenticated user owns or has access to
app.get('/messages/:id/download', authenticate, (req, res) => {
  const messageId = parseInt(req.params.id, 10);
  if (isNaN(messageId) || messageId <= 0)
    return res.status(400).json({ error: 'Invalid message ID' });

  const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(messageId);
  if (!message)
    return res.status(404).json({ error: 'Message not found' });

  const ownsOrIsRecipient =
    message.sender_id === req.user.id || message.recipient_id === req.user.id;

  if (!ownsOrIsRecipient) {
    const share = db.prepare(
      'SELECT 1 FROM message_shares WHERE message_id = ? AND shared_with_user_id = ?'
    ).get(messageId, req.user.id);
    if (!share)
      return res.status(403).json({ error: 'Access denied' });
  }

  res.json({
    messageId: message.id,
    from: message.sender_id,
    enc: message.enc,
    ciphertext: message.ciphertext,
    txHash: message.tx_hash,
    sentAt: message.sent_at
  });
});

// POST /messages/:id/forward — re-encrypt and forward a message to another user
app.post('/messages/:id/forward', authenticate, validateForwardMessage, async (req, res) => {
  const messageId = parseInt(req.params.id, 10);
  if (isNaN(messageId) || messageId <= 0)
    return res.status(400).json({ error: 'Invalid message ID' });

  const original = db.prepare('SELECT * FROM messages WHERE id = ?').get(messageId);
  if (!original)
    return res.status(404).json({ error: 'Message not found' });

  const ownsOrIsRecipient =
    original.sender_id === req.user.id || original.recipient_id === req.user.id;

  if (!ownsOrIsRecipient) {
    const share = db.prepare(
      'SELECT 1 FROM message_shares WHERE message_id = ? AND shared_with_user_id = ?'
    ).get(messageId, req.user.id);
    if (!share)
      return res.status(403).json({ error: 'Access denied' });
  }

  const { to, enc, ciphertext } = req.body;

  const recipient = db.prepare('SELECT id FROM users WHERE id = ?').get(to);
  if (!recipient)
    return res.status(404).json({ error: 'Recipient not found' });

  const txHash = await writeHashToChain(enc, ciphertext);

  const sentAt = new Date().toISOString();
  const result = db.prepare(
    'INSERT INTO messages (sender_id, recipient_id, enc, ciphertext, tx_hash, sent_at) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(req.user.id, to, enc, ciphertext, txHash, sentAt);

  const newMessageId = result.lastInsertRowid;

  db.prepare(
    'INSERT INTO message_shares (message_id, shared_with_user_id) VALUES (?, ?)'
  ).run(newMessageId, to);

  res.status(201).json({ messageId: newMessageId, txHash });
});

// PUT /auth/password — change the authenticated user's password
app.put('/auth/password', authenticate, validateChangePassword, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'User not found' });

  const match = await argon2.verify(user.password_hash, currentPassword);
  if (!match) return res.status(401).json({ error: 'Current password is incorrect' });

  const newHash = await argon2.hash(newPassword, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 3,
    parallelism: 4
  });

  db.prepare('UPDATE users SET password_hash = ?, token_version = token_version + 1 WHERE id = ?').run(newHash, user.id);

  res.json({ message: 'Password updated successfully' });
});

// DELETE /messages/:id/share/:uid — revoke a user's access to a shared message
app.delete('/messages/:id/share/:uid', authenticate, (req, res) => {
  const messageId = parseInt(req.params.id, 10);
  const targetUserId = parseInt(req.params.uid, 10);

  if (isNaN(messageId) || messageId <= 0)
    return res.status(400).json({ error: 'Invalid message ID' });
  if (isNaN(targetUserId) || targetUserId <= 0)
    return res.status(400).json({ error: 'Invalid user ID' });

  const message = db.prepare('SELECT * FROM messages WHERE id = ?').get(messageId);
  if (!message)
    return res.status(404).json({ error: 'Message not found' });

  if (message.sender_id !== req.user.id)
    return res.status(403).json({ error: 'Access denied' });

  const targetUser = db.prepare('SELECT id FROM users WHERE id = ?').get(targetUserId);
  if (!targetUser)
    return res.status(404).json({ error: 'User not found' });

  db.prepare(
    'DELETE FROM message_shares WHERE message_id = ? AND shared_with_user_id = ?'
  ).run(messageId, targetUserId);

  res.json({ message: 'Access revoked' });
});

app.listen(80, () => {
  console.log('Server running on port 80');
});
