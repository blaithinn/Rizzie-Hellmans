const express = require('express');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const db = require('./database');

const app = express();
app.use(express.json());

const JWT_SECRET = 'change-this-to-a-random-string-later';

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Register
app.post('/auth/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Username and password required' });

  try {
    const hash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,   // 64MB
      timeCost: 3,
      parallelism: 4
    });
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)').run(username, hash);
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

app.listen(80, () => {
  console.log('Server running on port 80');
});
