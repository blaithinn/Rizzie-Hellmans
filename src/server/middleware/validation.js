// Standard base64 (RFC 4648) — same pattern used in index.js for consistency
const BASE64_RE = /^[A-Za-z0-9+/]+={0,2}$/;

// Only alphanumeric and underscores permitted in usernames
const USERNAME_RE = /^[A-Za-z0-9_]+$/;

// SQL keywords that are forbidden in usernames as an extra semantic guard
const SQL_KEYWORDS_RE = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|TRUNCATE|UNION|EXEC|FROM|WHERE|INTO|TABLE|DATABASE|GRANT|REVOKE|HAVING|ORDER|GROUP|JOIN|LIMIT|OFFSET|SET|DECLARE|CAST|CONVERT)\b/i;

function isValidBase64(str) {
  return typeof str === 'string' &&
    str.length > 0 &&
    BASE64_RE.test(str) &&
    str.length % 4 === 0;
}

function validateRegister(req, res, next) {
  let { username, password, publicKey } = req.body;

  if (typeof username !== 'string' || !username.trim())
    return res.status(400).json({ error: 'username is required' });
  username = username.trim();

  if (!USERNAME_RE.test(username))
    return res.status(400).json({ error: 'username must contain only letters, numbers, and underscores' });

  if (SQL_KEYWORDS_RE.test(username))
    return res.status(400).json({ error: 'username contains a reserved word' });

  if (username.length < 3 || username.length > 30)
    return res.status(400).json({ error: 'username must be between 3 and 30 characters' });

  if (typeof password !== 'string' || !password.trim())
    return res.status(400).json({ error: 'password is required' });
  password = password.trim();

  if (password.length < 8)
    return res.status(400).json({ error: 'password must be at least 8 characters' });

  if (publicKey !== undefined && publicKey !== null) {
    if (!isValidBase64(publicKey))
      return res.status(400).json({ error: 'publicKey must be a valid base64 string' });
  }

  req.body.username = username;
  req.body.password = password;
  next();
}

function validateLogin(req, res, next) {
  let { username, password } = req.body;

  if (typeof username !== 'string' || !username.trim())
    return res.status(400).json({ error: 'username is required' });
  username = username.trim();

  if (typeof password !== 'string' || !password.trim())
    return res.status(400).json({ error: 'password is required' });
  password = password.trim();

  req.body.username = username;
  req.body.password = password;
  next();
}

function validateChangePassword(req, res, next) {
  let { currentPassword, newPassword } = req.body;

  if (typeof currentPassword !== 'string' || !currentPassword.trim())
    return res.status(400).json({ error: 'currentPassword is required' });
  currentPassword = currentPassword.trim();

  if (typeof newPassword !== 'string' || !newPassword.trim())
    return res.status(400).json({ error: 'newPassword is required' });
  newPassword = newPassword.trim();

  if (newPassword.length < 8)
    return res.status(400).json({ error: 'newPassword must be at least 8 characters' });

  req.body.currentPassword = currentPassword;
  req.body.newPassword = newPassword;
  next();
}

function validateSendMessage(req, res, next) {
  const { to, enc, ciphertext } = req.body;

  if (to == null)
    return res.status(400).json({ error: 'to is required' });

  const recipientId = parseInt(to, 10);
  if (!Number.isInteger(recipientId) || recipientId <= 0)
    return res.status(400).json({ error: 'to must be a positive integer user ID' });

  if (!isValidBase64(enc))
    return res.status(400).json({ error: 'enc must be a valid base64 string' });

  if (!isValidBase64(ciphertext))
    return res.status(400).json({ error: 'ciphertext must be a valid base64 string' });

  req.body.to = recipientId;
  next();
}

function validateUpdatePublicKey(req, res, next) {
  const { publicKey } = req.body;

  if (!isValidBase64(publicKey))
    return res.status(400).json({ error: 'publicKey must be a valid base64 string' });

  next();
}

function validateForwardMessage(req, res, next) {
  const { to, enc, ciphertext } = req.body;

  if (to == null)
    return res.status(400).json({ error: 'to is required' });

  const recipientId = parseInt(to, 10);
  if (!Number.isInteger(recipientId) || recipientId <= 0)
    return res.status(400).json({ error: 'to must be a positive integer user ID' });

  if (!isValidBase64(enc))
    return res.status(400).json({ error: 'enc must be a valid base64 string' });

  if (!isValidBase64(ciphertext))
    return res.status(400).json({ error: 'ciphertext must be a valid base64 string' });

  req.body.to = recipientId;
  next();
}

module.exports = {
  validateRegister,
  validateLogin,
  validateChangePassword,
  validateSendMessage,
  validateUpdatePublicKey,
  validateForwardMessage
};
