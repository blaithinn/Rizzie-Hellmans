# Rizzie-Hellmans — REST API Documentation

**Base URL:** `https://rizzie-hellmans.theburkenator.com/api/v1`  
**Backend:** Node.js + PostgreSQL  
**Auth:** JWT Bearer token required on all endpoints except `/auth/*` and `/health`

Include the token in the `Authorization` header:
```
Authorization: Bearer <token>
```

---

## Health Check

### `GET /health`
Returns 200 if the server is running. No authentication required.

**Response `200 OK`:**
```json
{ "status": "ok" }
```

---

## Authentication

### `POST /auth/register`
Register a new user. Stores an Argon2id hash of the password and the user's public key.

**Request body:**
```json
{
  "username": "alice",
  "password": "plaintextPassword",
  "publicKey": "<base64-encoded X25519 public key>"
}
```

**Response `201 Created`:**
```json
{
  "userId": "uuid-string"
}
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `400` | Missing or invalid fields |
| `409` | Username already taken |

---

### `POST /auth/login`
Authenticate a user and return a JWT session token.

**Request body:**
```json
{
  "username": "alice",
  "password": "plaintextPassword"
}
```

**Response `200 OK`:**
```json
{
  "token": "<JWT>",
  "expiresIn": 3600
}
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `400` | Missing fields |
| `401` | Invalid username or password |

---

### `PUT /auth/password`
Change the authenticated user's password. Re-hashes with Argon2id and invalidates existing sessions.

**Auth required.**

**Request body:**
```json
{
  "currentPassword": "oldPassword",
  "newPassword": "newPassword"
}
```

**Response `200 OK`:**
```json
{ "message": "Password updated successfully" }
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `401` | Current password incorrect |
| `400` | Missing or invalid fields |

---

## Users

### `GET /users/:id/pubkey`
Fetch a registered user's public key for use in HPKE encryption.

**Auth required.**

**Response `200 OK`:**
```json
{
  "publicKey": "<base64-encoded X25519 public key>"
}
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `404` | User not found |

---

### `PUT /users/pubkey`
Publish or update the authenticated user's public key.

**Auth required.**

**Request body:**
```json
{
  "publicKey": "<base64-encoded X25519 public key>"
}
```

**Response `200 OK`:**
```json
{ "message": "Public key updated" }
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `400` | Missing or invalid publicKey field |

---

## Messages

### `POST /messages`
Send an encrypted message to another user. The server stores only the ciphertext — plaintext is never seen by the server.

On receipt, the server computes `keccak256(enc || ciphertext)`, writes it to the smart contract via `storeHash()`, and stores the returned transaction hash alongside the message.

**Auth required.**

**Request body:**
```json
{
  "to": "recipient-user-id",
  "enc": "<base64-encoded HPKE encapsulated key>",
  "ciphertext": "<base64-encoded HPKE ciphertext>",
  "txHash": "<Ethereum transaction hash (optional — server can compute)"
}
```

**Response `201 Created`:**
```json
{
  "messageId": "uuid-string",
  "txHash": "<Ethereum transaction hash>"
}
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `400` | Missing or malformed fields |
| `404` | Recipient user not found |

---

### `GET /messages`
List all inbox and sent messages for the authenticated user. Returns metadata and ciphertext blobs — decryption happens client-side.

**Auth required.**

**Response `200 OK`:**
```json
[
  {
    "messageId": "uuid-string",
    "from": "sender-user-id",
    "to": "recipient-user-id",
    "enc": "<base64>",
    "ciphertext": "<base64>",
    "txHash": "<Ethereum transaction hash>",
    "sentAt": "2026-05-29T12:00:00Z"
  }
]
```

---

### `DELETE /messages/:id`
Delete a message. The authenticated user must own the message.

**Auth required. Ownership check enforced.**

**Response `200 OK`:**
```json
{ "message": "Message deleted" }
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `403` | User does not own this message |
| `404` | Message not found |

---

### `GET /messages/:id/download`
Download a message the authenticated user owns or has been granted access to.

**Auth required.**

**Response `200 OK`:**
```json
{
  "messageId": "uuid-string",
  "from": "sender-user-id",
  "enc": "<base64>",
  "ciphertext": "<base64>",
  "txHash": "<Ethereum transaction hash>",
  "sentAt": "2026-05-29T12:00:00Z"
}
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `403` | Access denied |
| `404` | Message not found |

---

### `POST /messages/:id/forward`
Re-encrypt and forward a message to another user. The client must verify the recipient's identity (fetch and pin their public key) before re-encrypting.

**Auth required.**

**Request body:**
```json
{
  "to": "recipient-user-id",
  "enc": "<base64-encoded HPKE encapsulated key for new recipient>",
  "ciphertext": "<base64-encoded re-encrypted ciphertext>"
}
```

**Response `201 Created`:**
```json
{
  "messageId": "uuid-string",
  "txHash": "<Ethereum transaction hash>"
}
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `403` | User does not have access to the original message |
| `404` | Message or recipient not found |

---

### `DELETE /messages/:id/share/:uid`
Revoke a specific user's access to a shared message. Only the message owner can do this.

**Auth required. Owner only.**

**Response `200 OK`:**
```json
{ "message": "Access revoked" }
```

**Error responses:**
| Status | Meaning |
|--------|---------|
| `403` | Only the message owner can revoke access |
| `404` | Message or user not found |

---

## Error Format

All error responses follow this structure:
```json
{
  "error": "Human-readable error message"
}
```

---

## Notes

- All request and response bodies are `application/json`
- JWTs expire after 1 hour (`expiresIn: 3600`). Clients should handle `401` responses and prompt re-login
- The server never stores or logs plaintext message content
- The `enc` field is the HPKE ephemeral public key (encapsulated key), required by the recipient for HPKE decapsulation
- Transaction hashes (`txHash`) reference records on the Ethereum Sepolia testnet — verifiable at `/verify`
