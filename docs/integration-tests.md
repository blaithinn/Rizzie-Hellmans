# Rizzie-Hellmans — Integration Test Suite

**Project:** CS4455 Cybersecurity — Epic Project 2026, Team 18  
**Authors:** Blaithin Kavanagh, Rose McInerney  
**Purpose:** Manual end-to-end test cases covering every aspect of the application — REST API, web frontend, C++ CLI, and blockchain verification.

---

## How to Use This Document

- Tests are grouped by feature area. Work through each section in order, as later sections often depend on accounts or messages created earlier.
- Every test has a **Setup** (pre-conditions), numbered **Steps**, and an **Expected result**.
- Checkboxes (`- [ ]`) let you tick off tests as you go.
- **API tests** use `curl`. Set the shell variables at the top of each session and copy-paste commands directly.
- **UI tests** describe browser interactions step by step.
- **C++ CLI tests** describe terminal interactions step by step.

---

## 0. Environment Setup

### 0.1 Prerequisites

| Item | Requirement |
|------|-------------|
| Node.js | v18 or later |
| npm | v9 or later |
| C++ compiler | GCC 11+ or Clang 13+ (Linux/macOS only) |
| CMake | 3.16+ |
| libsodium | **1.0.19** (must build from source on Ubuntu — the apt package is 1.0.18 and is missing HKDF APIs) |
| libcurl | HTTPS-enabled build |
| Browser | Any modern browser with Web Crypto API support (Chrome, Firefox, Edge, Safari) |
| curl | CLI tool for API tests |

### 0.2 Starting / Managing the Server (VM)

The server runs on a university VM managed via `pm2`. For all API and web tests use the live URL `https://rizzie-hellmans.theburkenator.com`.

**SSH into the VM:**
```bash
ssh -i <path_to_your_key> student@200.69.13.70 -p 2217
```

**Check if the server is already running:**
```bash
pm2 status
```

**Restart after pulling latest code:**
```bash
cd ~/Rizzie-Hellmans
git pull
cd src/server
npm install
pm2 restart rizzie-api
```

**Start from scratch (if not running):**
```bash
cd ~/Rizzie-Hellmans/src/server
pm2 start index.js --name rizzie-api
```

**View logs (useful when something isn't working):**
```bash
pm2 logs rizzie-api
```

**Confirm the server is live before testing:**
```bash
curl https://rizzie-hellmans.theburkenator.com/health
```

> **Note:** If the three blockchain env vars are absent from `.env` on the VM, messages are still stored — `txHash` will be `null` in all responses. All non-blockchain tests pass without them.

### 0.3 Building the C++ Client

```bash
cd src/cpp-client
cmake -B build
cmake --build build
# Binary: ./build/client
```

The C++ client always connects to the **live server** at `https://rizzie-hellmans.theburkenator.com` (hardcoded in `main.cpp`).

### 0.4 Test Accounts Convention

Throughout this document the following accounts are used. Register them in order at the start of testing.

| Role | Username | Password | Purpose |
|------|----------|----------|---------|
| Alice | `alice_test` | `AlicePass1` | Primary sender |
| Bob | `bob_test` | `BobPass123` | Primary recipient |
| Charlie | `charlie_test` | `CharlieP1` | Forward/share target |

> These names are just for readability. The server assigns integer user IDs (e.g., `id: 5`). Note down each user's ID after registration/login — you will need them for recipient and share tests.

### 0.5 Shell Variables (set once per session)

```bash
# Set to your server root (no trailing slash)
BASE_URL="https://rizzie-hellmans.theburkenator.com"
# Or for local:  BASE_URL="http://localhost"

# Fill in after logging in each user:
TOKEN_A=""    # Alice's JWT
TOKEN_B=""    # Bob's JWT
TOKEN_C=""    # Charlie's JWT
ID_A=""       # Alice's user ID (integer)
ID_B=""       # Bob's user ID (integer)
ID_C=""       # Charlie's user ID (integer)

# Minimal valid base64 test data (44 chars = 32 bytes encoded)
VALID_B64="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
VALID_CT="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="   # 56 chars = 40 bytes (nonce+ct minimum)
```

---

## Section 1 — Server Health & Config

### T-01: Health Check

- [ ] **Setup:** Server running.
- **Steps:**
  1. Run: `curl -s "$BASE_URL/health"`
- **Expected:**
  ```json
  {"status":"ok"}
  ```
  HTTP 200.

---

### T-02: Config Endpoint Returns Blockchain Configuration

- [ ] **Setup:** Server running with `SEPOLIA_RPC_URL` and `CONTRACT_ADDRESS` set in `.env`.
- **Steps:**
  1. Run: `curl -s "$BASE_URL/api/config"`
- **Expected:**
  ```json
  {
    "rpcUrl": "https://eth-sepolia.g.alchemy.com/v2/...",
    "contractAddress": "0xA1bdB7222B244417CCaB6EAeD2cd3d27dADee65A"
  }
  ```
  HTTP 200. No authentication required.

---

### T-03: Config Endpoint Returns Empty Strings Without Blockchain Env Vars

- [ ] **Setup:** Server running WITHOUT the three blockchain env vars set.
- **Steps:**
  1. Run: `curl -s "$BASE_URL/api/config"`
- **Expected:**
  ```json
  {"rpcUrl":"","contractAddress":""}
  ```
  HTTP 200.

---

## Section 2 — User Registration

### T-04: Successful Registration (No Public Key)

- [ ] **Setup:** Fresh server.
- **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/register" \
       -H "Content-Type: application/json" \
       -d '{"username":"alice_test","password":"AlicePass1"}'
     ```
- **Expected:**
  ```json
  {"message":"User registered successfully"}
  ```
  HTTP 201.

---

### T-05: Successful Registration With Public Key

- [ ] **Setup:** None.
- **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/register" \
       -H "Content-Type: application/json" \
       -d '{"username":"bob_test","password":"BobPass123","publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'
     ```
- **Expected:**
  ```json
  {"message":"User registered successfully"}
  ```
  HTTP 201.

---

### T-06: Duplicate Username Returns 409

- [ ] **Setup:** `alice_test` is already registered (T-04).
- **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/register" \
       -H "Content-Type: application/json" \
       -d '{"username":"alice_test","password":"DifferentPass1"}'
     ```
- **Expected:**
  ```json
  {"error":"Username already taken"}
  ```
  HTTP 409.

---

### T-07: Username Too Short

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/register" \
       -H "Content-Type: application/json" \
       -d '{"username":"ab","password":"Password1"}'
     ```
- **Expected:**
  ```json
  {"error":"username must be between 3 and 30 characters"}
  ```
  HTTP 400.

---

### T-08: Username Too Long

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/register" \
       -H "Content-Type: application/json" \
       -d '{"username":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","password":"Password1"}'
     ```
  (33 characters — exceeds 30 limit)
- **Expected:**
  ```json
  {"error":"username must be between 3 and 30 characters"}
  ```
  HTTP 400.

---

### T-09: Username With Special Characters

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/register" \
       -H "Content-Type: application/json" \
       -d '{"username":"alice!@#","password":"Password1"}'
     ```
- **Expected:**
  ```json
  {"error":"username must contain only letters, numbers, and underscores"}
  ```
  HTTP 400.

---

### T-10: Username Containing SQL Keyword

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/register" \
       -H "Content-Type: application/json" \
       -d '{"username":"SELECT","password":"Password1"}'
     ```
- **Expected:**
  ```json
  {"error":"username contains a reserved word"}
  ```
  HTTP 400.

---

### T-11: Password Too Short

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/register" \
       -H "Content-Type: application/json" \
       -d '{"username":"validuser","password":"short"}'
     ```
- **Expected:**
  ```json
  {"error":"password must be at least 8 characters"}
  ```
  HTTP 400.

---

### T-12: Missing Username Field

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/register" \
       -H "Content-Type: application/json" \
       -d '{"password":"Password1"}'
     ```
- **Expected:**
  ```json
  {"error":"username is required"}
  ```
  HTTP 400.

---

### T-13: Missing Password Field

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/register" \
       -H "Content-Type: application/json" \
       -d '{"username":"validuser"}'
     ```
- **Expected:**
  ```json
  {"error":"password is required"}
  ```
  HTTP 400.

---

### T-14: Registration With Invalid publicKey (Bad Base64)

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/register" \
       -H "Content-Type: application/json" \
       -d '{"username":"newuser9","password":"Password1","publicKey":"not-valid-base64!!!"}'
     ```
- **Expected:**
  ```json
  {"error":"publicKey must be a valid base64 string"}
  ```
  HTTP 400.

---

## Section 3 — Login

### T-15: Successful Login Returns JWT Token

- [ ] **Setup:** `alice_test` registered (T-04).
- **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/login" \
       -H "Content-Type: application/json" \
       -d '{"username":"alice_test","password":"AlicePass1"}'
     ```
  2. Save the returned `token` value as `$TOKEN_A`.
- **Expected:**
  ```json
  {"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."}
  ```
  HTTP 200. Token is a JWT (three dot-separated Base64URL parts).

---

### T-16: Login Returns User ID Encoded in JWT

- [ ] **Setup:** `$TOKEN_A` obtained (T-15).
- **Steps:**
  1. Decode the JWT payload (the middle section between the dots) using base64url decoding.
     ```bash
     echo $TOKEN_A | cut -d. -f2 | base64 -d 2>/dev/null
     ```
  2. Note the `id` and `username` fields. Save `id` as `$ID_A`.
- **Expected:** JSON with `id` (integer), `username` (`alice_test`), `tokenVersion` (0 initially).

---

### T-17: Wrong Password Returns 401

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/login" \
       -H "Content-Type: application/json" \
       -d '{"username":"alice_test","password":"WrongPassword"}'
     ```
- **Expected:**
  ```json
  {"error":"Invalid credentials"}
  ```
  HTTP 401.

---

### T-18: Non-Existent Username Returns 401

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/login" \
       -H "Content-Type: application/json" \
       -d '{"username":"nobody_xyz","password":"Password1"}'
     ```
- **Expected:**
  ```json
  {"error":"Invalid credentials"}
  ```
  HTTP 401. (Same error as wrong password — no username enumeration.)

---

### T-19: Login With Missing Username

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/login" \
       -H "Content-Type: application/json" \
       -d '{"password":"Password1"}'
     ```
- **Expected:**
  ```json
  {"error":"username is required"}
  ```
  HTTP 400.

---

## Section 4 — Public Key Management

> **Register charlie_test now** if you have not already, and log in all three users to obtain `$TOKEN_A`, `$TOKEN_B`, `$TOKEN_C`, `$ID_A`, `$ID_B`, `$ID_C`.

### T-20: Publish Public Key (PUT /users/pubkey)

- [ ] **Setup:** `$TOKEN_A` valid.
- **Steps:**
  1. ```bash
     curl -s -X PUT "$BASE_URL/users/pubkey" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_A" \
       -d '{"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'
     ```
- **Expected:**
  ```json
  {"message":"Public key updated"}
  ```
  HTTP 200.

---

### T-21: Update Public Key (Overwrite Existing)

- [ ] **Setup:** Alice already has a public key (T-20).
- **Steps:**
  1. ```bash
     curl -s -X PUT "$BASE_URL/users/pubkey" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_A" \
       -d '{"publicKey":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}'
     ```
- **Expected:**
  ```json
  {"message":"Public key updated"}
  ```
  HTTP 200. The new key replaces the old one.

---

### T-22: Fetch Another User's Public Key

- [ ] **Setup:** `$TOKEN_B` valid, Alice has published key (T-20 or T-21).
- **Steps:**
  1. ```bash
     curl -s -X GET "$BASE_URL/users/$ID_A/pubkey" \
       -H "Authorization: Bearer $TOKEN_B"
     ```
- **Expected:**
  ```json
  {"publicKey":"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB="}
  ```
  HTTP 200. Returns the currently-stored public key.

---

### T-23: Fetch Public Key — User Not Found

- [ ] **Steps:**
  1. ```bash
     curl -s -X GET "$BASE_URL/users/99999/pubkey" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:**
  ```json
  {"error":"User not found"}
  ```
  HTTP 404.

---

### T-24: Fetch Public Key — User Has No Key

- [ ] **Setup:** Register a fresh user `nokey_user` / `Password1` without a publicKey. Log in and get their ID as `$ID_NK`.
- **Steps:**
  1. ```bash
     curl -s -X GET "$BASE_URL/users/$ID_NK/pubkey" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:**
  ```json
  {"error":"User has not published a public key"}
  ```
  HTTP 404.

---

### T-25: PUT /users/pubkey Without Auth

- [ ] **Steps:**
  1. ```bash
     curl -s -X PUT "$BASE_URL/users/pubkey" \
       -H "Content-Type: application/json" \
       -d '{"publicKey":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}'
     ```
- **Expected:**
  ```json
  {"error":"Missing or invalid authorization header"}
  ```
  HTTP 401.

---

### T-26: PUT /users/pubkey With Invalid Base64

- [ ] **Steps:**
  1. ```bash
     curl -s -X PUT "$BASE_URL/users/pubkey" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_A" \
       -d '{"publicKey":"not!valid@base64"}'
     ```
- **Expected:**
  ```json
  {"error":"publicKey must be a valid base64 string"}
  ```
  HTTP 400.

---

## Section 5 — Send Message

> Before these tests, make sure both Alice and Bob have **published public keys** so we have valid recipients. The `enc` and `ciphertext` fields sent here are fake (all-zeros) — the server stores them as-is without any crypto validation. Real encryption is client-side.

### T-27: Send Message Successfully

- [ ] **Setup:** `$TOKEN_A` valid. Bob (`$ID_B`) exists.
- **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/messages" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_A" \
       -d "{\"to\":$ID_B,\"enc\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}"
     ```
  2. Note the returned `messageId` as `$MSG1`.
- **Expected:**
  ```json
  {"messageId":1,"txHash":"0xabc..."}
  ```
  HTTP 201. `messageId` is a positive integer. If blockchain is enabled `txHash` is a 66-char hex string; otherwise `txHash` is `null`.
  > **Note:** If blockchain env vars are set, this call waits for 1 Sepolia block confirmation before responding. This can take 10–60+ seconds. This is expected behaviour.

---

### T-28: Send Message Without Blockchain (txHash is null)

- [ ] **Setup:** Server started **without** `SEPOLIA_RPC_URL`, `SERVER_WALLET_PRIVATE_KEY`, or `CONTRACT_ADDRESS`.
- **Steps:**
  1. Send a message as in T-27.
- **Expected:**
  ```json
  {"messageId":2,"txHash":null}
  ```
  HTTP 201.

---

### T-29: Send to Non-Existent Recipient

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/messages" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_A" \
       -d '{"to":99999,"enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}'
     ```
- **Expected:**
  ```json
  {"error":"Recipient not found"}
  ```
  HTTP 404.

---

### T-30: Send Without `enc` Field

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/messages" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_A" \
       -d "{\"to\":$ID_B,\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}"
     ```
- **Expected:**
  ```json
  {"error":"enc must be a valid base64 string"}
  ```
  HTTP 400.

---

### T-31: Send With Invalid `enc` (Not Base64)

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/messages" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_A" \
       -d "{\"to\":$ID_B,\"enc\":\"not!valid\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}"
     ```
- **Expected:**
  ```json
  {"error":"enc must be a valid base64 string"}
  ```
  HTTP 400.

---

### T-32: Send With Invalid `ciphertext` (Not Base64)

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/messages" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_A" \
       -d "{\"to\":$ID_B,\"enc\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"ciphertext\":\"!!!invalid!!!\"}"
     ```
- **Expected:**
  ```json
  {"error":"ciphertext must be a valid base64 string"}
  ```
  HTTP 400.

---

### T-33: Send Without Authentication

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/messages" \
       -H "Content-Type: application/json" \
       -d "{\"to\":$ID_B,\"enc\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}"
     ```
- **Expected:**
  ```json
  {"error":"Missing or invalid authorization header"}
  ```
  HTTP 401.

---

## Section 6 — List Messages

### T-34: List Messages as Sender

- [ ] **Setup:** At least one message sent by Alice (T-27, `$MSG1`).
- **Steps:**
  1. ```bash
     curl -s -X GET "$BASE_URL/messages" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:** HTTP 200. JSON array containing at least one object for `$MSG1`.  
  Each object has: `messageId`, `from`, `to`, `enc`, `ciphertext`, `txHash`, `sentAt`.  
  For the sent message: `from` equals `$ID_A`, `to` equals `$ID_B`.

---

### T-35: List Messages as Recipient

- [ ] **Setup:** Same message `$MSG1`.
- **Steps:**
  1. ```bash
     curl -s -X GET "$BASE_URL/messages" \
       -H "Authorization: Bearer $TOKEN_B"
     ```
- **Expected:** HTTP 200. Array contains `$MSG1` with `from` = `$ID_A`, `to` = `$ID_B`.

---

### T-36: List Messages Returns Both Sent AND Received

- [ ] **Setup:** Bob sends a reply message to Alice. (`$TOKEN_B` needed, `$ID_A` as recipient.)
  1. ```bash
     curl -s -X POST "$BASE_URL/messages" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_B" \
       -d "{\"to\":$ID_A,\"enc\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}"
     ```
  2. Note the new message ID as `$MSG2`.
- **Steps:**
  1. ```bash
     curl -s -X GET "$BASE_URL/messages" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:** Array contains BOTH `$MSG1` (Alice sent) AND `$MSG2` (Alice received). Messages where `from=$ID_A` and messages where `to=$ID_A` are both included.

---

### T-37: List Messages Without Auth

- [ ] **Steps:**
  1. ```bash
     curl -s "$BASE_URL/messages"
     ```
- **Expected:**
  ```json
  {"error":"Missing or invalid authorization header"}
  ```
  HTTP 401.

---

## Section 7 — Download Message

### T-38: Download Message as Sender

- [ ] **Setup:** `$MSG1` exists, `$TOKEN_A` valid.
- **Steps:**
  1. ```bash
     curl -s "$BASE_URL/messages/$MSG1/download" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:** HTTP 200.
  ```json
  {
    "messageId": 1,
    "from": <ID_A>,
    "enc": "AAAA...=",
    "ciphertext": "AAAA...==",
    "txHash": "0x..." or null,
    "sentAt": "2026-06-03T..."
  }
  ```
  > Note: `to` is NOT included in the download response (only in the list response).

---

### T-39: Download Message as Recipient

- [ ] **Setup:** `$MSG1` exists, `$TOKEN_B` valid.
- **Steps:**
  1. ```bash
     curl -s "$BASE_URL/messages/$MSG1/download" \
       -H "Authorization: Bearer $TOKEN_B"
     ```
- **Expected:** HTTP 200. Same structure as T-38.

---

### T-40: Download Message as Third Party (Access Denied)

- [ ] **Setup:** `$TOKEN_C` valid. Charlie has no relation to `$MSG1`.
- **Steps:**
  1. ```bash
     curl -s "$BASE_URL/messages/$MSG1/download" \
       -H "Authorization: Bearer $TOKEN_C"
     ```
- **Expected:**
  ```json
  {"error":"Access denied"}
  ```
  HTTP 403.

---

### T-41: Download Non-Existent Message

- [ ] **Steps:**
  1. ```bash
     curl -s "$BASE_URL/messages/99999/download" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:**
  ```json
  {"error":"Message not found"}
  ```
  HTTP 404.

---

### T-42: Download With Invalid Message ID

- [ ] **Steps:**
  1. ```bash
     curl -s "$BASE_URL/messages/abc/download" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:**
  ```json
  {"error":"Invalid message ID"}
  ```
  HTTP 400.

---

### T-43: Download Without Auth

- [ ] **Steps:**
  1. ```bash
     curl -s "$BASE_URL/messages/$MSG1/download"
     ```
- **Expected:**
  ```json
  {"error":"Missing or invalid authorization header"}
  ```
  HTTP 401.

---

## Section 8 — Forward Message

### T-44: Forward a Message Successfully

- [ ] **Setup:** Bob has received `$MSG1`. Charlie (`$ID_C`) exists.
- **Steps:**
  1. Bob forwards `$MSG1` to Charlie (re-encrypted — use any valid base64 values for the new enc/ciphertext):
     ```bash
     curl -s -X POST "$BASE_URL/messages/$MSG1/forward" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_B" \
       -d "{\"to\":$ID_C,\"enc\":\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=\",\"ciphertext\":\"CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC==\"}"
     ```
  2. Note the returned `messageId` as `$MSG3`.
- **Expected:**
  ```json
  {"messageId": 3, "txHash": "0x..." or null}
  ```
  HTTP 201. A new message is created (`$MSG3`) with sender=Bob, recipient=Charlie.

---

### T-45: Charlie Can Download the Forwarded Message

- [ ] **Setup:** `$MSG3` created (T-44), `$TOKEN_C` valid.
- **Steps:**
  1. ```bash
     curl -s "$BASE_URL/messages/$MSG3/download" \
       -H "Authorization: Bearer $TOKEN_C"
     ```
- **Expected:** HTTP 200. Returns `$MSG3` details with Charlie's `enc`/`ciphertext`.

---

### T-46: Forward by Non-Owner (Access Denied)

- [ ] **Setup:** `$MSG1` was sent by Alice to Bob. Charlie (`$TOKEN_C`) has no access to it.
- **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/messages/$MSG1/forward" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_C" \
       -d "{\"to\":$ID_B,\"enc\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}"
     ```
- **Expected:**
  ```json
  {"error":"Access denied"}
  ```
  HTTP 403.

---

### T-47: Forward to Non-Existent Recipient

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/messages/$MSG1/forward" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_B" \
       -d '{"to":99999,"enc":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","ciphertext":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}'
     ```
- **Expected:**
  ```json
  {"error":"Recipient not found"}
  ```
  HTTP 404.

---

### T-48: Forward Non-Existent Message

- [ ] **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/messages/99999/forward" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_B" \
       -d "{\"to\":$ID_C,\"enc\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}"
     ```
- **Expected:**
  ```json
  {"error":"Message not found"}
  ```
  HTTP 404.

---

## Section 9 — Delete Message

### T-49: Delete Message as Sender

- [ ] **Setup:** Send a new message from Alice to Bob. Note the ID as `$MSG_DEL`.
  ```bash
  curl -s -X POST "$BASE_URL/messages" \
    -H "Content-Type: application/json" \
    -H "Authorization: Bearer $TOKEN_A" \
    -d "{\"to\":$ID_B,\"enc\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\",\"ciphertext\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==\"}"
  ```
- **Steps:**
  1. ```bash
     curl -s -X DELETE "$BASE_URL/messages/$MSG_DEL" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:**
  ```json
  {"message":"Message deleted"}
  ```
  HTTP 200.

---

### T-50: Verify Deleted Message Is Gone

- [ ] **Setup:** `$MSG_DEL` was deleted (T-49).
- **Steps:**
  1. ```bash
     curl -s "$BASE_URL/messages/$MSG_DEL/download" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:**
  ```json
  {"error":"Message not found"}
  ```
  HTTP 404.

---

### T-51: Delete Message as Recipient (Denied — Only Sender Can Delete)

- [ ] **Setup:** `$MSG1` was sent by Alice to Bob. Bob is the recipient.
- **Steps:**
  1. ```bash
     curl -s -X DELETE "$BASE_URL/messages/$MSG1" \
       -H "Authorization: Bearer $TOKEN_B"
     ```
- **Expected:**
  ```json
  {"error":"Access denied"}
  ```
  HTTP 403. Only the original sender can delete.

---

### T-52: Delete Cascades Through message_shares

- [ ] **Setup:** Forward `$MSG1` to Charlie (creates `$MSG3` as in T-44). Then delete `$MSG3`.
- **Steps:**
  1. Delete the forwarded message as Bob (sender of `$MSG3`):
     ```bash
     curl -s -X DELETE "$BASE_URL/messages/$MSG3" \
       -H "Authorization: Bearer $TOKEN_B"
     ```
  2. Try to download `$MSG3` as Charlie:
     ```bash
     curl -s "$BASE_URL/messages/$MSG3/download" \
       -H "Authorization: Bearer $TOKEN_C"
     ```
- **Expected:**
  - Step 1: `{"message":"Message deleted"}` HTTP 200.
  - Step 2: `{"error":"Message not found"}` HTTP 404.
  - The message_shares row for (MSG3, Charlie) is also deleted (cascade handled in server code).

---

### T-53: Delete Non-Existent Message

- [ ] **Steps:**
  1. ```bash
     curl -s -X DELETE "$BASE_URL/messages/99999" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:**
  ```json
  {"error":"Message not found"}
  ```
  HTTP 404.

---

### T-54: Delete Without Auth

- [ ] **Steps:**
  1. ```bash
     curl -s -X DELETE "$BASE_URL/messages/$MSG1"
     ```
- **Expected:**
  ```json
  {"error":"Missing or invalid authorization header"}
  ```
  HTTP 401.

---

## Section 10 — Revoke Share

> For these tests, first create a fresh forwarded message from Bob to Charlie. Note its ID as `$MSG_FWD`.

```bash
curl -s -X POST "$BASE_URL/messages/$MSG1/forward" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN_B" \
  -d "{\"to\":$ID_C,\"enc\":\"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD=\",\"ciphertext\":\"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\"}"
```

### T-55: Revoke Share as Sender (Happy Path)

- [ ] **Setup:** `$MSG_FWD` created above. Bob (`$TOKEN_B`) is the sender. Charlie (`$ID_C`) has access via message_shares.
- **Steps:**
  1. ```bash
     curl -s -X DELETE "$BASE_URL/messages/$MSG_FWD/share/$ID_C" \
       -H "Authorization: Bearer $TOKEN_B"
     ```
- **Expected:**
  ```json
  {"message":"Access revoked"}
  ```
  HTTP 200. The message_shares row `(MSG_FWD, ID_C)` is deleted.

---

### T-56: Revoke Share as Non-Sender (Access Denied)

- [ ] **Setup:** `$MSG_FWD` was sent by Bob. Alice is not the sender.
- **Steps:**
  1. ```bash
     curl -s -X DELETE "$BASE_URL/messages/$MSG_FWD/share/$ID_C" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:**
  ```json
  {"error":"Access denied"}
  ```
  HTTP 403.

---

### T-57: Revoke Share — Non-Existent Message

- [ ] **Steps:**
  1. ```bash
     curl -s -X DELETE "$BASE_URL/messages/99999/share/$ID_C" \
       -H "Authorization: Bearer $TOKEN_B"
     ```
- **Expected:**
  ```json
  {"error":"Message not found"}
  ```
  HTTP 404.

---

### T-58: Revoke Share — Non-Existent User

- [ ] **Steps:**
  1. ```bash
     curl -s -X DELETE "$BASE_URL/messages/$MSG1/share/99999" \
       -H "Authorization: Bearer $TOKEN_A"
     ```
- **Expected:**
  ```json
  {"error":"User not found"}
  ```
  HTTP 404.

---

### T-59: Revoke Share — Invalid Message ID

- [ ] **Steps:**
  1. ```bash
     curl -s -X DELETE "$BASE_URL/messages/abc/share/$ID_C" \
       -H "Authorization: Bearer $TOKEN_B"
     ```
- **Expected:**
  ```json
  {"error":"Invalid message ID"}
  ```
  HTTP 400.

---

## Section 11 — Change Password

### T-60: Change Password Successfully

- [ ] **Setup:** `$TOKEN_A` valid. Register a temporary user for this test: `tempuser` / `TempPass1`.
  ```bash
  curl -s -X POST "$BASE_URL/auth/register" \
    -H "Content-Type: application/json" \
    -d '{"username":"tempuser","password":"TempPass1"}'
  ```
  Log in and get `$TOKEN_TEMP`:
  ```bash
  TOKEN_TEMP=$(curl -s -X POST "$BASE_URL/auth/login" \
    -H "Content-Type: application/json" \
    -d '{"username":"tempuser","password":"TempPass1"}' | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")
  ```
- **Steps:**
  1. ```bash
     curl -s -X PUT "$BASE_URL/auth/password" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_TEMP" \
       -d '{"currentPassword":"TempPass1","newPassword":"NewTempPass9"}'
     ```
- **Expected:**
  ```json
  {"message":"Password updated successfully"}
  ```
  HTTP 200.

---

### T-61: Old Token Is Invalidated After Password Change

- [ ] **Setup:** Password changed in T-60. `$TOKEN_TEMP` is the old token.
- **Steps:**
  1. Attempt to use the old token:
     ```bash
     curl -s "$BASE_URL/messages" \
       -H "Authorization: Bearer $TOKEN_TEMP"
     ```
- **Expected:**
  ```json
  {"error":"Session expired, please log in again"}
  ```
  HTTP 401. The server increments `token_version` on password change, invalidating all previously issued tokens.

---

### T-62: Can Log In With New Password After Change

- [ ] **Setup:** T-60 completed (password changed to `NewTempPass9`).
- **Steps:**
  1. ```bash
     curl -s -X POST "$BASE_URL/auth/login" \
       -H "Content-Type: application/json" \
       -d '{"username":"tempuser","password":"NewTempPass9"}'
     ```
- **Expected:** HTTP 200. New JWT token returned.

---

### T-63: Change Password — Wrong Current Password

- [ ] **Steps:**
  1. ```bash
     curl -s -X PUT "$BASE_URL/auth/password" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_A" \
       -d '{"currentPassword":"WrongOldPass","newPassword":"NewPassword1"}'
     ```
- **Expected:**
  ```json
  {"error":"Current password is incorrect"}
  ```
  HTTP 401.

---

### T-64: Change Password — New Password Too Short

- [ ] **Steps:**
  1. ```bash
     curl -s -X PUT "$BASE_URL/auth/password" \
       -H "Content-Type: application/json" \
       -H "Authorization: Bearer $TOKEN_A" \
       -d '{"currentPassword":"AlicePass1","newPassword":"short"}'
     ```
- **Expected:**
  ```json
  {"error":"newPassword must be at least 8 characters"}
  ```
  HTTP 400.

---

### T-65: Change Password Without Auth

- [ ] **Steps:**
  1. ```bash
     curl -s -X PUT "$BASE_URL/auth/password" \
       -H "Content-Type: application/json" \
       -d '{"currentPassword":"AlicePass1","newPassword":"NewPassword1"}'
     ```
- **Expected:**
  ```json
  {"error":"Missing or invalid authorization header"}
  ```
  HTTP 401.

---

## Section 12 — Security Headers

### T-66: Security Headers Present on All Responses

- [ ] **Steps:**
  1. ```bash
     curl -s -I "$BASE_URL/health"
     ```
- **Expected:** Response headers include ALL of the following:
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY`
  - `X-XSS-Protection: 1; mode=block`
  - Does NOT include `X-Powered-By` (suppressed).

---

### T-67: JWT Token With Tampered Signature Is Rejected

- [ ] **Steps:**
  1. Take `$TOKEN_A`, append an extra character to corrupt the signature (last segment after the second dot).
  2. ```bash
     FAKE_TOKEN="${TOKEN_A}X"
     curl -s "$BASE_URL/messages" \
       -H "Authorization: Bearer $FAKE_TOKEN"
     ```
- **Expected:**
  ```json
  {"error":"Invalid or expired token"}
  ```
  HTTP 401.

---

### T-68: Authorization Header Without "Bearer" Prefix Is Rejected

- [ ] **Steps:**
  1. ```bash
     curl -s "$BASE_URL/messages" \
       -H "Authorization: $TOKEN_A"
     ```
- **Expected:**
  ```json
  {"error":"Missing or invalid authorization header"}
  ```
  HTTP 401. The header must start with `Bearer `.

---

---

## Section 13 — Web Frontend: Authentication

> Open the web app at `https://rizzie-hellmans.theburkenator.com` (or `http://localhost` for local).  
> These tests are performed in the browser. Open DevTools (F12) → Console to observe errors.

### T-69: Sign Up Creates Account and Logs In Automatically

- [ ] **Steps:**
  1. Navigate to the homepage.
  2. Click the **Sign up** tab.
  3. Enter username `webtest_alice`, password `WebAlice1`, confirm `WebAlice1`.
  4. Click **Sign up**.
- **Expected:**
  - A brief "Generating your secret rizz keys…" message appears.
  - The auth screen disappears and the main chat screen appears.
  - The top bar shows the username and a user ID.
  - No errors in the browser console.
  - A keypair was generated and stored in `localStorage` (key: `rizz_key_webtest_alice`).
  - The public key was automatically published to the server (can verify with T-22 style curl).

---

### T-70: Sign Up Validation — Username Too Short

- [ ] **Steps:**
  1. In the Sign up tab, enter username `ab`, password `Password1`, confirm `Password1`.
  2. Click **Sign up**.
- **Expected:** Error message appears: `"Username must be 3+ characters (letters, numbers, _)."` No API call is made.

---

### T-71: Sign Up Validation — Passwords Don't Match

- [ ] **Steps:**
  1. Enter any valid username, password `Password1`, confirm `Password2`.
  2. Click **Sign up**.
- **Expected:** Error: `"Passwords don't match 💔"`. No API call is made.

---

### T-72: Sign Up — Duplicate Username

- [ ] **Setup:** `webtest_alice` already registered (T-69).
- **Steps:**
  1. Attempt to sign up again with username `webtest_alice`.
- **Expected:** Error: `"💔 That username is already taken."`.

---

### T-73: Login With Valid Credentials

- [ ] **Steps:**
  1. Click the **Login** tab.
  2. Enter username `webtest_alice`, password `WebAlice1`.
  3. Click **Log in / Rizz in**.
- **Expected:** Chat screen appears. Top bar shows `webtest_alice` and the user ID.

---

### T-74: Login With Wrong Password Shows Error

- [ ] **Steps:**
  1. Enter username `webtest_alice`, password `WrongPassword`.
  2. Click **Log in**.
- **Expected:** Error: `"💔 Wrong username or password."`.

---

### T-75: Session Persists After Page Reload

- [ ] **Setup:** Logged in as `webtest_alice` (T-73).
- **Steps:**
  1. Reload the page (F5 or Ctrl+R).
- **Expected:** The chat screen is immediately shown — no login prompt. The session was restored from `localStorage`.

---

### T-76: Logout Clears Session

- [ ] **Setup:** Logged in.
- **Steps:**
  1. Click the **⚙️** settings button (top-right).
  2. Click **Log out**.
- **Expected:**
  - Redirected to the auth (login) screen.
  - `localStorage` no longer contains `rizz_token` or `rizz_username` for this user.
  - Reloading the page stays on the login screen.

---

## Section 14 — Web Frontend: Messaging

> Log in as two different users in two different browsers (or one normal + one incognito window). For clarity: **Browser A** = `webtest_alice`, **Browser B** = `webtest_bob`.

### T-77: Add a Contact via "New Rizz"

- [ ] **Setup:** `webtest_bob` is registered and has a public key.
- **Steps (in Browser A):**
  1. Click **＋ New Rizz** button.
  2. Enter Bob's user ID in the **Rizzipient User ID** field.
  3. Optionally enter a nickname (e.g., "Cute Bob").
  4. Click **Find & Rizz 💘**.
- **Expected:**
  - Modal closes.
  - Bob appears in the contacts sidebar with the given nickname (or default `Rizzipient #<id>`).

---

### T-78: Add Contact With Invalid User ID

- [ ] **Steps:**
  1. Open New Rizz modal.
  2. Enter `0` or a negative number as the user ID.
  3. Click Find & Rizz.
- **Expected:** Error: `"Enter a valid user ID."`. No API call.

---

### T-79: Add Contact — User Has No Public Key

- [ ] **Setup:** A user exists with no public key (T-24's `nokey_user`). Note their ID as `$ID_NK`.
- **Steps:**
  1. Open New Rizz modal.
  2. Enter `$ID_NK`.
  3. Click Find & Rizz.
- **Expected:** Error: `"No rizzipient with that ID has published a key 💔"`.

---

### T-80: Send a Message

- [ ] **Setup:** Bob is in Alice's contact list (T-77). Bob has a valid public key.
- **Steps (in Browser A):**
  1. Click Bob's name in the sidebar.
  2. Type a message, e.g. `Hello Bob! Testing E2E encryption.`
  3. Press **Enter** or click **➤**.
- **Expected:**
  - Message bubble appears on the right (sent side) immediately.
  - If blockchain enabled: a `✓✓ Delivered Rizz` receipt badge appears under the bubble.
  - If no blockchain: a single `✓ Sent` receipt appears.
  - A toast notification: `"Rizz delivered 💘 Certified on-chain 🔗"` (or without the chain part if no blockchain).

---

### T-81: Recipient Receives and Decrypts Message Automatically

- [ ] **Setup:** Alice sent a message (T-80). Browser B is logged in as `webtest_bob`.
- **Steps (in Browser B):**
  1. Wait up to 4 seconds for the auto-poll (or refresh messages manually).
  2. Click Alice's contact in Bob's sidebar.
- **Expected:**
  - The message from Alice appears decrypted in plain text on the left (received side).
  - Bob can read: `"Hello Bob! Testing E2E encryption."`
  - The server only stores ciphertext — Bob's browser decrypted it locally using his private key.

---

### T-82: Message Sent to User Without a Key Shows an Error Toast

- [ ] **Setup:** Add a contact with no public key using their raw user ID (bypass the check by entering the ID in the New Rizz dialog if they exist with no key). Select their thread. Type a message.
- **Steps:**
  1. Select a contact who has no published public key.
  2. Type a message and send.
- **Expected:** Toast error: `"That rizzipient hasn't published a key 💔"`. No message sent.

---

### T-83: Quick Emoji Buttons Insert Into Composer

- [ ] **Steps:**
  1. With a chat open, click one of the emoji buttons (💘, 🔥, etc.) above the message input.
- **Expected:** The emoji is appended to the message textarea. Does not send the message on its own.

---

### T-84: Rename a Contact (Local Nickname Only)

- [ ] **Steps:**
  1. Open a chat with Bob.
  2. Click the **✏️ rename** button in the chat header.
  3. Change the name to "Bobby".
  4. Click **Save**.
- **Expected:**
  - The chat header now shows "Bobby".
  - The contacts sidebar shows "Bobby".
  - This nickname is stored only in `localStorage` — it is private to this device/browser.
  - Bob's server username is unchanged.

---

### T-85: Auto-Polling (New Messages Appear Without Manual Refresh)

- [ ] **Setup:** Both browsers open and logged in.
- **Steps:**
  1. In Browser B (Bob), send a message to Alice.
  2. Watch Browser A (Alice) — do NOT manually refresh.
- **Expected:** Within ~4 seconds Alice's browser updates and the new message appears. The app polls every 4 seconds via `setInterval`.

---

## Section 15 — Web Frontend: Message Actions

### T-86: Download a Received Message as .txt File

- [ ] **Setup:** Bob received a message from Alice (T-81).
- **Steps (in Browser B):**
  1. Hover over Alice's message bubble. Click **⬇ Download**.
- **Expected:**
  - Browser downloads a file named `rizz-message-<id>.txt`.
  - Open the file. It must contain all of the following lines:
    ```
    💘 Rizz Me Through The Phone — message export
    ──────────────────────────────────────────
    Message ID : <integer>
    From ID    : <Alice's ID>
    Sent At    : <ISO-8601 timestamp>
    Tx Hash    : <0x... or (none)>
    
    Decrypted rizz:
    Hello Bob! Testing E2E encryption.
    
    ── encrypted blobs ──
    enc        : <base64>
    ciphertext : <base64>
    ```
  - The `Tx Hash`, `enc`, and `ciphertext` lines are the three values used in the Verify page.

---

### T-87: Download a Sent Message Shows Plaintext From Cache

- [ ] **Setup:** Alice sent a message (T-80) and is still logged in (plaintext cached in `localStorage`).
- **Steps (in Browser A):**
  1. Click **⬇ Download** on Alice's own sent message.
- **Expected:** Downloaded file contains the original plaintext under "Decrypted rizz:". Alice's browser cannot decrypt its own messages (ephemeral keys discarded) — it reads the cached plaintext from `localStorage` instead.

---

### T-88: Download on New Device Shows "Encrypted" Placeholder

- [ ] **Setup:** Alice's `localStorage` is cleared (or use a fresh browser profile).
- **Steps:**
  1. Log in as Alice on the new device. Open the sent message thread.
  2. Click **⬇ Download** on a sent message where no localStorage cache exists.
- **Expected:** Downloaded file shows:  
  `🔒 (encrypted — not decryptable on this device)` under "Decrypted rizz:".

---

### T-89: Forward a Message via UI

- [ ] **Setup:** Bob has received a message from Alice. Charlie (`webtest_charlie`) is registered with a public key.
- **Steps (in Browser B — Bob):**
  1. On Alice's message, click **↪ Forward**.
  2. Enter Charlie's user ID.
  3. Click **Forward 💌**.
- **Expected:**
  - Modal closes.
  - Toast: `"Rizz forwarded 💌 Certified on-chain 🔗"`.
  - A new forwarded message appears in Bob's chat list (Bob is now in a conversation with Charlie).
  - The forwarded message is re-encrypted for Charlie's public key (not a copy of the original ciphertext).

---

### T-90: Cannot Forward a Locked Message

- [ ] **Setup:** Alice is viewing a thread where she received a message but her private key was replaced (the message is locked).
- **Steps:**
  1. On a locked bubble (shows `"🔒 Couldn't decrypt…"`), check if the **↪ Forward** button is visible.
- **Expected:** The Forward button is **not rendered** for locked messages. Only unlocked (decryptable) messages show the Forward option.

---

### T-91: Delete a Message via UI

- [ ] **Setup:** Alice has sent message(s) to Bob.
- **Steps (in Browser A):**
  1. Hover over one of Alice's sent messages. Click **🗑 Delete**.
  2. Confirm the browser `confirm()` dialog.
- **Expected:**
  - Message bubble disappears from Alice's view immediately.
  - Toast: `"Message deleted 🗑"`.
  - Refresh Bob's browser — the message is also gone from Bob's view.

---

### T-92: Manage Access (Revoke Forward Share) via UI

- [ ] **Setup:** Bob forwarded a message to Charlie (T-89). The forwarded message in Bob's view has a **🔗 Access** button.
- **Steps (in Browser B — Bob):**
  1. Click **🔗 Access** on the forwarded message.
  2. The manage-access modal shows Charlie's entry with a **Revoke** button.
  3. Click **Revoke**.
- **Expected:**
  - Toast: `"Access revoked 🔒"`.
  - Charlie's entry disappears from the access modal.
  - The `message_shares` row is deleted server-side.
  > **Note:** This revokes UI-level access tracking only. The forwardee is also stored as `recipient_id` on the message row, so they can still retrieve the ciphertext via the download and list endpoints after revocation. Fix: grant forwarded access exclusively through `message_shares` (omit the forwardee from `recipient_id`), so a share deletion is the sole access gate.

---

## Section 16 — Web Frontend: Settings

### T-93: Settings Modal Shows User ID and Public Key

- [ ] **Steps:**
  1. Click **⚙️** in the top-right.
- **Expected:** Modal shows:
  - "User ID: `<integer>`" — the value to share with contacts.
  - The user's X25519 public key (44-char base64 string).
  - **📋 Copy public key** button.
  - Change password fields.
  - Export / Import key buttons.
  - Logout button.

---

### T-94: Change Password via Settings

- [ ] **Steps (in Browser A):**
  1. Open settings modal.
  2. Enter current password in "Current password" field.
  3. Enter a new password (8+ chars) in "New password" field.
  4. Click **Update password**.
- **Expected:**
  - Message: `"Password updated! Logging you back in…"`.
  - ~700ms later: toast `"Password changed 🔐"`. Modal closes. User remains logged in with a fresh token.
  - Old token is invalidated — any other open tabs will get a 401 next time they poll.

---

### T-95: Export Key Produces JSON File

- [ ] **Steps:**
  1. Open settings modal.
  2. Click **⬇ Export key**.
- **Expected:**
  - File `rizz-key-<username>.json` is downloaded.
  - Contents are JSON with keys: `username`, `publicKey` (base64), `secretKey` (base64).
  - **Keep this file private** — it contains the private decryption key.

---

### T-96: Import Key From JSON File

- [ ] **Setup:** You have a previously exported `rizz-key-<username>.json` file.
- **Steps:**
  1. Open settings modal.
  2. Click **⬆ Import key**.
  3. Select the JSON file.
- **Expected:**
  - Toast: `"Key imported 🔑 reloading rizz…"`.
  - Messages reload. Previously locked messages (encrypted for this key) now decrypt successfully.

---

### T-97: Import Invalid Key File Shows Error

- [ ] **Steps:**
  1. Open settings modal → Import key.
  2. Select any non-JSON file or a JSON file without `publicKey`/`secretKey` fields.
- **Expected:** Toast: `"That doesn't look like a rizz key 💔"`. No change to the current key.

---

### T-98: Certify Rizz Opens Verify Page

- [ ] **Setup:** A message exists with a `txHash`.
- **Steps:**
  1. Click the **🔥 Certify Rizz** button on a message bubble (or click the `✓✓ Delivered Rizz` receipt).
- **Expected:** A new browser tab opens at `/verify.html?tx=0x...` (the verify page, pre-populated with the transaction hash).

---

---

## Section 17 — Blockchain Verification Page (`/verify`)

> Navigate to `https://rizzie-hellmans.theburkenator.com/verify` directly, or reach it via the **🔥 Certify Rizz** button.

### T-99: Verify Page Loads

- [ ] **Steps:**
  1. Navigate to `/verify`.
- **Expected:** Page titled "Certify Your Rizz 💘🔥" loads. Shows two options (A: file upload, B: manual input). The **🔍 Check The Rizz** button is present.

---

### T-100: Successful Verification — Manual Input

- [ ] **Setup:** You have a downloaded message `.txt` file from T-86. Extract the `Tx Hash`, `enc`, and `ciphertext` values.
- **Steps:**
  1. Paste the `Tx Hash` value (starts with `0x...`) into the **Transaction Hash** field.
  2. Paste the `enc` value into the **enc (base64)** field.
  3. Paste the `ciphertext` value into the **ciphertext (base64)** field.
  4. Click **🔍 Check The Rizz**.
- **Expected:**
  - Loading spinner appears with messages: "Loading configuration…" → "Computing hash…" → "Sliding into Sepolia…"
  - Result: **"Certified Rizz ✓"** badge (pink/purple).
  - Shows: "⏱️ Sealed: `<UTC date/time>`"
  - Shows both computed hash and on-chain hash — they **match**.
  > This test requires active Sepolia connectivity and a valid blockchain transaction. Allow 5–15 seconds.

---

### T-101: Tampered Data Produces Hash Mismatch

- [ ] **Setup:** You have a valid `Tx Hash` from a real message.
- **Steps:**
  1. Paste the valid `Tx Hash`.
  2. Paste any valid-format base64 string in `enc` that is NOT the one from that transaction.
  3. Paste any valid ciphertext base64 string.
  4. Click **🔍 Check The Rizz**.
- **Expected:**
  - Result: **"Hash Mismatch ✕"** badge (red).
  - Shows both the computed hash (from your input) and the on-chain hash — they **do not match**.
  - This proves the `enc`/`ciphertext` you provided differs from what was sealed on-chain.

---

### T-102: Invalid Transaction Hash Format

- [ ] **Steps:**
  1. Enter `not-a-tx-hash` in the Transaction Hash field.
  2. Click **🔍 Check The Rizz**.
- **Expected:** Error: `"Invalid transaction hash — must be 0x followed by exactly 64 hex characters."` No Sepolia call is made.

---

### T-103: Non-Existent Transaction Hash

- [ ] **Steps:**
  1. Enter a well-formed but non-existent hash: `0x0000000000000000000000000000000000000000000000000000000000000000`.
  2. Enter valid base64 in enc and ciphertext.
  3. Click **🔍 Check The Rizz**.
- **Expected:** Result: `"Fake Rizz ✕"` — error message: `"Transaction not found on Sepolia. It may not exist yet, may still be pending, or the hash is wrong."`.

---

### T-104: Empty Fields Validation

- [ ] **Steps:**
  1. Leave all fields blank.
  2. Click **🔍 Check The Rizz**.
- **Expected:** Error: `"All three fields are required — Transaction Hash, enc, and ciphertext."`.

---

### T-105: Invalid Base64 in enc Field

- [ ] **Steps:**
  1. Enter a valid-format tx hash.
  2. Enter `not!valid!base64` in the enc field.
  3. Enter valid base64 in ciphertext.
  4. Click **🔍 Check The Rizz**.
- **Expected:** Error message mentioning enc is not valid base64. No Sepolia call.

---

### T-106: File Upload — Option A (Happy Path)

- [ ] **Setup:** You have a downloaded message `.txt` file (T-86).
- **Steps:**
  1. Navigate to `/verify`.
  2. Click or drag the `.txt` file onto the **📎 upload zone**.
- **Expected:**
  - A green "✅ File parsed — fields auto-filled below" confirmation box appears showing the extracted `Tx Hash`, `enc`, and `ciphertext`.
  - The three input fields are automatically filled in.
  - You can then click **🔍 Check The Rizz** and it proceeds as T-100.

---

### T-107: File Upload — Invalid or Missing Fields

- [ ] **Steps:**
  1. Upload a plain text file that does NOT contain `Tx Hash:`, `enc:`, and `ciphertext:` lines.
- **Expected:** Red error box: `"File is missing required fields: Tx Hash, enc, ciphertext. Make sure this is a downloaded message file."`.

---

---

## Section 18 — C++ CLI Client

> The C++ client always targets the **live server** at `https://rizzie-hellmans.theburkenator.com`.  
> All tests in this section interact with the live server.

### T-108: Build the C++ Client

- [ ] **Steps:**
  1. `cd src/cpp-client`
  2. `cmake -B build`
  3. `cmake --build build`
- **Expected:** Build completes without errors. Binary at `./build/client` is created.

---

### T-109: First Run — New Key Generation

- [ ] **Setup:** No `~/.rizzie/keys/` directory exists.
- **Steps:**
  1. Run `./build/client`.
  2. At "Enter passphrase:", type `MyPassphrase1` and press Enter.
- **Expected:**
  - "✓ Generated new key pair." message.
  - Your public key is shown (44-char base64 string).
  - A `~/.rizzie/keys/identity.key` file is created (binary, encrypted).
  - Press Enter to continue. The main menu appears.

---

### T-110: Subsequent Run — Loads Existing Key

- [ ] **Setup:** `~/.rizzie/keys/identity.key` exists from T-109.
- **Steps:**
  1. Run `./build/client`.
  2. Enter the same passphrase `MyPassphrase1`.
- **Expected:**
  - "✓ Loaded existing key pair." message.
  - The same public key as T-109 is shown.
  - Main menu appears.

---

### T-111: Wrong Passphrase on Startup Fails Gracefully

- [ ] **Setup:** `~/.rizzie/keys/identity.key` exists.
- **Steps:**
  1. Run `./build/client`.
  2. Enter the wrong passphrase.
- **Expected:**
  - Error: `"Failed to load private key: …"` (AES-GCM tag verification fails — the wrong key cannot decrypt the key file).
  - Program exits. No menu appears.

---

### T-112: Empty Passphrase Is Rejected

- [ ] **Steps:**
  1. Run `./build/client`.
  2. Press Enter immediately at the passphrase prompt (empty input).
- **Expected:** Error: `"Passphrase must not be empty"`. Program exits.

---

### T-113: Register via CLI (Option 1)

- [ ] **Setup:** Main menu visible (logged-out state).
- **Steps:**
  1. Enter `1` (Register).
  2. Username: `cpp_alice`
  3. Password: `CppAlice1`
- **Expected:** Server response shown, e.g. `User registered successfully`. Press Enter to return to menu.

---

### T-114: Register Duplicate Username via CLI

- [ ] **Setup:** `cpp_alice` already registered.
- **Steps:**
  1. Enter `1`, then `cpp_alice`, then `CppAlice1`.
- **Expected:** Server error shown: `Username already taken`. Menu unchanged. No crash.

---

### T-115: Login via CLI (Option 2)

- [ ] **Setup:** `cpp_alice` registered (T-113).
- **Steps:**
  1. Enter `2` (Login).
  2. Username: `cpp_alice`
  3. Password: `CppAlice1`
- **Expected:**
  - Login succeeds. Server returns a JWT token (stored internally by the client).
  - The menu header changes to show `● Logged in (user id: <integer>)`.
  - **Also register and log in** as `cpp_bob` in a second terminal session for the remaining tests.

---

### T-116: Login With Wrong Password via CLI

- [ ] **Steps:**
  1. Enter `2`, username `cpp_alice`, password `WrongPass`.
- **Expected:** Server error shown: `Invalid credentials`. User remains not logged in.

---

### T-117: Send Message via CLI (Option 3)

- [ ] **Setup:** Logged in as `cpp_alice`. `cpp_bob`'s user ID is known from T-115 (their "user id: X" shown after login).
- **Steps:**
  1. Enter `3` (Send message).
  2. Recipient user ID: `<cpp_bob's ID>`.
  3. Message: `Hello from C++ CLI!`
- **Expected:**
  - Encryption happens client-side using libsodium HPKE Mode_Auth scheme (`securechat-v2`).
  - Server responds with `messageId` and `txHash` (or null).
  - Press Enter to return to menu.

---

### T-118: Refresh Inbox via CLI (Option 4)

- [ ] **Setup:** `cpp_bob` has received the message from T-117.
- **Steps (in `cpp_bob`'s session):**
  1. Enter `4` (Refresh inbox).
- **Expected:**
  - The inbox panel updates with the new message row.
  - The message preview shows the decrypted plaintext: `Hello from C++ CLI!`.
  - Row shows: message ID, sender ID (you), recipient ID, truncated preview, time.

---

### T-119: Forward Message via CLI (Option 5)

- [ ] **Setup:** `cpp_bob` has received a message (T-118). A third user `cpp_charlie` is registered with a key on the server.
- **Steps (in `cpp_bob`'s session):**
  1. Enter `5` (Forward message).
  2. Message ID to forward: the ID of the message from Alice.
  3. Recipient user ID: `<cpp_charlie's ID>`.
- **Expected:**
  - The message is re-encrypted for Charlie's key.
  - Server responds with a new `messageId` for the forwarded message.
  - Press Enter to return to menu.

---

### T-120: Change Password via CLI (Option 6)

- [ ] **Setup:** Logged in.
- **Steps:**
  1. Enter `6` (Change password).
  2. Current password: `CppAlice1`
  3. New password: `CppAlice2`
- **Expected:**
  - Server responds: `Password updated successfully`.
  - The client's stored JWT token is now invalid (token_version incremented).
  - You must log in again (option 2) with the new password to continue.

---

### T-121: Download Message via CLI (Option 7)

- [ ] **Setup:** `cpp_bob` has a message in inbox.
- **Steps (in `cpp_bob`'s session):**
  1. Enter `7` (Download message).
  2. Message ID to download: select a message ID from the inbox display.
- **Expected:**
  - Message details are printed to the terminal, including `enc`, `ciphertext`, `txHash`, `sentAt`.
  - A `.txt` file is saved (in the same format as the web download).

---

### T-122: Revoke Access via CLI (Option 8)

- [ ] **Setup:** `cpp_bob` has forwarded a message to `cpp_charlie` (T-119). Note the forwarded message's ID.
- **Steps (in `cpp_bob`'s session):**
  1. Enter `8` (Revoke access).
  2. Message ID: the forwarded message ID.
  3. User ID to revoke: `<cpp_charlie's ID>`.
- **Expected:** Server responds: `Access revoked`.

---

### T-123: Delete Message via CLI (Option 9)

- [ ] **Setup:** `cpp_alice` has sent messages.
- **Steps (in `cpp_alice`'s session):**
  1. Enter `9` (Delete message).
  2. Enter the ID of one of Alice's sent messages.
- **Expected:**
  - Server responds: `Message deleted`.
  - After pressing 4 (refresh), the message no longer appears in the inbox.

---

### T-124: TOFU Key Pinning Warning on Key Change

- [ ] **Setup:** `cpp_alice` has previously received a message from a user (their key is pinned in `~/.rizzie/keys/trusted_keys.txt`). That user then registers a new account or re-generates their key (changing their published public key).
- **Steps:**
  1. Enter `4` (Refresh inbox) in `cpp_alice`'s session after the sender's public key has changed.
- **Expected:**
  - A warning is printed to the terminal indicating the pinned key for that sender has changed.
  - The message may still decrypt (if the same keypair was used to encrypt it), but the TOFU mismatch is flagged.
  - This protects against a man-in-the-middle substituting a different public key.

---

### T-125: Accessing Menu Items Before Login Shows Warning

- [ ] **Setup:** Client started, not logged in.
- **Steps:**
  1. Enter `3` (Send message) before logging in.
- **Expected:** `"Please login first."` message. Returns to menu. No crash.

---

### T-126: Invalid Menu Choice Shows Error

- [ ] **Steps:**
  1. At the main menu, enter `99`.
- **Expected:** `"Invalid choice — enter 0–9."`. Returns to menu.

---

### T-127: Quit via CLI (Option 0)

- [ ] **Steps:**
  1. Enter `0`.
- **Expected:** Screen clears, "Goodbye." printed. Program exits with code 0.

---

---

## Section 19 — Cross-Client Compatibility

> This section documents the **intentional** crypto interoperability boundary between the web and C++ clients.

### T-128: Web Client Sends to Web Client (Fully Interoperable)

- [ ] **Setup:** Both users are using the browser UI.
- **Expected:** Messages send and decrypt correctly. Both sides use the `securechat-v1` scheme (TweetNaCl X25519 + HKDF-SHA256 + AES-256-GCM).

---

### T-129: C++ Client Sends to C++ Client (Fully Interoperable)

- [ ] **Setup:** Both users are using the C++ CLI.
- **Expected:** Messages send and decrypt correctly. Both sides use the `securechat-v2` HPKE Mode_Auth scheme (libsodium X25519×2 + HKDF-SHA256 + AES-256-GCM).

---

### T-130: C++ Sends to Web — Expected Decrypt Failure

- [ ] **Setup:** `cpp_alice` (C++ client) sends a message to `webtest_bob` (browser user).
- **Steps:**
  1. `cpp_alice` sends a message to `webtest_bob`'s user ID.
  2. `webtest_bob` opens the browser and refreshes messages.
- **Expected:**
  - The message appears in Bob's browser as `"🔒 Couldn't decrypt — this rizz was sealed for another key"`.
  - **This is by design, not a bug.** The C++ client uses `securechat-v2` (two DH operations + different KDF) while the browser uses `securechat-v1` (single DH + different KDF). The schemes are incompatible — neither client can read the other's messages.

---

### T-131: Web Sends to C++ — Expected Decrypt Failure

- [ ] **Setup:** `webtest_alice` (browser) sends a message to `cpp_bob` (C++ client).
- **Expected:** `cpp_bob` cannot decrypt the message. It will show a decryption error or locked indicator.  
  This is the same scheme incompatibility as T-130, in the other direction.

---

---

## Appendix A — Quick Reference: Expected Status Codes

| Scenario | Expected HTTP Status |
|----------|---------------------|
| Successful registration | 201 |
| Successful login | 200 |
| Successful message send | 201 |
| Successful forward | 201 |
| Successful download/list/get | 200 |
| Successful delete/change/revoke/update | 200 |
| Missing required field | 400 |
| Invalid format (base64, ID) | 400 |
| Invalid/expired/missing JWT | 401 |
| Wrong credentials | 401 |
| Wrong current password | 401 |
| Access denied (wrong owner) | 403 |
| Resource not found | 404 |
| Duplicate username | 409 |

---

## Appendix B — Quick Reference: Exact Error Messages

| Error | Field | HTTP |
|-------|-------|------|
| `username is required` | validation | 400 |
| `username must contain only letters, numbers, and underscores` | validation | 400 |
| `username contains a reserved word` | validation | 400 |
| `username must be between 3 and 30 characters` | validation | 400 |
| `password is required` | validation | 400 |
| `password must be at least 8 characters` | validation | 400 |
| `publicKey must be a valid base64 string` | validation | 400 |
| `enc must be a valid base64 string` | validation | 400 |
| `ciphertext must be a valid base64 string` | validation | 400 |
| `to must be a positive integer user ID` | validation | 400 |
| `newPassword must be at least 8 characters` | validation | 400 |
| `Invalid message ID` | validation | 400 |
| `Invalid user ID` | validation | 400 |
| `Missing or invalid authorization header` | auth | 401 |
| `Invalid or expired token` | auth | 401 |
| `Session expired, please log in again` | auth (token_version) | 401 |
| `Invalid credentials` | auth | 401 |
| `Current password is incorrect` | auth | 401 |
| `Access denied` | authorization | 403 |
| `User not found` | not found | 404 |
| `User has not published a public key` | not found | 404 |
| `Message not found` | not found | 404 |
| `Recipient not found` | not found | 404 |
| `Username already taken` | conflict | 409 |

---

## Appendix C — Key Architectural Constraints

1. **The server never stores or sees plaintext.** Only `enc` (base64 ephemeral public key) and `ciphertext` (base64 AES-GCM output) are stored.
2. **Blockchain records are permanent.** Even after a message is deleted from the server, its hash remains on Sepolia forever. The verify page will still find the on-chain record.
3. **C++ and web clients are NOT interoperable.** They use different KDF schemes (`securechat-v2` vs `securechat-v1`). This is a known design choice, not a bug.
4. **Private keys never leave the client.** The web client stores them in `localStorage`. The C++ client stores them encrypted at `~/.rizzie/keys/identity.key`. The server only stores public keys.
5. **Senders cannot decrypt their own sent messages.** Ephemeral keypairs are discarded after encryption. The web UI caches sent plaintext in `localStorage` as a workaround. The C++ client does the same.
6. **Token invalidation is immediate.** After a password change, all previously issued JWTs are rejected. The `token_version` column in `users` is incremented and checked on every authenticated request.
