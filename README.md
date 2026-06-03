# Rizzie-Hellmans — Secure Messaging Application

**CS4455 Cybersecurity — Epic Project 2026**
Team 18 | Blaithin Kavanagh · Rose McInerney
Live server: `rizzie-hellmans.theburkenator.com`
Contract (Sepolia): `0xe562bD4F0E06783a7133Dc1d4dD486406eD753DC`

---

## Project Overview

Rizzie-Hellmans is an end-to-end encrypted (E2EE) messaging application. Message plaintexts never leave the client unencrypted — the server stores and relays opaque ciphertext only. A Solidity smart contract on the Ethereum Sepolia testnet records a keccak256 digest of every message for tamper-evident integrity verification.

The system has three components:

| Component | Language / Tech | Location |
|-----------|----------------|----------|
| C++ command-line client | C++17, libsodium, libcurl, CMake | `src/cpp-client/` |
| REST API server | Node.js, Express, SQLite, argon2 | `src/server/` |
| Web frontend + verification page | HTML/JS, TweetNaCl, Web Crypto API, ethers.js | `public/` |

---

## Architecture

```
┌────────────────────────┐        HTTPS        ┌─────────────────────────────┐
│  C++ CLI client        │ ──────────────────► │  Node.js / Express server   │
│  (libcurl + libsodium) │                     │  port 80                    │
└────────────────────────┘                     │  rizzie-hellmans            │
                                               │  .theburkenator.com         │
┌────────────────────────┐        HTTPS        │                             │
│  Browser (public/)     │ ──────────────────► │  ┌─────────┐  ┌──────────┐ │
│  TweetNaCl + WebCrypto │                     │  │ SQLite  │  │ ethers   │ │
└────────────────────────┘                     │  │ users.db│  │ → Sepolia│ │
                                               └──┴─────────┴──┴──────────┘─┘
                                                          │
                                               ┌──────────▼──────────┐
                                               │  Ethereum Sepolia   │
                                               │  MessageHash.sol    │
                                               │  0xe562bD4…        │
                                               └─────────────────────┘
```

All client–server traffic is over HTTPS (TLS). libcurl has `CURLOPT_SSL_VERIFYPEER` and `CURLOPT_SSL_VERIFYHOST` enabled on every request. The server never receives or stores plaintext.

> **Note on interoperability:** The C++ client and the JS browser client use different key derivation schemes (`"securechat-v2"` vs `"securechat-v1"`) and the C++ client additionally performs a static sender DH for sender authentication. Messages encrypted by one client cannot be decrypted by the other.

---

## Prerequisites

### Server
- Node.js 18+
- npm

### C++ client
- CMake 3.16+
- GCC or Clang with C++17 support
- **libsodium 1.0.19+** — the Ubuntu 24.04 apt package is 1.0.18 which is missing `crypto_kdf_hkdf_sha256_*` APIs
- libcurl with HTTPS support

#### Installing libsodium 1.0.19 from source (Ubuntu/Debian)
```bash
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.19.tar.gz
tar xf libsodium-1.0.19.tar.gz
cd libsodium-1.0.19
./configure --prefix=/usr/local
make -j$(nproc)
sudo make install
sudo ldconfig
```

---

## Server Setup

The server runs on a university VM managed via `pm2`. The live URL is `https://rizzie-hellmans.theburkenator.com`.

### SSH into the VM
```bash
ssh -i <path_to_your_key> student@200.69.13.70 -p 2217
```

### Check if the server is already running
```bash
pm2 status
```

### Restart after a git pull
```bash
cd ~/Rizzie-Hellmans
git pull
cd src/server
npm install
pm2 restart rizzie-api
```

### Start from scratch (if not running)
```bash
cd ~/Rizzie-Hellmans/src/server
pm2 start index.js --name rizzie-api
```

### View logs
```bash
pm2 logs rizzie-api
```

### Confirm it's live
```bash
curl https://rizzie-hellmans.theburkenator.com/health
```
Or open `https://rizzie-hellmans.theburkenator.com` in a browser.

### Environment variables
The `.env` file lives in the repository root on the VM. `JWT_SECRET` is mandatory — the server refuses to start without it. The three blockchain variables are optional; if omitted, messages are stored without a blockchain record and the server logs a warning.
```
JWT_SECRET=<a long random secret>
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/<your-alchemy-key>
SERVER_WALLET_PRIVATE_KEY=<ethereum wallet private key with Sepolia ETH>
CONTRACT_ADDRESS=0xe562bD4F0E06783a7133Dc1d4dD486406eD753DC
```

---

## C++ Client — Build and Run

### Build
```bash
cd src/cpp-client
cmake -B build
cmake --build build
```

CMake searches for libsodium in `/usr/local/lib` first (the 1.0.19 build) before the system path. If the build fails with a missing `crypto_kdf_hkdf_sha256_*` symbol, install libsodium 1.0.19 from source as above.

### Run
```bash
./build/client
```

On first launch, the client prompts for a passphrase, generates a fresh X25519 key pair, encrypts the private key under an Argon2id-derived AES-256-GCM key, and saves it to `~/.rizzie/keys/identity.key`. On subsequent runs the passphrase is used to decrypt and load the existing key.

### Menu
```
1. Register          — create an account on the server
2. Login             — authenticate and receive a JWT
3. Send message      — E2EE message to another user (by user ID)
4. View inbox        — fetch and decrypt all messages, grouped by conversation
5. Forward message   — re-encrypt a message for a third party (requires prior inbox fetch)
6. Change password   — update password; server invalidates all existing sessions
7. Download message  — fetch a single message by ID
8. Revoke access     — remove a user's forwarded-share access to a message
9. Delete message    — hard-delete a sent message from the server
0. Quit
```

---

## C++ Component Details

### File structure
```
src/cpp-client/
├── CMakeLists.txt
├── include/
│   ├── Client.h          — top-level client (orchestrates all operations)
│   ├── CryptoUtils.h     — key generation, E2EE encrypt/decrypt, at-rest key storage
│   ├── User.h            — models an authenticated user (username + public key)
│   ├── Message.h         — models a single message (id, sender, recipient, enc, ct, plaintext, txHash, sentAt)
│   ├── Conversation.h    — groups messages by conversation partner
│   ├── MessageStore.h    — in-memory cache of decrypted messages (used by forwardMessage)
│   ├── KeyStore.h        — TOFU key pinning (persisted to ~/.rizzie/keys/trusted_keys.txt)
│   └── HttpClient.h      — libcurl wrapper (GET, POST, PUT, DELETE over HTTPS with cert verification)
└── src/
    ├── main.cpp           — passphrase prompt, key load/generate, menu loop
    ├── Client.cpp         — all API calls and business logic
    ├── CryptoUtils.cpp    — libsodium cryptographic operations
    ├── User.cpp
    ├── Conversation.cpp
    ├── MessageStore.cpp
    ├── KeyStore.cpp
    └── HttpClient.cpp
```

### Classes and ownership
- `main` owns `Client` by value on the stack.
- `Client` owns `HttpClient`, `MessageStore`, and `User` via `std::unique_ptr` — they are heap-allocated but ownership is clear and deterministic.
- `KeyStore` is a plain member of `Client` (not a pointer) — its lifetime matches the client's exactly.
- `MessageStore` is reset (`make_unique`) at the start of each inbox fetch so the local cache always reflects the latest server state.
- `Conversation` objects live in a local `std::map` inside `fetchAndDecryptMessages` — temporary aggregators that go out of scope after display.

### STL containers and algorithms used
| Feature | Location |
|---------|----------|
| `std::vector<unsigned char>` | Every key, ciphertext, nonce, and DH output in `CryptoUtils` |
| `std::map<string, Conversation>` | Groups inbox messages by partner in `fetchAndDecryptMessages` |
| `std::set<string>` | Collects unique conversation partners (sorted, deduplicated) for the inbox summary |
| `std::unordered_map<string, string>` | `KeyStore` in-memory pin cache |
| `std::count` | Counts sent vs. received messages for the inbox header line |
| `std::sort` | Sorts messages within a conversation by `sentAt` timestamp before display |
| `std::copy` | Copies `Conversation::getMessages()` into a sortable `std::vector` |
| `std::find_if` | Used in `MessageStore::findById` and `KeyStore::getPinnedKey` |

Lambdas are used for the `std::sort` comparator and in `std::find_if` calls.

### Memory management
- No raw `new` or `delete` anywhere in the codebase. Heap objects use `std::unique_ptr`.
- All key material and DH outputs are held in `std::vector<unsigned char>` and zeroed with `sodium_memzero` immediately after use.
- libcurl handles are managed with `curl_easy_init`/`curl_easy_cleanup` in each request method — no leaks on error paths (handles are cleaned up before every return).

### Input sanitisation
`jsonEscape()` in `Client.cpp` escapes `\`, `"`, and control characters before embedding any user-supplied string into a JSON request body, preventing JSON injection. All server-side JSON parsing uses parameterised SQLite queries — no string concatenation into SQL.

---

## Cryptographic Design Summary

### C++ client — message encryption (HPKE Mode_Auth equivalent)

Two X25519 Diffie-Hellman operations are concatenated as the HKDF input, binding both a fresh ephemeral key (forward secrecy) and the sender's static key (sender authentication):

```
eph_dh    = X25519(eph_sk,    recipient_pk)   ← fresh ephemeral key per message
static_dh = X25519(sender_sk, recipient_pk)   ← binds sender identity

PRK     = HKDF-Extract(salt=∅, IKM = eph_dh || static_dh)
AES_key = HKDF-Expand(PRK, info = "securechat-v2" || eph_pk, len=32)
payload = nonce(12 B, random) || AES-256-GCM(AES_key, nonce, plaintext)

Transmitted: eph_pk as "enc" field, payload as "ciphertext" field (both base64)
```

Decryption mirrors this: `X25519(recipient_sk, eph_pk)` and `X25519(recipient_sk, sender_pk)`. An incorrect sender public key produces a different shared secret and the AES-GCM authentication tag fails.

### JS browser client — message encryption

The browser client uses a simpler scheme (no static sender DH):

```
eph_dh  = X25519(eph_sk, recipient_pk)        ← TweetNaCl nacl.scalarMult
AES_key = HKDF-SHA256(IKM=eph_dh, salt=0×32, info="securechat-v1" || eph_pk)
payload = nonce(12 B, random) || AES-256-GCM(AES_key, nonce, plaintext)
```

Web Crypto API (`crypto.subtle`) handles HKDF and AES-GCM. TweetNaCl handles X25519. The JS client has forward secrecy but not sender authentication. Keys are stored in `localStorage`; the private key never leaves the browser.

### At-rest private key encryption (C++ client)
```
IKM  = Argon2id(passphrase, salt=rand(16), opslimit=INTERACTIVE(2), memlimit=64 MB)
PRK  = HKDF-Extract(salt=∅, IKM)
key  = HKDF-Expand(PRK, info="rizzie-atrest-key-v1", len=32)
file = salt(16 B) || nonce(12 B, random) || AES-256-GCM(key, private_key)
```

### Server-side password hashing
Argon2id via the `argon2` npm package: `memoryCost=65536` (64 MB), `timeCost=3`, `parallelism=4`.

### TOFU key pinning (C++ client)
On first contact with a user, their public key is written to `~/.rizzie/keys/trusted_keys.txt`. On subsequent contacts the pinned key is compared and the user is warned interactively if it has changed, allowing detection of MITM attacks via a key-substituting server.

### Libraries used
- **libsodium 1.0.19** — all C++ crypto (X25519, AES-256-GCM, HKDF-SHA256, Argon2id, `randombytes_buf` CSPRNG)
- **TweetNaCl** (`nacl.js`) — X25519 in the browser
- **Web Crypto API** — HKDF-SHA256 and AES-256-GCM in the browser
- **argon2** (npm) — server-side Argon2id password hashing
- **jsonwebtoken** (npm) — JWT session tokens
- **ethers.js 6** — Sepolia blockchain interaction (server and browser)

---

## Blockchain — Integrity Verification

Every message stored by the server has a keccak256 digest written to the `MessageHash` Solidity contract on Ethereum Sepolia:

```javascript
hash = keccak256(base64_decode(enc) || base64_decode(ciphertext))
```

The resulting transaction hash is stored in SQLite alongside the message and returned to the client.

### Contract
- **Address:** `0xe562bD4F0E06783a7133Dc1d4dD486406eD753DC`
- **Network:** Ethereum Sepolia testnet
- **ABI and deployment details:** `docs/blockchain/contract.json`
- **Functions:** `storeHash(bytes32)`, `getHash(uint256)`, `getRecordCount()`
- **Event:** `HashStored(address indexed sender, bytes32 hash, uint256 timestamp)`

### Verification page
A standalone page at `/verify` (`public/verify.html`) allows anyone to verify a transaction hash:

1. Paste a transaction hash (returned by the server after sending a message)
2. The page queries Sepolia via Alchemy, retrieves the `HashStored` event, and displays the on-chain timestamp
3. A clear pass/fail result is shown

The page works independently of the messaging application — no login required. It can also be deep-linked with a `?tx=0x...` query parameter to auto-verify.

---

## Security Controls

| Concern | Control |
|---------|---------|
| SQL injection | `better-sqlite3` parameterised queries throughout — no string concatenation into SQL |
| JSON injection | `jsonEscape()` in C++ client escapes all user-controlled strings before JSON embedding |
| Input validation | Server validation middleware enforces username format (`[A-Za-z0-9_]`, 3–30 chars), password length (≥8), and base64 format on all public keys and ciphertext fields |
| Broken authentication | JWT with 24-hour expiry; `token_version` column incremented on password change, immediately invalidating all previous tokens |
| Broken access control | Download and forward endpoints verify sender/recipient ownership or explicit `message_shares` grant before serving |
| SSL/TLS | libcurl sets `CURLOPT_SSL_VERIFYPEER=1` and `CURLOPT_SSL_VERIFYHOST=2` on all HTTP methods |
| Sensitive data exposure | Passwords never logged or stored in plaintext; private keys encrypted at rest; server stores only ciphertext |
| Cryptographic issues | Only vetted libraries (libsodium, Web Crypto, TweetNaCl); CSPRNG for all nonces and salts; no hardcoded keys or IVs |
| Security misconfiguration | Security headers on all responses: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `X-XSS-Protection: 1; mode=block` |
| Server reads plaintext | Impossible by design — server stores base64 ciphertext only; decryption requires the recipient's private key |
