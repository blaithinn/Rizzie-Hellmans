# SecureChat C++ Client

## Prerequisites

### libsodium 1.0.19 (must be built from source on Ubuntu 24.04)

Ubuntu 24.04's apt repository only provides libsodium 1.0.18, which lacks the
`crypto_kdf_hkdf_sha256_extract` and `crypto_kdf_hkdf_sha256_expand` APIs added in 1.0.19.
Build and install 1.0.19 from source before configuring the project:

```bash
cd /tmp
wget https://download.libsodium.org/libsodium/releases/libsodium-1.0.19.tar.gz
tar -xzf libsodium-1.0.19.tar.gz
cd libsodium-stable
./configure
make && make check
sudo make install
sudo ldconfig
```

Verify the version:
```bash
pkg-config --modversion libsodium   # should print 1.0.19
```

### Other dependencies

```bash
sudo apt install cmake libcurl4-openssl-dev
```

## Build

```bash
cd src/cpp-client
cmake -B build -S .
cmake --build build
```

## Run

```bash
./build/client
```

On first launch you will be prompted for a passphrase used to encrypt your local
private key at rest. On subsequent launches the same passphrase unlocks the
existing key. The TUI menu then provides all messaging operations.

## Crypto design

Each outgoing message uses a two-DH construction equivalent to HPKE `Mode_Auth`
(RFC 9180 §5.1.3):

1. A fresh ephemeral X25519 key pair is generated per message.
2. Two Diffie-Hellman operations are performed:
   - `eph_dh  = X25519(eph_sk,    recipient_pk)` — provides per-message confidentiality
   - `static_dh = X25519(sender_sk, recipient_pk)` — cryptographically binds sender identity
3. `HKDF-SHA256(IKM = eph_dh ‖ static_dh, info = "securechat-v2" ‖ eph_pk)` derives the AES key.
4. `AES-256-GCM` encrypts the plaintext with the ephemeral public key (`eph_pk`) as AAD.

The static DH means that only the holder of `sender_sk` could have produced a
ciphertext that decrypts correctly under the recipient's key — providing sender
authentication without a separate signature. The ephemeral public key is transmitted
as the `enc` field and is bound as AEAD additional data so any tampering with it is
detected at decryption.

Server API contract:

- **POST /messages** body: `{ "to": "<userId>", "enc": "<base64>", "ciphertext": "<base64>" }`
- **GET /messages** response includes `enc` and `ciphertext` fields per message

The `ciphertext` field layout: `nonce (12 bytes) || ciphertext+tag`, base64-encoded.

See `crypto_design_document.md` at the repo root for the full threat model,
parameter-level justifications, and known limitations.
