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

## Run smoke test

```bash
./build/client
```

Expected output ends with `Encrypt/decrypt round-trip OK.`

## Crypto design

Each outgoing message generates a fresh ephemeral X25519 key pair.
The ephemeral private key performs the DH with the recipient's static public key;
the ephemeral public key is transmitted as the `enc` field.
The shared secret is key-derived via HKDF-SHA256 (libsodium 1.0.19 native API)
and used as an AES-256-GCM key to encrypt the plaintext.

This matches the server API contract:

- **POST /messages** body: `{ "to": "<userId>", "enc": "<base64>", "ciphertext": "<base64>" }`
- **GET /messages** response includes `enc` and `ciphertext` fields per message

The `ciphertext` field is `nonce (12 bytes) || ciphertext+tag` encoded as base64.
