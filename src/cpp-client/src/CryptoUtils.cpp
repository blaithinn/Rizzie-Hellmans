#include "CryptoUtils.h"
#include <sodium.h>
#include <stdexcept>
#include <cstring>

// ---- HKDF-SHA256 helpers (RFC 5869) ----------------------------------------
// libsodium >= 1.0.19 exposes crypto_kdf_hkdf_sha256_extract/expand natively,
// but Ubuntu ships 1.0.18, so we implement the same two-step construction using
// the streaming HMAC-SHA256 API that has been available since much earlier.

// Extract: PRK = HMAC-SHA256(salt, IKM)
// Null/empty salt is replaced by a 32-byte all-zero string per RFC 5869 §2.2.
static void hkdfExtract(const unsigned char* salt, size_t saltLen,
                         const unsigned char* ikm,  size_t ikmLen,
                         unsigned char prk[crypto_auth_hmacsha256_BYTES])
{
    unsigned char zeroSalt[crypto_auth_hmacsha256_BYTES] = {};
    if (salt == nullptr || saltLen == 0) { salt = zeroSalt; saltLen = sizeof(zeroSalt); }

    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, salt, saltLen);
    crypto_auth_hmacsha256_update(&st, ikm, ikmLen);
    crypto_auth_hmacsha256_final(&st, prk);
    sodium_memzero(&st, sizeof(st));
}

// Expand: OKM = T(1) — produces exactly 32 bytes (one HMAC-SHA256 block).
// T(1) = HMAC-SHA256(PRK, info || 0x01)  (T(0) = "" per the RFC)
static void hkdfExpand(const unsigned char prk[crypto_auth_hmacsha256_BYTES],
                        const unsigned char* info, size_t infoLen,
                        unsigned char* out, size_t outLen)
{
    // One block covers up to 32 bytes; AES-256-GCM needs exactly 32, so this is sufficient.
    if (outLen > crypto_auth_hmacsha256_BYTES) {
        throw std::runtime_error("hkdfExpand: outLen > 32 not implemented");
    }
    const unsigned char counter = 0x01;
    unsigned char block[crypto_auth_hmacsha256_BYTES];

    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, prk, crypto_auth_hmacsha256_BYTES);
    crypto_auth_hmacsha256_update(&st, info, infoLen);
    crypto_auth_hmacsha256_update(&st, &counter, 1);
    crypto_auth_hmacsha256_final(&st, block);
    sodium_memzero(&st, sizeof(st));

    std::memcpy(out, block, outLen);
    sodium_memzero(block, sizeof(block));
}
// ----------------------------------------------------------------------------

void CryptoUtils::generateKeyPair(std::vector<unsigned char>& publicKey,
                                   std::vector<unsigned char>& privateKey) {
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialise libsodium");
    }

    publicKey.resize(crypto_box_PUBLICKEYBYTES);
    privateKey.resize(crypto_box_SECRETKEYBYTES);

    crypto_box_keypair(publicKey.data(), privateKey.data());
}

std::string CryptoUtils::toBase64(const std::vector<unsigned char>& data) {
    size_t b64len = sodium_base64_encoded_len(data.size(), sodium_base64_VARIANT_ORIGINAL);
    std::string result(b64len, '\0');
    sodium_bin2base64(result.data(), b64len, data.data(), data.size(),
                      sodium_base64_VARIANT_ORIGINAL);
    // remove null terminator sodium adds
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

std::vector<unsigned char> CryptoUtils::encryptMessage(
    const std::string& plaintext,
    const std::vector<unsigned char>& recipientPublicKey,
    const std::vector<unsigned char>& senderSecretKey)
{
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialise libsodium");
    }
    // AES-256-GCM requires hardware AES support (AES-NI on x86, crypto extensions on ARM)
    if (!crypto_aead_aes256gcm_is_available()) {
        throw std::runtime_error("AES-256-GCM is not available on this CPU");
    }

    // --- Step 1: X25519 Diffie-Hellman ---
    // Compute a shared secret from the sender's private key and the recipient's public key.
    // Binding sender_sk into the DH is what gives us Mode_Auth: only the true holder of
    // sender_sk produces the same shared secret, so a forged ciphertext won't decrypt.
    std::vector<unsigned char> sharedSecret(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(sharedSecret.data(),
                          senderSecretKey.data(),
                          recipientPublicKey.data()) != 0) {
        throw std::runtime_error("X25519 DH failed (low-order point rejected)");
    }

    // Derive the sender's public key from their secret key so we can include it in the
    // HKDF info string — the decrypting side will supply it as a parameter, but we need
    // it here to build the same info bytes without requiring an extra argument.
    std::vector<unsigned char> senderPublicKey(crypto_scalarmult_BYTES);
    crypto_scalarmult_base(senderPublicKey.data(), senderSecretKey.data());

    // --- Step 2: HKDF-SHA256 key derivation ---
    // Extract a pseudorandom key (PRK) from the raw DH output.
    // Null salt defaults to an all-zero salt per RFC 5869 §2.2.
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    hkdfExtract(nullptr, 0, sharedSecret.data(), sharedSecret.size(), prk);
    sodium_memzero(sharedSecret.data(), sharedSecret.size());

    // Expand to a 32-byte AES-256-GCM key.
    // Info = "securechat-v1" || sender_pk provides domain separation: different senders
    // and protocol versions derive distinct keys even from the same DH output.
    const std::string infoPrefix = "securechat-v1";
    std::vector<unsigned char> info(infoPrefix.begin(), infoPrefix.end());
    info.insert(info.end(), senderPublicKey.begin(), senderPublicKey.end());

    std::vector<unsigned char> aesKey(crypto_aead_aes256gcm_KEYBYTES);
    hkdfExpand(prk, info.data(), info.size(), aesKey.data(), aesKey.size());
    sodium_memzero(prk, sizeof(prk));

    // --- Step 3: AES-256-GCM encryption ---
    // AES-256-GCM uses a 12-byte nonce (96-bit, the GCM standard size).
    // Random generation is safe here because the derived key is fresh per message.
    std::vector<unsigned char> nonce(crypto_aead_aes256gcm_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    // crypto_aead_aes256gcm_encrypt appends the 16-byte authentication tag after the ciphertext.
    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
    unsigned long long ciphertextLen = 0;
    if (crypto_aead_aes256gcm_encrypt(
            ciphertext.data(), &ciphertextLen,
            reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
            nullptr, 0,  // no additional authenticated data
            nullptr,     // nsec — not used by this primitive, must be null
            nonce.data(),
            aesKey.data()) != 0) {
        sodium_memzero(aesKey.data(), aesKey.size());
        throw std::runtime_error("AES-256-GCM encryption failed");
    }
    sodium_memzero(aesKey.data(), aesKey.size());
    ciphertext.resize(ciphertextLen);

    // Final payload: nonce (12 B) || ciphertext+tag (plaintext.size() + 16 B)
    std::vector<unsigned char> payload;
    payload.reserve(nonce.size() + ciphertext.size());
    payload.insert(payload.end(), nonce.begin(), nonce.end());
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());
    return payload;
}

std::string CryptoUtils::decryptMessage(
    const std::vector<unsigned char>& payload,
    const std::vector<unsigned char>& senderPublicKey,
    const std::vector<unsigned char>& recipientSecretKey)
{
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialise libsodium");
    }
    if (!crypto_aead_aes256gcm_is_available()) {
        throw std::runtime_error("AES-256-GCM is not available on this CPU");
    }

    // Minimum valid payload is nonce + tag alone (zero-length plaintext is legal)
    const size_t minLen = crypto_aead_aes256gcm_NPUBBYTES + crypto_aead_aes256gcm_ABYTES;
    if (payload.size() < minLen) {
        throw std::runtime_error("Payload too short to be valid ciphertext");
    }

    // --- Step 1: X25519 Diffie-Hellman ---
    // X25519 is commutative: X25519(recipient_sk, sender_pk) == X25519(sender_sk, recipient_pk),
    // so the recipient reproduces the exact same shared secret the sender computed.
    std::vector<unsigned char> sharedSecret(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(sharedSecret.data(),
                          recipientSecretKey.data(),
                          senderPublicKey.data()) != 0) {
        throw std::runtime_error("X25519 DH failed");
    }

    // --- Step 2: HKDF-SHA256 key derivation (must mirror encryptMessage exactly) ---
    unsigned char prk[crypto_auth_hmacsha256_BYTES];
    hkdfExtract(nullptr, 0, sharedSecret.data(), sharedSecret.size(), prk);
    sodium_memzero(sharedSecret.data(), sharedSecret.size());

    const std::string infoPrefix = "securechat-v1";
    std::vector<unsigned char> info(infoPrefix.begin(), infoPrefix.end());
    info.insert(info.end(), senderPublicKey.begin(), senderPublicKey.end());

    std::vector<unsigned char> aesKey(crypto_aead_aes256gcm_KEYBYTES);
    hkdfExpand(prk, info.data(), info.size(), aesKey.data(), aesKey.size());
    sodium_memzero(prk, sizeof(prk));

    // --- Step 3: AES-256-GCM decryption ---
    const unsigned char* nonce      = payload.data();
    const unsigned char* ciphertext = payload.data() + crypto_aead_aes256gcm_NPUBBYTES;
    size_t              ciphertextLen = payload.size() - crypto_aead_aes256gcm_NPUBBYTES;

    std::vector<unsigned char> plaintext(ciphertextLen - crypto_aead_aes256gcm_ABYTES);
    unsigned long long plaintextLen = 0;
    if (crypto_aead_aes256gcm_decrypt(
            plaintext.data(), &plaintextLen,
            nullptr,           // nsec — not used by this primitive, must be null
            ciphertext, ciphertextLen,
            nullptr, 0,        // no additional authenticated data
            nonce,
            aesKey.data()) != 0) {
        sodium_memzero(aesKey.data(), aesKey.size());
        // Fires on wrong keys OR any bit-flip anywhere in the payload
        throw std::runtime_error("Decryption failed: authentication tag mismatch");
    }
    sodium_memzero(aesKey.data(), aesKey.size());
    plaintext.resize(plaintextLen);

    return std::string(plaintext.begin(), plaintext.end());
}

std::vector<unsigned char> CryptoUtils::fromBase64(const std::string& b64) {
    std::vector<unsigned char> bin(b64.size());
    size_t binLen = 0;
    if (sodium_base642bin(bin.data(), bin.size(),
                          b64.data(), b64.size(),
                          nullptr, &binLen, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0) {
        throw std::runtime_error("Invalid base64 input");
    }
    bin.resize(binLen);
    return bin;
}
