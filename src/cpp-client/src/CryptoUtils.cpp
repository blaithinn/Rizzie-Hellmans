#include "CryptoUtils.h"
#include <sodium.h>
#include <stdexcept>
#include <fstream>
#include <cstring>

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
    if (!result.empty() && result.back() == '\0') result.pop_back();
    return result;
}

std::vector<unsigned char> CryptoUtils::encryptMessage(
    const std::string& plaintext,
    const std::vector<unsigned char>& recipientPublicKey,
    const std::vector<unsigned char>& senderSecretKey,
    std::vector<unsigned char>& encOut)
{
    (void)senderSecretKey;  // DH uses ephemeral key; static sender key not bound in this mode

    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialise libsodium");
    }
    if (!crypto_aead_aes256gcm_is_available()) {
        throw std::runtime_error("AES-256-GCM is not available on this CPU");
    }

    // --- Step 1: Generate ephemeral X25519 key pair ---
    // Fresh per-message ephemeral key means ciphertexts are unlinkable even to the
    // same sender, and forward secrecy is preserved if the sender's static key leaks.
    encOut.resize(crypto_box_PUBLICKEYBYTES);
    std::vector<unsigned char> ephSk(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(encOut.data(), ephSk.data());

    // --- Step 2: X25519 Diffie-Hellman ---
    std::vector<unsigned char> sharedSecret(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(sharedSecret.data(),
                          ephSk.data(),
                          recipientPublicKey.data()) != 0) {
        sodium_memzero(ephSk.data(), ephSk.size());
        throw std::runtime_error("X25519 DH failed (low-order point rejected)");
    }
    sodium_memzero(ephSk.data(), ephSk.size());

    // --- Step 3: HKDF-SHA256 key derivation (libsodium 1.0.19 native API) ---
    unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    // Null salt is RFC 5869 §2.2 compliant — libsodium substitutes 32 zero bytes.
    if (crypto_kdf_hkdf_sha256_extract(prk, nullptr, 0,
                                        sharedSecret.data(), sharedSecret.size()) != 0) {
        sodium_memzero(sharedSecret.data(), sharedSecret.size());
        throw std::runtime_error("HKDF extract failed");
    }
    sodium_memzero(sharedSecret.data(), sharedSecret.size());

    // Info = "securechat-v1" || eph_pk ties the key to this specific ephemeral exchange.
    const std::string infoPrefix = "securechat-v1";
    std::vector<unsigned char> info(infoPrefix.begin(), infoPrefix.end());
    info.insert(info.end(), encOut.begin(), encOut.end());

    std::vector<unsigned char> aesKey(crypto_aead_aes256gcm_KEYBYTES);
    if (crypto_kdf_hkdf_sha256_expand(aesKey.data(), aesKey.size(),
                                       reinterpret_cast<const char*>(info.data()), info.size(),
                                       prk) != 0) {
        sodium_memzero(prk, sizeof(prk));
        throw std::runtime_error("HKDF expand failed");
    }
    sodium_memzero(prk, sizeof(prk));

    // --- Step 4: AES-256-GCM encryption ---
    std::vector<unsigned char> nonce(crypto_aead_aes256gcm_NPUBBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> ciphertext(plaintext.size() + crypto_aead_aes256gcm_ABYTES);
    unsigned long long ciphertextLen = 0;
    if (crypto_aead_aes256gcm_encrypt(
            ciphertext.data(), &ciphertextLen,
            reinterpret_cast<const unsigned char*>(plaintext.data()), plaintext.size(),
            nullptr, 0,   // no additional authenticated data
            nullptr,      // nsec — unused by this primitive
            nonce.data(),
            aesKey.data()) != 0) {
        sodium_memzero(aesKey.data(), aesKey.size());
        throw std::runtime_error("AES-256-GCM encryption failed");
    }
    sodium_memzero(aesKey.data(), aesKey.size());
    ciphertext.resize(ciphertextLen);

    // Payload sent as the "ciphertext" field: nonce (12 B) || ciphertext+tag
    std::vector<unsigned char> payload;
    payload.reserve(nonce.size() + ciphertext.size());
    payload.insert(payload.end(), nonce.begin(), nonce.end());
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());
    return payload;
}

std::string CryptoUtils::decryptMessage(
    const std::vector<unsigned char>& payload,
    const std::vector<unsigned char>& enc,
    const std::vector<unsigned char>& recipientSecretKey)
{
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialise libsodium");
    }
    if (!crypto_aead_aes256gcm_is_available()) {
        throw std::runtime_error("AES-256-GCM is not available on this CPU");
    }

    const size_t minLen = crypto_aead_aes256gcm_NPUBBYTES + crypto_aead_aes256gcm_ABYTES;
    if (payload.size() < minLen) {
        throw std::runtime_error("Payload too short to be valid ciphertext");
    }

    // --- Step 1: X25519 DH — recipient's static key + sender's ephemeral public key ---
    // X25519 is commutative: X25519(recipient_sk, eph_pk) == X25519(eph_sk, recipient_pk)
    std::vector<unsigned char> sharedSecret(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(sharedSecret.data(),
                          recipientSecretKey.data(),
                          enc.data()) != 0) {
        throw std::runtime_error("X25519 DH failed");
    }

    // --- Step 2: HKDF-SHA256 key derivation (must mirror encryptMessage exactly) ---
    unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    if (crypto_kdf_hkdf_sha256_extract(prk, nullptr, 0,
                                        sharedSecret.data(), sharedSecret.size()) != 0) {
        sodium_memzero(sharedSecret.data(), sharedSecret.size());
        throw std::runtime_error("HKDF extract failed");
    }
    sodium_memzero(sharedSecret.data(), sharedSecret.size());

    const std::string infoPrefix = "securechat-v1";
    std::vector<unsigned char> info(infoPrefix.begin(), infoPrefix.end());
    info.insert(info.end(), enc.begin(), enc.end());

    std::vector<unsigned char> aesKey(crypto_aead_aes256gcm_KEYBYTES);
    if (crypto_kdf_hkdf_sha256_expand(aesKey.data(), aesKey.size(),
                                       reinterpret_cast<const char*>(info.data()), info.size(),
                                       prk) != 0) {
        sodium_memzero(prk, sizeof(prk));
        throw std::runtime_error("HKDF expand failed");
    }
    sodium_memzero(prk, sizeof(prk));

    // --- Step 3: AES-256-GCM decryption ---
    const unsigned char* nonce         = payload.data();
    const unsigned char* ciphertext    = payload.data() + crypto_aead_aes256gcm_NPUBBYTES;
    size_t               ciphertextLen = payload.size() - crypto_aead_aes256gcm_NPUBBYTES;

    std::vector<unsigned char> plaintext(ciphertextLen - crypto_aead_aes256gcm_ABYTES);
    unsigned long long plaintextLen = 0;
    if (crypto_aead_aes256gcm_decrypt(
            plaintext.data(), &plaintextLen,
            nullptr,            // nsec — unused
            ciphertext, ciphertextLen,
            nullptr, 0,         // no additional authenticated data
            nonce,
            aesKey.data()) != 0) {
        sodium_memzero(aesKey.data(), aesKey.size());
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

// ---------------------------------------------------------------------------
// Persistent encrypted private-key storage
// ---------------------------------------------------------------------------

static void deriveAtRestKey(unsigned char outKey[crypto_aead_aes256gcm_KEYBYTES],
                            const unsigned char salt[crypto_pwhash_SALTBYTES],
                            const std::string& passphrase)
{
    // Step 1: Argon2id password hashing — stretches passphrase into 32-byte IKM.
    unsigned char ikm[32];
    if (crypto_pwhash(ikm, sizeof(ikm),
                      passphrase.c_str(), passphrase.size(),
                      salt,
                      crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE,
                      crypto_pwhash_ALG_ARGON2ID13) != 0) {
        throw std::runtime_error("crypto_pwhash failed (out of memory?)");
    }

    // Step 2a: HKDF-SHA256 extract — empty salt (RFC 5869 §2.2: libsodium uses 32 zero bytes).
    unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    if (crypto_kdf_hkdf_sha256_extract(prk, nullptr, 0, ikm, sizeof(ikm)) != 0) {
        sodium_memzero(ikm, sizeof(ikm));
        throw std::runtime_error("HKDF extract failed");
    }
    sodium_memzero(ikm, sizeof(ikm));

    // Step 2b: HKDF-SHA256 expand — info binds this key to the at-rest purpose.
    const char info[] = "rizzie-atrest-key-v1";
    if (crypto_kdf_hkdf_sha256_expand(outKey, crypto_aead_aes256gcm_KEYBYTES,
                                       info, std::strlen(info), prk) != 0) {
        sodium_memzero(prk, sizeof(prk));
        throw std::runtime_error("HKDF expand failed");
    }
    sodium_memzero(prk, sizeof(prk));
}

void CryptoUtils::savePrivateKey(const std::vector<unsigned char>& privateKey,
                                  const std::string& passphrase,
                                  const std::string& filepath)
{
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialise libsodium");
    }
    if (!crypto_aead_aes256gcm_is_available()) {
        throw std::runtime_error("AES-256-GCM is not available on this CPU (no AES-NI)");
    }

    // --- Step 1: random salt for Argon2id ---
    unsigned char salt[crypto_pwhash_SALTBYTES]; // 16 bytes
    randombytes_buf(salt, sizeof(salt));

    // --- Steps 2+3: derive AES key ---
    unsigned char aesKey[crypto_aead_aes256gcm_KEYBYTES];
    deriveAtRestKey(aesKey, salt, passphrase);

    // --- Step 4: random nonce ---
    unsigned char nonce[crypto_aead_aes256gcm_NPUBBYTES]; // 12 bytes
    randombytes_buf(nonce, sizeof(nonce));

    // --- Step 5: AES-256-GCM encryption ---
    std::vector<unsigned char> ciphertext(privateKey.size() + crypto_aead_aes256gcm_ABYTES);
    unsigned long long ciphertextLen = 0;
    if (crypto_aead_aes256gcm_encrypt(
            ciphertext.data(), &ciphertextLen,
            privateKey.data(), privateKey.size(),
            nullptr, 0,
            nullptr,
            nonce, aesKey) != 0) {
        sodium_memzero(aesKey, sizeof(aesKey));
        throw std::runtime_error("AES-256-GCM encryption failed");
    }
    sodium_memzero(aesKey, sizeof(aesKey));
    ciphertext.resize(ciphertextLen);

    // --- Step 6: write salt || nonce || ciphertext+tag ---
    std::ofstream file(filepath, std::ios::binary | std::ios::trunc);
    if (!file) {
        throw std::runtime_error("Cannot open key file for writing: " + filepath);
    }
    file.write(reinterpret_cast<const char*>(salt),       sizeof(salt));
    file.write(reinterpret_cast<const char*>(nonce),      sizeof(nonce));
    file.write(reinterpret_cast<const char*>(ciphertext.data()), static_cast<std::streamsize>(ciphertext.size()));
    if (!file) {
        throw std::runtime_error("Failed to write key file: " + filepath);
    }
}

std::vector<unsigned char> CryptoUtils::loadPrivateKey(const std::string& passphrase,
                                                         const std::string& filepath)
{
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialise libsodium");
    }
    if (!crypto_aead_aes256gcm_is_available()) {
        throw std::runtime_error("AES-256-GCM is not available on this CPU (no AES-NI)");
    }

    // --- Read file ---
    std::ifstream file(filepath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Cannot open key file: " + filepath);
    }
    std::vector<unsigned char> fileData(
        (std::istreambuf_iterator<char>(file)),
        std::istreambuf_iterator<char>());

    const size_t headerLen = crypto_pwhash_SALTBYTES + crypto_aead_aes256gcm_NPUBBYTES;
    if (fileData.size() <= headerLen + crypto_aead_aes256gcm_ABYTES) {
        throw std::runtime_error("Key file is too short or corrupt: " + filepath);
    }

    // --- Split into components ---
    const unsigned char* salt       = fileData.data();
    const unsigned char* nonce      = fileData.data() + crypto_pwhash_SALTBYTES;
    const unsigned char* ciphertext = fileData.data() + headerLen;
    size_t               ciphertextLen = fileData.size() - headerLen;

    // --- Re-derive key (steps 2+3 mirror savePrivateKey) ---
    unsigned char aesKey[crypto_aead_aes256gcm_KEYBYTES];
    deriveAtRestKey(aesKey, salt, passphrase);

    // --- AES-256-GCM decryption ---
    std::vector<unsigned char> privateKey(ciphertextLen - crypto_aead_aes256gcm_ABYTES);
    unsigned long long plaintextLen = 0;
    if (crypto_aead_aes256gcm_decrypt(
            privateKey.data(), &plaintextLen,
            nullptr,
            ciphertext, ciphertextLen,
            nullptr, 0,
            nonce, aesKey) != 0) {
        sodium_memzero(aesKey, sizeof(aesKey));
        throw std::runtime_error("Failed to decrypt key file: wrong passphrase or corrupt file");
    }
    sodium_memzero(aesKey, sizeof(aesKey));
    privateKey.resize(plaintextLen);

    return privateKey;
}
