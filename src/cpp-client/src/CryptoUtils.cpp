#include "CryptoUtils.h"
#include <sodium.h>
#include <stdexcept>

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
