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
    if (sodium_init() < 0) {
        throw std::runtime_error("Failed to initialise libsodium");
    }
    if (!crypto_aead_aes256gcm_is_available()) {
        throw std::runtime_error("AES-256-GCM is not available on this CPU");
    }

    // --- Step 1: Generate ephemeral X25519 key pair ---
    // Fresh per-message ephemeral key gives per-message forward secrecy.
    encOut.resize(crypto_box_PUBLICKEYBYTES);
    std::vector<unsigned char> ephSk(crypto_box_SECRETKEYBYTES);
    crypto_box_keypair(encOut.data(), ephSk.data());

    // --- Step 2a: Ephemeral DH — X25519(eph_sk, recipient_pk) ---
    std::vector<unsigned char> ephDH(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(ephDH.data(), ephSk.data(), recipientPublicKey.data()) != 0) {
        sodium_memzero(ephSk.data(), ephSk.size());
        throw std::runtime_error("X25519 ephemeral DH failed (low-order point rejected)");
    }
    sodium_memzero(ephSk.data(), ephSk.size());

    // --- Step 2b: Static sender DH — X25519(sender_sk, recipient_pk) ---
    // Binding the sender's static key means only the holder of sender_sk can produce
    // a ciphertext that decrypts correctly under the recipient's key — sender auth.
    std::vector<unsigned char> staticDH(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(staticDH.data(), senderSecretKey.data(), recipientPublicKey.data()) != 0) {
        sodium_memzero(ephDH.data(), ephDH.size());
        throw std::runtime_error("X25519 static DH failed (low-order point rejected)");
    }

    // --- Step 3: HKDF-SHA256 over eph_dh || static_dh ---
    // Null salt is RFC 5869 §2.2 compliant — libsodium substitutes 32 zero bytes.
    std::vector<unsigned char> dhInput;
    dhInput.reserve(ephDH.size() + staticDH.size());
    dhInput.insert(dhInput.end(), ephDH.begin(), ephDH.end());
    dhInput.insert(dhInput.end(), staticDH.begin(), staticDH.end());
    sodium_memzero(ephDH.data(), ephDH.size());
    sodium_memzero(staticDH.data(), staticDH.size());

    unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    if (crypto_kdf_hkdf_sha256_extract(prk, nullptr, 0,
                                        dhInput.data(), dhInput.size()) != 0) {
        sodium_memzero(dhInput.data(), dhInput.size());
        throw std::runtime_error("HKDF extract failed");
    }
    sodium_memzero(dhInput.data(), dhInput.size());

    // Info = "securechat-v2" || eph_pk ties the derived key to this exchange.
    const std::string infoPrefix = "securechat-v2";
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
            encOut.data(), encOut.size(),
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
    const std::vector<unsigned char>& recipientSecretKey,
    const std::vector<unsigned char>& senderPublicKey)
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

    // --- Step 1a: Ephemeral DH — X25519(recipient_sk, eph_pk) ---
    // X25519 is commutative: DH(recipient_sk, eph_pk) == DH(eph_sk, recipient_pk)
    std::vector<unsigned char> ephDH(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(ephDH.data(), recipientSecretKey.data(), enc.data()) != 0) {
        throw std::runtime_error("X25519 ephemeral DH failed");
    }

    // --- Step 1b: Static DH — X25519(recipient_sk, sender_pk) ---
    // Mirrors DH(sender_sk, recipient_pk) computed during encryption.
    // If senderPublicKey does not match the actual sender, the derived key differs
    // and the AES-GCM tag check fails — this is how sender identity is verified.
    std::vector<unsigned char> staticDH(crypto_scalarmult_BYTES);
    if (crypto_scalarmult(staticDH.data(), recipientSecretKey.data(), senderPublicKey.data()) != 0) {
        sodium_memzero(ephDH.data(), ephDH.size());
        throw std::runtime_error("X25519 static DH failed");
    }

    // --- Step 2: HKDF-SHA256 over eph_dh || static_dh (mirrors encryptMessage) ---
    std::vector<unsigned char> dhInput;
    dhInput.reserve(ephDH.size() + staticDH.size());
    dhInput.insert(dhInput.end(), ephDH.begin(), ephDH.end());
    dhInput.insert(dhInput.end(), staticDH.begin(), staticDH.end());
    sodium_memzero(ephDH.data(), ephDH.size());
    sodium_memzero(staticDH.data(), staticDH.size());

    unsigned char prk[crypto_kdf_hkdf_sha256_KEYBYTES];
    if (crypto_kdf_hkdf_sha256_extract(prk, nullptr, 0,
                                        dhInput.data(), dhInput.size()) != 0) {
        sodium_memzero(dhInput.data(), dhInput.size());
        throw std::runtime_error("HKDF extract failed");
    }
    sodium_memzero(dhInput.data(), dhInput.size());

    const std::string infoPrefix = "securechat-v2";
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
            enc.data(), enc.size(),
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
