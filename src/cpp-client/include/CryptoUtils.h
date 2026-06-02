#pragma once
#include <string>
#include <vector>
#include <sodium.h>

class CryptoUtils {
public:
    // Key pair generation
    static void generateKeyPair(std::vector<unsigned char>& publicKey,
                                std::vector<unsigned char>& privateKey);

    // Encode/decode base64 for sending keys/ciphertext over HTTP
    static std::string toBase64(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> fromBase64(const std::string& b64);

    // Authenticated encryption — HPKE Mode_Auth equivalent.
    // Construction: (eph X25519 DH || static X25519 DH) → HKDF-SHA256 → AES-256-GCM.
    //
    // Two DH operations are combined as the HKDF input:
    //   eph_dh   = X25519(eph_sk,    recipient_pk)   — fresh per message
    //   static_dh = X25519(sender_sk, recipient_pk)   — binds sender identity
    // HKDF extract runs over eph_dh || static_dh, so decryption requires knowledge
    // of both the ephemeral private key (held by sender) and the sender's static
    // private key.  A recipient verifying with the wrong senderPublicKey gets a
    // different shared secret and the AES-GCM tag fails — forged messages are
    // detected.
    //
    // The ephemeral public key is written to encOut and transmitted as the API
    // "enc" field so the recipient can reproduce the same shared secret.
    //
    // Return value layout: nonce (12 bytes) || ciphertext+tag (plaintext.size() + 16 bytes)
    static std::vector<unsigned char> encryptMessage(
        const std::string& plaintext,
        const std::vector<unsigned char>& recipientPublicKey,
        const std::vector<unsigned char>& senderSecretKey,
        std::vector<unsigned char>& encOut);

    // Decrypts a payload produced by encryptMessage.
    // enc is the ephemeral public key from the "enc" API field.
    // senderPublicKey is the sender's registered static X25519 public key —
    // decryption fails (AES-GCM tag mismatch) if it does not match the key used
    // during encryption, proving the message came from that specific sender.
    // Throws std::runtime_error on wrong keys or any tampering.
    static std::string decryptMessage(
        const std::vector<unsigned char>& payload,
        const std::vector<unsigned char>& enc,
        const std::vector<unsigned char>& recipientSecretKey,
        const std::vector<unsigned char>& senderPublicKey);

    // Persistent encrypted private-key storage.
    //
    // savePrivateKey encrypts privateKey with a passphrase-derived key and writes a
    // binary file:  salt (16 B) || nonce (12 B) || ciphertext+tag
    //
    // Key derivation:
    //   1. Argon2id (crypto_pwhash, INTERACTIVE params) stretches the passphrase
    //      using the random salt to produce a 32-byte intermediate key (IKM).
    //   2. HKDF-SHA256 (extract + expand, info = "rizzie-atrest-key-v1") derives
    //      the final AES-256-GCM key from that IKM.
    //
    // loadPrivateKey reverses the process exactly.
    //
    // Throws std::runtime_error on any failure (bad passphrase, file error, no AES-NI).
    static void savePrivateKey(const std::vector<unsigned char>& privateKey,
                               const std::string& passphrase,
                               const std::string& filepath);

    static std::vector<unsigned char> loadPrivateKey(const std::string& passphrase,
                                                      const std::string& filepath);
};
