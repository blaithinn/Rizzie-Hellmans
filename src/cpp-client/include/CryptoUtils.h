#pragma once
#include <string>
#include <vector>
#include <sodium.h>

class CryptoUtils {
public:
    // Key pair generation
    static void generateKeyPair(std::vector<unsigned char>& publicKey,
                                std::vector<unsigned char>& privateKey);

    // Encode/decode base64 for sending keys over HTTP
    static std::string toBase64(const std::vector<unsigned char>& data);
    static std::vector<unsigned char> fromBase64(const std::string& b64);

    // Authenticated encryption — HPKE Mode_Auth equivalent.
    // Construction: X25519 DH → HKDF-SHA256 → AES-256-GCM.
    //
    // The sender's private key is bound into the DH step, so only the true holder
    // of senderSecretKey could have produced a ciphertext that decrypts correctly.
    // The sender's public key is included in the HKDF info string for domain separation
    // (different senders and protocol versions derive distinct keys from the same DH output).
    //
    // Payload layout: nonce (12 bytes) || ciphertext+tag (plaintext.size() + 16 bytes)
    // The 12-byte nonce is randomly generated per message and prepended for transport.
    static std::vector<unsigned char> encryptMessage(
        const std::string& plaintext,
        const std::vector<unsigned char>& recipientPublicKey,
        const std::vector<unsigned char>& senderSecretKey);

    // Decrypts a payload produced by encryptMessage.
    // Reproduces the same DH + HKDF derivation using recipientSecretKey and senderPublicKey.
    // Throws std::runtime_error on wrong keys or any tampering (AES-GCM tag mismatch).
    static std::string decryptMessage(
        const std::vector<unsigned char>& payload,
        const std::vector<unsigned char>& senderPublicKey,
        const std::vector<unsigned char>& recipientSecretKey);
};
