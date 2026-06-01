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

    // Authenticated encryption — HPKE-style ephemeral sender.
    // Construction: ephemeral X25519 DH → HKDF-SHA256 → AES-256-GCM.
    //
    // A fresh ephemeral key pair is generated per message.  The ephemeral
    // private key drives the X25519 DH with the recipient's static public key.
    // The ephemeral public key is written to encOut and must be transmitted
    // alongside the ciphertext so the recipient can reproduce the same shared
    // secret (matches Bláithín's API: separate "enc" and "ciphertext" fields).
    //
    // senderSecretKey is kept for interface symmetry; DH uses the ephemeral key.
    //
    // Return value layout: nonce (12 bytes) || ciphertext+tag (plaintext.size() + 16 bytes)
    static std::vector<unsigned char> encryptMessage(
        const std::string& plaintext,
        const std::vector<unsigned char>& recipientPublicKey,
        const std::vector<unsigned char>& senderSecretKey,
        std::vector<unsigned char>& encOut);

    // Decrypts a payload produced by encryptMessage.
    // enc is the ephemeral public key from the "enc" field of the API response.
    // Throws std::runtime_error on wrong keys or any tampering (AES-GCM tag mismatch).
    static std::string decryptMessage(
        const std::vector<unsigned char>& payload,
        const std::vector<unsigned char>& enc,
        const std::vector<unsigned char>& recipientSecretKey);
};
