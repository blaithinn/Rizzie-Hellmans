#include <iostream>
#include <string>
#include "CryptoUtils.h"

// TODO (task 2.10): replace this test harness with Client init + menu loop.
// TODO (task 2.2):  replace hardcoded key pairs with real server pubkey fetched via HttpClient.
int main() {
    std::cout << "SecureChat C++ Client v0.1 — task 2.3 crypto smoke test" << std::endl;

    // Generate two key pairs to stand in for Alice (sender) and Bob (recipient).
    // In production, Alice's keys come from local storage and Bob's public key
    // comes from GET /users/:id/pubkey (task 2.2).
    std::vector<unsigned char> alicePub, aliceSec;
    std::vector<unsigned char> bobPub,   bobSec;
    CryptoUtils::generateKeyPair(alicePub, aliceSec);
    CryptoUtils::generateKeyPair(bobPub,   bobSec);

    std::cout << "Alice pubkey (base64): " << CryptoUtils::toBase64(alicePub) << std::endl;
    std::cout << "Bob   pubkey (base64): " << CryptoUtils::toBase64(bobPub)   << std::endl;

    const std::string message = "Hello Bob, this is an authenticated encrypted message!";
    std::cout << "\nPlaintext:  " << message << std::endl;

    // Alice encrypts for Bob.
    // encOut = ephemeral public key → goes in the "enc" field of POST /messages.
    // payload = nonce || ciphertext+tag → goes in the "ciphertext" field.
    std::vector<unsigned char> encOut;
    auto payload = CryptoUtils::encryptMessage(message, bobPub, aliceSec, encOut);
    std::cout << "enc        (base64): " << CryptoUtils::toBase64(encOut)  << std::endl;
    std::cout << "ciphertext (base64): " << CryptoUtils::toBase64(payload) << std::endl;

    // Bob decrypts using the ephemeral public key (enc) and his own secret key.
    std::string decrypted = CryptoUtils::decryptMessage(payload, encOut, bobSec);
    std::cout << "Decrypted:  " << decrypted << std::endl;

    if (decrypted == message) {
        std::cout << "\nEncrypt/decrypt round-trip OK." << std::endl;
    } else {
        std::cerr << "\nERROR: round-trip mismatch!" << std::endl;
        return 1;
    }

    return 0;
}
