#include <iostream>
#include <string>
#include "CryptoUtils.h"

// TODO (task 2.10): replace this test harness with Client init + menu loop.
// TODO (task 2.2):  replace hardcoded key pairs with real server pubkey fetched via HttpClient.
int main() {
    std::cout << "SecureChat C++ Client v0.1 — task 2.3 crypto smoke test" << std::endl;

    // Generate two key pairs to stand in for Alice (sender) and Bob (recipient).
    // These are regenerated fresh every run — in production, Alice's keys come from
    // local storage and Bob's public key comes from the server (task 2.2).
    std::vector<unsigned char> alicePub, aliceSec;
    std::vector<unsigned char> bobPub,   bobSec;
    CryptoUtils::generateKeyPair(alicePub, aliceSec);
    CryptoUtils::generateKeyPair(bobPub,   bobSec);

    std::cout << "Alice pubkey (base64): " << CryptoUtils::toBase64(alicePub) << std::endl;
    std::cout << "Bob   pubkey (base64): " << CryptoUtils::toBase64(bobPub)   << std::endl;

    const std::string message = "Hello Bob, this is an authenticated encrypted message!";
    std::cout << "\nPlaintext:  " << message << std::endl;

    // Alice encrypts for Bob, authenticating with her own secret key.
    auto payload = CryptoUtils::encryptMessage(message, bobPub, aliceSec);
    std::cout << "Ciphertext (base64): " << CryptoUtils::toBase64(payload) << std::endl;

    // Bob decrypts, verifying it genuinely came from Alice.
    std::string decrypted = CryptoUtils::decryptMessage(payload, alicePub, bobSec);
    std::cout << "Decrypted:  " << decrypted << std::endl;

    if (decrypted == message) {
        std::cout << "\nEncrypt/decrypt round-trip OK." << std::endl;
    } else {
        std::cerr << "\nERROR: round-trip mismatch!" << std::endl;
        return 1;
    }

    return 0;
}
